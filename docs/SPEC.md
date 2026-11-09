# Flectar Mail Sync protocol, version 1

Status: **draft**. Sections marked *(planned)* are not implemented yet and may
change. Everything else is implemented by the crates in this repository and
covered by their tests.

## 1. Overview

Flectar Mail Sync keeps one person's app state the same on all their
devices. That state covers accounts, preferences, signatures, rules and similar
records. Mail, contacts and calendars are not part of it: they sync with
the mail provider as before.

- **Group:** one person's devices and their records.
- **Device:** holds its own signing key and KEM key in its operating system's
  key store, plus the group's root keys.
- **Record:** an encrypted blob with a random 16-byte id. The server stores
  the newest version of each record. A deleted record leaves a **tombstone**
  without payload.
- **Sequence number (`seq`):** every record change gets the next one in its
  group. The server assigns it, so no device clock ever orders changes.
- **Membership chain:** a hash-chained list of signed operations that says
  which devices belong to the group, which recovery key may act, and which
  root key is current. The server and every device check it with the same
  rules (§5.4).
- **Epoch:** numbers the group's current root key. It starts at 1 and
  increases with each `rotate` operation.

The server is blind. It never holds a key that could read a record, and it
does not know which kind of state a record carries. Every device keeps the
complete state, so a server can be rebuilt from any device.

## 2. Encoding

- Bodies are UTF-8 JSON with camelCase keys.
- Binary values are unpadded base64url strings (RFC 4648 §5).
- Integers are JSON numbers below 2^53.
- Times are milliseconds since the Unix epoch.
- Unknown JSON fields must be ignored by both sides.

| Value | Bytes |
|---|---|
| group id, device id, record id, challenge id, pairing slot id | 16, random |
| collection tag | 16 |
| record nonce | 24 |
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| X-Wing public key | 1216 |
| login nonce | 32 |

`RECOVERY_ID` is 16 zero bytes. It stands for the recovery key wherever a
device id is expected: in logins, key wraps and operation authorizers.

## 3. Versioning

`GET /v1/info` returns `protocolMin` and `protocolMax`. A client must not talk
to a server whose range excludes its protocol version. The path prefix `/v1`
changes only with an incompatible protocol version.

## 4. Cryptography

### 4.1 Primitives

| Use | Primitive |
|---|---|
| Signatures | Ed25519 (RFC 8032), strict verification |
| Key derivation | HKDF-SHA256 (RFC 5869) with no salt, 32-byte output |
| Record and key sealing | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) |
| Collection tags | HMAC-SHA256, first 16 bytes |
| Hashes and commitments | SHA-256 |
| Wrapping root keys to devices | HPKE (RFC 9180), base mode, suite 1 (§4.8) |

Every secret fed to HKDF is uniformly random, so no password stretching is
used (RFC 5869 §4).

### 4.2 Labels

Each derivation and signature is bound to one purpose by an ASCII label:

| Name | Bytes |
|---|---|
| `RECOVERY_SIGN` | `flectar-mail-sync/v1 recovery-sign` |
| `RECOVERY_KEM` | `flectar-mail-sync/v1 recovery-kem` |
| `RECORD_KEY` | `flectar-mail-sync/v1 record-key` |
| `TAG_KEY` | `flectar-mail-sync/v1 tag-key` |
| `RECORD_AAD` | `flectar-mail-sync/v1 record` |
| `RECORD_ID` | `flectar-mail-sync/v1 record-id` |
| `ROOT_COMMIT` | `flectar-mail-sync/v1 root-commit` |
| `PREVIOUS_ROOT` | `flectar-mail-sync/v1 previous-root` |
| `WRAP` | `flectar-mail-sync/v1 wrap` |
| `AUTH` | `flectar-mail-sync/v1 auth` |
| `OP_SIGNATURE` | `flectar-mail-sync/v1 op` |
| `OP_HASH` | `flectar-mail-sync/v1 op-hash` |
| `DEVICE_BINDING` | `flectar-mail-sync/v1 device-binding` |
| `RECOVERY_BINDING` | `flectar-mail-sync/v1 recovery-binding` |
| `PAIRING` | `flectar-mail-sync/v1 pairing` |
| `FINGERPRINT` | `flectar-mail-sync/v1 fingerprint` |

`||` is concatenation. `u16be` and `u64be` are big-endian unsigned integers.

### 4.3 Recovery code

- **The code:** 32 random bytes, shown as 24 words of the BIP39 English list.
  The words only encode the 32 bytes and their checksum. BIP39's PBKDF2
  seed derivation is not used.
- **Recovery signing key:** the Ed25519 key whose seed is
  `HKDF(code, RECOVERY_SIGN)`.
- **Recovery KEM key:** HPKE `DeriveKeyPair(HKDF(code, RECOVERY_KEM))` of
  suite 1. Devices hold only its public half, so they can wrap new root keys
  for recovery without knowing the code.
- **Finding the group:** the server finds a group by its current recovery
  signing key (§6.4), so the 24 words and the server's address are enough to
  recover, even after `reset_recovery` replaced the code. A recovery key
  belongs to one group at most.

### 4.4 Root keys and epochs

- The root key `K_e` of epoch `e` is 32 random bytes.
- record key = `HKDF(K_e, RECORD_KEY || u64be(e))`
- tag key = `HKDF(K_e, TAG_KEY || u64be(e))`
- **Commitment:**
  `SHA-256(ROOT_COMMIT || group_id || u64be(e) || K_e)`.
  - The genesis operation (epoch 1) and every `rotate` operation carry it.
  - A device must compare every root key it unwraps with the commitment in
    the verified chain. A wrap does not prove who made it (§4.8); the
    commitment does.
- **Sealed previous root:** a `rotate` to epoch `e` carries
  `nonce (24) || XChaCha20-Poly1305(HKDF(K_e, PREVIOUS_ROOT || u64be(e)), nonce, K_{e-1}, aad)`,
  where `aad = PREVIOUS_ROOT || group_id || u64be(e)`. That is 72 bytes. With
  the current root key a device can walk back to every earlier one, so records
  of older epochs stay readable without being re-encrypted.

### 4.5 Records

- **Plaintext:** UTF-8 JSON that the server never sees:

  ```json
  {"v": 1, "collection": "pref", "schema": 1,
   "stamp": {"ms": 1762400000000, "counter": 0, "device": "<device id>"},
   "body": {}}
  ```

  - `collection` must match the record's tag (§4.6); readers check it.
  - `schema` versions the collection's `body`, which the application
    defines. Applications keep unknown fields when they rewrite a body.
  - `stamp` is a hybrid logical clock: wall-clock milliseconds that never run
    backwards on a device and always move past every stamp it has seen, a
    counter, and the writing device. Stamps compare in that order.
  - Readers ignore unknown top-level fields, so new ones must be safe to
    drop.
- **Padding:** append `0x80`, then zeros up to the next multiple of 256 bytes.
  At least one byte is always added.
- **Sealing:** `ciphertext = XChaCha20-Poly1305(record key, nonce, padded, aad)`
  with a random 24-byte nonce, where
  `aad = RECORD_AAD || group_id || record_id || tag || u64be(epoch)`.

The associated data binds a ciphertext to its group, record, collection and
epoch, so a server cannot move it elsewhere.

### 4.6 Collection tags

`tag = HMAC-SHA256(tag key, UTF-8 collection name)[0..16]`. The server sees
only the tag.

Items known by name, such as preference keys, get record ids the same way,
so every device finds the same record without the server learning the name:
`record_id = HMAC-SHA256(HKDF(K_1, RECORD_ID), UTF-8 name)[0..16]`, where
`RECORD_ID` is `flectar-mail-sync/v1 record-id`. Only epoch 1's root key is
used, so ids survive rotations; every member can derive `K_1` (§4.4). Other
records use random ids.

### 4.7 Login message

```
AUTH || u16be(len(audience)) || audience || group_id || device_id || nonce
```

`audience` is the server's public URL without a trailing slash, exactly as the
device is configured. A signature for one server cannot log in to another.
For a recovery login, `group_id` and `device_id` are both `RECOVERY_ID`,
because recovery learns its group only once logged in, and the recovery
signing key signs.

### 4.8 Key wraps

- **Suite 1:** HPKE base mode with:
  - KEM: X-Wing, the hybrid of X25519 and ML-KEM-768. KEM id `0x647a`, as
    draft-ietf-hpke-pq-03 assigns it.
  - KDF: HKDF-SHA256.
  - AEAD: ChaCha20-Poly1305.

  Wraps are stored on the server, so the hybrid post-quantum KEM keeps them
  safe from "harvest now, decrypt later".
- **Format:** `u16be(1) || enc (1120) || ciphertext (48)`, where `ciphertext`
  seals `K_e`.
  - `info`: `WRAP || group_id || u64be(e) || target`.
  - `aad`: empty.
  - `target`: the device id, or `RECOVERY_ID`.
- **No sender authentication:** X-Wing has no authenticated mode. A device
  must check what it unwraps against the chain's commitment (§4.4).

### 4.9 Pairing

The device that shows a code opens a pairing slot (§6.12). Either device may
do so. The two devices then exchange three messages through it:

| Index | Message | From | Content |
|---|---|---|---|
| 0 | invite | existing device | `0x01 \|\| group_id (16) \|\| u64be(head_index) \|\| head_hash (32) \|\| var server_url` |
| 1 | join request | new device | `0x01 \|\| device keys \|\| binding_signature (64)` |
| 2 | join result | existing device | `0x01 \|\| 0x01 \|\| u64be(index of the add_device operation)`, or `0x01 \|\| 0x02` if declined |

- **Invite:** the group's server URL may differ from the server holding the
  slot. The head is the latest chain head the existing device has verified.
- **Join request:** device keys are encoded as in §5.1, and the binding
  signature is the one `add_device` carries (§5.2), made for the invited
  group.
- **Checks by the new device:** after it is added, it logs in and accepts the
  chain only if the operation at `head_index` hashes to `head_hash`. Then it
  unwraps its root key and checks the commitment (§4.4).

**With a QR code:** the code carries the slot's server, the slot id and a
pairing secret of 32 random bytes:

```
flectar-mail-sync:pair?v=1&server=<percent-encoded URL>&slot=<slot id>&secret=<secret>
```

Every message is sealed under the secret:
`nonce (24) || XChaCha20-Poly1305(HKDF(secret, PAIRING), nonce, message, aad)`,
where `aad = PAIRING || slot_id || index` and `index` is one byte. Binding
the index keeps a server from passing one side's message off as the other's.

**With a short code**, for devices without a camera: the slot is opened with
an eight-digit code (§6.12), which the user types on the new device. The
messages travel in the clear, and the user compares **approval words** on
both screens before the existing device adds the new one:

1. Compute `SHA-256(FINGERPRINT || group_id || head_hash || device_id || sign_public_key || u64be(len(kem_public_key)) || kem_public_key)`.
2. Take its first 66 bits.
3. Read them as six 11-bit indices into the BIP39 English list.

The existing device computes them from its own group and head and the keys it
received; the new device from the invite it received and its own keys. They
differ if a server swapped the keys, the group or the head.

### 4.10 Files

Something too large for a record, such as a scheduled message with its
attachments, is stored as a file (§6.15). Each file is sealed under a key of
its own, 32 random bytes that only a record carries:

```
0x01 || nonce (24) || XChaCha20-Poly1305(file_key, nonce, content, aad = FILE)
```

The server learns a file's size and when it is fetched, never its key or
content. A device that refers to a file in a record names its id, sealed
size and key.

## 5. Membership chain

### 5.1 Encoding

Operations are signed and hashed over this canonical binary encoding, never
over JSON:

```
"FMSO" || 0x01 || kind (1 byte) || group_id (16) || u64be(index)
       || prev_hash (32) || u64be(created_at_ms) || body
```

- A variable field (`var`) is `u16be(length) || bytes`.
- **Device keys:** `device_id (16) || sign_public_key (32) || var kem_public_key`.
  The KEM key is at most 4096 bytes.
- **Authorizer:** 17 bytes. It is either `0x01 || device_id`, where the
  device id is not `RECOVERY_ID`, or `0x02 || RECOVERY_ID`.
- Decoders reject unknown kinds, bad authorizers, over-long fields and
  trailing bytes.

### 5.2 Signatures, hashes and bindings

- **Signature:** `Ed25519(key, OP_SIGNATURE || op_bytes)`.
- **Hash:** `SHA-256(OP_HASH || op_bytes)`.
- **Chain:** each operation's `prev_hash` is the previous operation's hash and
  its `index` is one higher. The genesis has index 0 and an all-zero
  `prev_hash`.
- **Device binding:** a device being added signs
  `DEVICE_BINDING || group_id || device keys`, proving it holds its private
  key.
- **Recovery binding:** a new recovery key signs
  `RECOVERY_BINDING || group_id || recovery_sign_public_key || var recovery_kem_public_key`,
  so nobody can reset recovery to a key they do not hold, such as another
  group's.

Operations are plaintext to the server, so they carry only ids, public keys
and commitments. Device names belong in encrypted records.

### 5.3 Kinds

| Kind | Name | Body after the header | Signatures |
|---|---|---|---|
| 1 | genesis | `recovery_sign_public_key (32)`, `var recovery_kem_public_key`, device keys, `root_commitment (32)` | the recovery key's, then the device's |
| 2 | add_device | authorizer, device keys, `binding_signature (64)` | the authorizer's |
| 3 | remove_device | authorizer, `device_id (16)` | the authorizer's |
| 4 | rotate | authorizer, `u64be(epoch)`, `root_commitment (32)`, `var sealed_previous_root`, at most 256 bytes | the authorizer's |
| 5 | reset_recovery | authorizer, `recovery_sign_public_key (32)`, `var recovery_kem_public_key`, `binding_signature (64)` | the authorizer's |
| 6 | move_server | authorizer, `var url` (UTF-8, at most 2048 bytes) | the authorizer's |
| 7 | delete_group | authorizer | the authorizer's |

### 5.4 Rules

A chain is valid when its first operation is a valid genesis and each later
operation passes these checks against the state before it:

1. **Order and authority:**
   - The group is not deleted, the group id matches, and the index and
     `prev_hash` extend the head.
   - The operation is not a genesis and carries exactly one signature.
   - That signature verifies with the authorizer's current key: an active
     device's signing key, or the current recovery signing key.
2. **add_device:**
   - The id is not `RECOVERY_ID`, not active, and was never removed.
   - The binding signature verifies with the new device's key.
3. **remove_device:** the device is active. A device may remove itself.
4. **rotate:** `epoch` is the current epoch plus one, and the sealed previous
   root is not empty.
5. **reset_recovery:** the binding signature verifies with the new recovery
   signing key.
6. **move_server:** the URL starts with `https://` or `http://`.
7. **delete_group:** no operation may follow it.

`GroupState` in `flectar-mail-sync-crypto` implements these rules. The server
and the app both use it.

## 6. HTTP API

### 6.1 General

- Servers are reached over HTTPS.
- Authenticated endpoints take `Authorization: Bearer <token>` (§6.4).
- Every error is answered with this body, plus `conflicts` on commit
  conflicts:

```json
{"error": {"code": "conflict", "message": "…"}, "conflicts": [{"recordId": "…", "currentSeq": 5}]}
```

| Status | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed request, or an operation that breaks §5.4 |
| 401 | `unauthorized` | Missing or invalid session |
| 401 | `challenge_expired` | A login's challenge expired, was used, or is gone: ask for a new one (§6.4) |
| 401 | `device_unknown` | The server could not confirm a login. Not a removal (§6.4) |
| 402 | `payment_required` | The group's free trial or paid period ended, so uploads wait for a payment (§6.14) |
| 403 | `forbidden` | The session belongs to another group, or a recovery session asked for something only devices may do |
| 403 | `device_removed` | A login signed by the key of a device the chain removed (§6.4) |
| 404 | `not_found` | Unknown group, or no wrap for this session |
| 404 | `code_unknown` | No such code (§6.14) |
| 408 | `request_timeout` | The request, or its body, took longer than the server waits; try again |
| 409 | `conflict` | Stale `expectedSeq`, the group id is taken, the recovery key belongs to another group, or the chain moved on |
| 409 | `stale_epoch` | A record was sealed for another epoch than the current one: read the chain, fetch the root key and seal again |
| 409 | `already_subscribed` | A checkout was refused: the group already has a subscription; open the management page instead (§6.14) |
| 409 | `code_used` | The code was redeemed already (§6.14) |
| 409 | `code_expired` | The code was not redeemed in time (§6.14) |
| 410 | `gone` | `since` is below the tombstone horizon; read again from 0 |
| 410 | `group_deleted` | The group was deleted |
| 411 | `bad_request` | A commit came without `Content-Length` (§6.5) |
| 413 | `payload_too_large` | Over a size or batch limit |
| 429 | `rate_limited` | Too many requests |
| 507 | `quota_exceeded` | The group would exceed its storage quota or device limit |
| 507 | `chain_full` | The group's chain holds as many operations as the server keeps (§6.10) |
| 507 | `server_full` | The server is short of disk space for now: new groups, commits that store records, and new files wait. Reading, deleting and changing members go on. Try again later |
| 500 | `internal` | Server failure |

Clients handle codes they do not know by the HTTP status.

A request's answer must begin within 30 s, its body included; past that the
server answers `408`. Commits get 2 minutes, and uploads to a server's own
file addresses 10. A commit's body must also keep up at least 16 KiB/s after
its first 15 s, or it answers `408 request_timeout`, and a page of records or
operations must go out as fast, or the server cuts it off. Once a client
stops reading what the server sends, it must take 64 KiB within 30 s, or the
server closes the connection. A change the server stored takes effect, and
is announced to the group's devices, even when its request ends before the
answer.

### 6.2 `GET /v1/info`

```json
{"server": "flectar-mail-sync", "version": "0.1.0", "protocolMin": 1, "protocolMax": 1,
 "limits": {"maxRecordBytes": 262144, "maxBatchRecords": 1000, "maxRequestBytes": 8388608,
            "maxGroupBytes": 67108864, "maxPageRecords": 1000, "maxDevices": 25},
 "billing": {"trialDays": 14, "plans": [
   {"id": "monthly", "amount": 500, "currency": "eur", "interval": "month", "taxIncluded": true},
   {"id": "yearly", "amount": 4800, "currency": "eur", "interval": "year", "taxIncluded": true}]}}
```

`billing` appears only on a server that charges (§6.14), so devices can
show the price before a group is created. There, `limits.maxGroupBytes` and
`files.maxGroupFileBytes` are the quotas of a group that pays; a group that
doesn't gets smaller ones (§6.14).

### 6.3 `POST /v1/groups`

Request: `{"op": <genesis>, "signatures": [<recovery>, <device>], "wraps": [{"target", "ciphertext"}, …]}`.

- **Wraps:** epoch 1 wraps. The recovery wrap is required; the device's own
  wrap is optional.
- **No trial:** `"noTrial": true` asks a server that charges to start the
  group without a free trial (§6.14).
- **Success:** `201 {"groupId", "highSeq": 0}`.
- **Taken id or recovery key:** `409`. The id of a deleted group is never used
  again; its recovery key is free again.

### 6.4 Login

1. `POST /v1/auth/challenge` returns `{"challengeId", "nonce", "expiresAt"}`.
   - A device sends `{"groupId", "deviceId"}`. `deviceId` must not be
     `RECOVERY_ID`.
   - Recovery sends only `{"recoveryPublicKey"}`, its current signing key.
     The server finds the group whose current recovery key it is.
   - A challenge lasts 120 s and is single-use. It is issued even for
     unknown groups, devices or keys, so the endpoint does not reveal which
     exist.
2. `POST /v1/auth/session` with `{"challengeId", "signature"}` takes the
   signature over the login message (§4.7). It returns
   `{"token", "expiresAt", "groupId"}`, and the session lasts one hour. A
   device, or recovery, keeps at most 16 sessions; a newer one ends the
   oldest.
3. A refused login says why only as far as its signature allows:
   - `401 challenge_expired`: the challenge expired, was used, or the
     server no longer holds it, as after a restart. Ask for a new one.
   - `401 device_unknown`: the server could not confirm the login. It
     doesn't know the group, or the device in it, or the signature doesn't
     check against the device's key, as when the server's address is not
     the one devices sign for. This is not a removal: a server restored
     from a backup may have lost the group, or the operation that added
     the device, until a device appends it again (§8).
   - `403 device_removed`: the signature checks against the key of a device
     the chain removed.
   - `410 group_deleted`: the group was deleted.
   Apart from `challenge_expired`, a recovery login fails with
   `401 device_unknown` whatever the reason, so the endpoint doesn't reveal
   which recovery keys are in use.

**Recovery sessions:** recovery learns its group from the session response.
It must then check that the chain's current recovery key is its own. A
recovery session may only:
- read the chain (§6.9);
- read the recovery wrap (§6.11);
- append an `add_device` operation (§6.10).

**When sessions end:**
- A removed device's sessions end at once, and so do recovery sessions when
  recovery is reset.
- After a group is deleted, its sessions last until they expire, and every
  request answers `410 group_deleted`. Devices still connected learn of the
  deletion that way, and the others when they log in.

### 6.5 `POST /v1/groups/{group}/commit`

This endpoint is for device sessions only.

`{"items": [item, …]}`, applied atomically: either every item is stored or
none. The request must carry `Content-Length`, or it answers `411`; one
longer than `maxRequestBytes` answers `413` before its body is read.

- **Put:** `{"recordId", "expectedSeq", "tag", "epoch", "nonce", "ciphertext"}`.
- **Delete:** `{"recordId", "expectedSeq", "deleted": true}`.

Rules:
- A `ciphertext` has at least 272 bytes, the length of an empty record
  once padded and sealed (§4.5); shorter ones answer `400`.
- `expectedSeq` must equal the record's current `seq`, or 0 if the record
  does not exist (a tombstone counts as existing). Otherwise the answer is
  `409` with every stale record and its `currentSeq`, and nothing is stored.
- A record id appears at most once per commit.
- A deletion needs `expectedSeq > 0`.
- `epoch` must equal the group's current epoch, else the answer is
  `409 stale_epoch`. This happens when another device rotated the key.
- Size, batch and quota limits come from `/v1/info`. A commit that does not
  grow the group is accepted even over quota.
- **Quota:** each record and each tombstone counts 256 bytes on top of its
  tag, nonce and ciphertext, so tombstones fill the quota too until they
  are dropped (§6.6). Chain operations count as well (§6.10).

Success returns `{"highSeq", "results": [{"recordId", "seq"}, …]}`. The
results are in item order, with consecutive sequence numbers.

### 6.6 `GET /v1/groups/{group}/changes?since=N&limit=M`

This endpoint is for device sessions only.

Returns records and tombstones with `seq > N`, oldest first, read from one
snapshot: `{"records": [...], "highSeq", "more"}`. A tombstone carries only
`recordId`, `seq` and `"deleted": true`.

- **Paging:** if `more` is true, ask again with `since` set to the last
  `seq`. `limit` defaults to, and is capped at, `maxPageRecords`. A page
  also ends before the record that would take it past about 2 MiB of
  records, so it may hold fewer, but always at least one.
- **Tombstone horizon:** tombstones are dropped after the server's retention
  period (180 days by default). The group's horizon is the highest dropped
  `seq`.
  - `0 < since < horizon` answers `410 gone`.
  - `since = 0` is always allowed and reads the whole group. A client must
    then delete local records that are not in it.

### 6.7 `GET /v1/groups/{group}/events`

This endpoint is for device sessions only.

A Server-Sent Events stream. A `seq` event carries the group's newest
sequence number: it is sent at once, and again each time it advances. A
`chain` event is sent each time an operation is appended to the chain. A
`billing` event says what the group pays changed (§6.14), for example after
a payment.

```
event: seq
data: {"highSeq":12}

event: chain
data: {"headIndex":3}

event: billing
data: {}
```

Clients ignore event types they do not know.

- The server sends keep-alive comments every 15 s. Clients reconnect with
  backoff.
- A group keeps at most twice as many streams open as it had devices when
  the session logged in, and the server 32768 in all by default, at most
  half the files it may open; past that, opening one answers `429`.
- The stream ends when the server shuts down, when a device of the group is
  removed, or when the group is deleted.

### 6.8 `GET /healthz`

`200 ok` when the database answers.

### 6.9 `GET /v1/groups/{group}/ops?since=N`

Returns `{"ops": [{"index", "op", "signatures"}, …], "more"}`: operations
with `index >= N`, oldest first.

A device verifies them with §5.4. It anchors the chain to a head hash it
already trusts: one it verified before, or the one a pairing gave it.

### 6.10 `POST /v1/groups/{group}/ops`

Request: `{"op", "signatures", "wraps"}`.

1. An operation for an index that already exists answers `409`; the client
   reads the chain again and rebuilds the operation. One that skips an
   index, or names another group, answers `400`. Both are refused before
   the chain is replayed or anything is written.
2. The server replays the stored chain, checks the operation with §5.4, and
   applies it.
3. Success returns `{"headIndex", "epoch"}`.

**Limit.** A chain holds at most 1000 operations, years of adding and
replacing devices. Past that, the server answers `507 chain_full` to every
operation but `remove_device`, a `rotate` while one is due (§5.4), and
`delete_group`. A full chain gains no devices, so those run out; they keep
a group able to drop a device and to delete itself. To add devices again,
start a new group.

The wraps must be exactly what the kind allows. They are stored for the epoch
current after the operation.

| Kind | Required wraps | Allowed wraps |
|---|---|---|
| add_device | none | the new device |
| rotate | every remaining device and `RECOVERY_ID` | the same |
| reset_recovery | none | `RECOVERY_ID` (for the new recovery key) |
| remove_device, move_server, delete_group | none | none |

Each operation counts its own bytes, its signatures and 256 bytes against
the group's quota. One that would exceed it answers `507 quota_exceeded`,
unless it is one a full chain still takes (see **Limit** above) or a
`reset_recovery`, so a code that leaked can always be replaced.

Effects:
- **add_device:** answers `507` when it would exceed `maxDevices`. Only an
  addition is held to the limit: a group over a limit the server lowered
  since still removes devices and rotates.
- **remove_device:** drops the device's wraps, ends its sessions, and ends the
  group's event streams. When it removes the last device, on a server that
  charges, the group's subscription stops renewing and ends with the period
  that is paid, since no device is left to stop it, and its open checkout
  ends; the server records this with the operation and tries again until
  the provider has done it. The recovery code can still bring a device
  back.
- **rotate:** drops wraps of older epochs.
- **reset_recovery:** drops the old recovery wrap and ends recovery sessions.
  A new key that belongs to another group answers `409`.
- **delete_group:** erases the group's records, wraps, devices, chain and
  recovery key. A marker keeps the id from being used again. A group no
  device has signed in to for the unused group lifetime (§9) is erased the
  same way, unless its subscription is still paid for or a code still makes
  it free (§6.14).

### 6.11 `GET /v1/groups/{group}/wrap`

Returns `{"epoch", "ciphertext"}`: the current epoch's wrap for the session's
device, or for recovery in a recovery session. If there is none, it answers
`404`.

### 6.12 Pairing slots

Short-lived mailboxes for the messages of §4.9. They need no session: the new
device has none yet. Whoever knows a slot id may use the slot, so slot ids
are random and only travel in QR codes, and the messages are sealed or
checked with approval words.

- `POST /v1/pairing` with `{"code": false}` opens a slot. It answers
  `201 {"slotId", "expiresAt"}`, plus `"code"` when `true` was asked: eight
  digits that find the slot once.
- `GET /v1/pairing/codes/{code}` answers `{"slotId"}`, or `404`. A code works
  only once, so someone guessing codes can find a slot only before its owner
  does.
- `PUT /v1/pairing/{slot}/messages/{index}` with `{"message"}` stores a
  message at `index`, which must be the next free one.
  - `201` stores it; `200` means the same message was already there, so
    writers can retry.
  - `409` if another message is at `index`, or `index` skips ahead.
  - `413` past the size or message limit.
- `GET /v1/pairing/{slot}/messages?from=N&wait=S` returns
  `{"messages": [{"index", "message"}, …], "expiresAt"}` with the messages
  from index `N` on. If there are none, it waits up to `S` seconds (at most
  25) for one to arrive, then answers with an empty list.
- `DELETE /v1/pairing/{slot}` ends the slot. Either device does so when done.

An unknown or expired slot answers `404`. Slots live in memory; a server
restart ends them.

### 6.13 Rate limits

Over a limit, the server answers `429 rate_limited` with a `Retry-After`
header in seconds. Limits are bursts refilled at a steady rate (GCRA):

| Endpoints | Counted per | Default burst | Default refill |
|---|---|---|---|
| `GET /v1/info` | client address | 120 | 1 per 250 ms |
| `POST /v1/groups` | client address | 5 | 1 per 4 h |
| `POST /v1/auth/challenge`, `POST /v1/auth/session` | client address | 40 | 1 per 5 s |
| pairing slots and messages | client address | 60 | 1 per 2 s |
| `GET /v1/pairing/codes/{code}` | client address | 5 | 1 per 30 s |
| `GET /v1/pairing/codes/{code}` that finds nothing | network: an IPv4 /24, an IPv6 /48 | 10 | 1 per 30 s; while over it, every lookup from the network answers `429` |
| `GET /v1/pairing/codes/{code}` that finds nothing | server | 120 | 1 per 500 ms; while over it, every lookup answers `429` |
| endpoints with a session | group | 300 | 1 per 100 ms |
| `POST …/ops` | group | 30 | 1 per min |
| `POST …/billing/checkout`, `POST …/billing/manage` | group | 5 | 1 per min |
| `POST …/billing/redeem` | group | 5 | 1 per 10 min |
| `POST …/files` | group | 20 | 1 per min |

- **Client address:** IPv6 addresses count per /64 network.
- **Behind a proxy:** when the connecting peer is a configured trusted
  proxy, the client address is the rightmost `X-Forwarded-For` entry that is
  not a trusted proxy. Entries to its left come from the client and are
  ignored.
- **Caps per address:** an address keeps at most 64 pending login
  challenges and 8 open pairing slots, and the server 100000 and 4096.
  Past an address's cap its oldest makes room, and past the server's, the
  oldest of the address holding the most: a new login or pairing is never
  refused for it, and a few busy addresses can't push out everyone else's.
- **In flight:** a group may have 4 requests with a session in flight at
  once for each device it had when the session logged in, at least 8 and
  at most 64, and the server 1024 in all; past either, `429`. An event
  stream counts only while it opens, and a commit counts in the server's
  1024 only once its body is in. A page of records or operations counts
  until the last of it is sent.
- **Heavy requests:** commits, pages of records or operations, and chain
  appends, which replay the chain, also wait up to 10 s for one of the
  server's 32 slots for them, then answer `429`. A group takes at most one
  slot per device, at least 2 and at most 8, and a page holds its slot
  until the last of it is sent. Commits also wait for room for their
  bodies: the server reads at most 128 MiB of them at once, and a group an
  eighth of that, or one commit of `maxRequestBytes` if more.

### 6.14 Billing

A server may charge for syncing. Groups have no accounts, so devices pay for
their group: each payment is tied to the group's id. On a server that
doesn't charge, every group syncs for free.

`GET /v1/groups/{group}/billing` answers:

```json
{"enabled": true, "status": "active", "trialEndsAt": 1767225600000,
 "paidUntil": 1798761600000, "renews": true, "plans": [ … ]}
```

- `enabled`: the server charges. When `false`, `status` is `free` and the
  other fields are empty.
- `status`:
  - `free`: nothing to pay.
  - `trial`: in the free trial, which ends at `trialEndsAt`.
  - `active`: paid until `paidUntil`.
  - `past_due`: a renewal failed. It stays so until the payment goes
    through or the subscription ends; uploads stop after a while (below).
  - `granted`: free until `freeUntil`, through redeemed codes. A
    subscription shows before it, and it shows before the trial.
  - `expired`: the trial, paid period or free period ended.
  - A client that meets a status it does not know shows no billing state.
    The `402` answers below still tell it when uploads stop.
- `trialEndsAt`, `paidUntil`, `freeUntil`: milliseconds since the Unix
  epoch. `paidUntil` is the end of the last paid period, and `freeUntil` the
  end of the free period that redeemed codes gave the group.
- `renews`: the subscription renews at `paidUntil`.
- `plans`: as in `/v1/info`. `amount` is in the currency's smallest unit;
  `taxIncluded` says whether it includes tax. The provider may charge in the
  buyer's own currency.

The trial starts the first time the server sees the group: at its first
upload or billing request. A group created with `noTrial` has none. Devices
remember that they had a trial on a server, and ask for none when they
start a group there again, so starting over doesn't bring another trial.
Servers that don't charge ignore `noTrial`.

**Uploads.** While the group's status is `expired`, a commit that stores
records answers `402 payment_required`. Everything else keeps working:
reading, deleting records, adding and removing devices, and deleting the
group. A paid period stays usable for 3 days after `paidUntil` while the
renewal arrives. A `past_due` group may upload for 14 days from the first
failed payment, however often its period renews unpaid; after that it stays
`past_due` and its uploads answer `402` until the payment goes through, so
devices offer the management page, where it can be fixed.

**Storage.** A group that doesn't pay, in its trial or after it, may store
8 MiB of records and chain (§6.5) and 32 MiB of files (§6.15) by default.
Paying, or a free period from a code, gives it the quotas `/v1/info`
reports. Past either, uploads answer `507 quota_exceeded`.

**Pages.** Paying happens in the browser, on pages of the payment provider:

- `POST /v1/groups/{group}/billing/checkout` with `{"plan": "yearly"}`
  answers `{"url"}`, a checkout for the plan. What is left of the trial
  carries over when more than 49 hours remain (the provider needs 48).
  Opening a checkout ends the group's previous one, so a group is never
  charged twice. It answers `400` for an unknown plan, and
  `409 already_subscribed` when the group already has a subscription, even
  one still waiting for its first payment: devices then open the
  management page instead.
- `POST /v1/groups/{group}/billing/manage` answers `{"url"}`, the page that
  changes or cancels the subscription and lists its invoices. `409` when
  the group has no customer at the provider: it never subscribed, or the
  provider deleted the customer's data.
- On a server that doesn't charge, both answer `404`.

**Codes.** Whoever runs the server can hand out codes that make syncing
free for a while, such as a year for someone who contributed.

- `POST /v1/groups/{group}/billing/redeem` with `{"code"}` answers the
  group's billing state, as above, and sends a `billing` event to its
  devices.
- A code is 16 characters of Crockford's base 32, shown in groups of four
  such as `7KQ2-M9XD-T4RB-WH3E`. Case, spaces and dashes don't matter, and
  `O`, `I` and `L` read as `0`, `1` and `1`.
- Each code works once, for any group. Its days start when the group's
  trial, paid period or earlier free period ends, whichever is last, so none
  of them is cut short. If the group has a subscription that renews,
  redeeming a code stops it from renewing: it ends with the period that is
  paid, and the free period follows. A period whose payment failed
  (`past_due`) isn't paid: the subscription ends at once, so the payment
  stops being retried, and the free period starts now. The redemption
  counts even while the provider can't be reached; the server asks it again
  until it has done its part.
- Errors: `404 code_unknown`, `409 code_used`, and `409 code_expired` for a
  code not redeemed in time. On a server that doesn't charge, `404`.
- The server keeps only a hash of each code, and when it was redeemed. The
  reference server creates codes with `flectar-mail-sync-server codes
  create`, which prints them.

A `delete_group` operation (§5.3) also ends the group's open checkout and
cancels every subscription of the group to syncing that isn't over: the one
recorded first, then any other the provider's search finds. The server
records this in the same transaction as the operation, and tries again
until the provider has done all of it; only then does it forget the group's
billing state, so nothing links a deleted group to the provider's customer
any more. A checkout opened while the group is deleted answers `410` and
ends too. Billing requests for a deleted group answer `410`, like every
other request. A group erased for being unused is first checked with the
provider, in case a payment's event was lost, its search included: one it
lost track of that is still paid for keeps the group. Otherwise its
subscriptions end the same way before it goes.

**Provider (informative).** The reference server sells through Stripe
Managed Payments, with Stripe as merchant of record: Stripe collects the
payment and handles sales tax and VAT. Stripe sends its events to
`POST /v1/billing/stripe`, signed in the `Stripe-Signature` header; the
server refuses signatures that don't match or that are over 5 minutes old.
It acts on `checkout.session.completed` and `customer.subscription.*` events
with a snapshot payload, and reads each subscription back from Stripe
instead of trusting the event, so events may arrive in any order. A
subscription recorded as `canceled` or `incomplete_expired` stays so, as
Stripe never moves one out of those: a read that started earlier, or a
search that lags, can't bring it back. It accepts other events, and thin
ones, so Stripe stops sending them, and logs them as errors. Only
subscriptions whose metadata names the group, under the key
`flectar_mail_sync_group`, count for it, and only while they sell the plans'
product: one of the plans' prices, or another price of that product. The
server learns the product by reading the plans' prices; until it could, a
subscription with another price stays as recorded and its event is refused,
so Stripe sends it again. Only the server's own checkouts set that metadata,
so no other payment counts as one for syncing. Before it opens a checkout,
the server also searches the provider for the group's subscriptions, so one
it lost track of, or one still waiting for its first payment, isn't paid for
twice. Nor does anything of the other mode, live or test, than the server's
key: the server records the mode of each subscription and checkout, and
ignores events and objects of the other one. When what it stored of a group
looks out of date, such as a subscription past its period's end, one past
due for longer than uploads wait for, one still waiting for its first
payment, or a checkout with nothing to show for it, the server reads it back
from the provider before answering, at most every five minutes per group, or
every 30 s while its checkout is still open: the provider stops resending a
lost event after three days. A read-back that changed what the group pays
sends its devices a `billing` event. A checkout whose subscription is
recorded is forgotten, so a group whose subscription ended isn't read back
again. Reads of one subscription are recorded one at a time, so an older
read never lands after a newer one.

### 6.15 Files

A server may store files (§4.10); `/v1/info` then reports `files` with
`maxFileBytes`, `maxGroupFileBytes` and `ttlSeconds`. Without it, the server
stores none and answers these routes with 404.

- `POST /v1/groups/{group}/files` with `{"size": n}`, the sealed file's exact
  length, makes room for it and answers `{"id": "...", "upload": {"url",
  "method": "PUT", "expiresAt"}}`. Room counts against the group's file quota
  at once (507 `quota_exceeded`), larger files are refused (413), and on a
  server that charges, a group that may not upload gets 402. Every address
  handed out costs requests that object storage charges for, so a group
  makes room for 20 files at once, then one a minute (§6.13).
- The device sends the sealed bytes with the method to the URL, which works
  without a session until `expiresAt`, 2 minutes on, and takes exactly the
  announced size. It may be the server's own (`/v1/file-data/{token}`) or
  object storage's, such as a presigned S3 address that signs the
  `Content-Length`. A device whose upload fails deletes the file, which
  gives its room back once the address expires.
- `POST /v1/groups/{group}/files/{id}/complete` confirms the upload once its
  length matches the announced size (409 otherwise). Unconfirmed room is
  dropped after an hour.
- `GET /v1/groups/{group}/files/{id}` answers `{"size": n, "download":
  {"url", "method": "GET", "expiresAt"}}` for a confirmed file. A download
  address works for 5 minutes. A file whose stored bytes no longer have
  its size is removed instead, and answers `404`.
- `DELETE /v1/groups/{group}/files/{id}` removes it. Its upload address may
  still work until it expires, and an upload that started through it may
  take 10 minutes more, so the file counts against the group's quota until
  then, and whatever arrives through it is removed. A file also goes
  `ttlSeconds` after its upload is confirmed, or when its group is deleted.
- A group keeps at most 1000 files by default, and one that doesn't pay 20,
  counting those not uploaded yet and deleted ones whose upload address
  still works; past that, room for another answers `507 quota_exceeded`.

Devices check a downloaded file against the size in the record before
opening it.

## 7. Device flows (informative)

- **Create a group:**
  1. Generate a random group id and a recovery code.
  2. Generate the device's keys and the root key `K_1`.
  3. Sign the genesis with both keys.
  4. Wrap `K_1` for recovery and send `POST /v1/groups`.
- **Add a device with a QR code:**
  1. One device opens a slot and shows the QR code. A phone usually scans a
     computer's screen, whichever of the two is new.
  2. The existing device writes the invite. The new device reads it, and
     writes its join request.
  3. The existing device appends `add_device`, with a wrap of the current
     root key for the new device. Then it writes the join result.
  4. The new device logs in, checks the chain against the invite's head,
     unwraps its key and checks the commitment. Either device deletes the
     slot.
- **Add a device without a camera:** the existing device opens a slot with a
  code and shows the code. The user types it on the new device. Before the
  existing device appends `add_device`, the user checks that both screens
  show the same approval words (§4.9).
- **Recover:**
  1. Type the 24 words and the server's address.
  2. Log in with the recovery key. The session response names the group.
  3. Read the chain and check that its recovery key is this code's.
  4. Read the recovery wrap, unwrap it and check the commitment.
  5. Append `add_device` authorized by the recovery key.
  6. Continue as the new device.
- **Remove a device:**
  1. Append `remove_device`, then `rotate` with a new root key wrapped for
     every remaining device and recovery.
  2. Write new records under the new epoch.
- **Leave:** a device removes itself. It cannot rotate for the others: a
  `remove_device` or `reset_recovery` with no `rotate` after it leaves a
  rotation due, and the next device to sync appends the `rotate`. The
  chain's compare-and-set lets only one device do so.
- **If the recovery code may have leaked:** generate a new code, then
  `reset_recovery` and `rotate`.
- **Read older records:** open the sealed previous roots back from the
  current key.

## 8. Client sync algorithm (informative)

`flectar-mail-sync-client` implements this section. A device keeps:
- the whole chain it verified, and its root keys
- a cursor: the highest `seq` it has applied
- a seen mark: the highest `seq` it knows the server reached, from reads
  and from its own commits
- a mirror: for each record, the last server version and the newest stamp
  seen, even after a deletion. It is the base of three-way merges.
- an outbox: local changes not yet committed, each stamped when made

**Logging in** (§6.4): on `challenge_expired`, the device logs in again
with a new challenge, a few times, then tries again later. On
`device_unknown`, the server may have lost the group, so the device creates
it again from its genesis (step 6). If it exists (`409`), the server lost at
most the operation that added this device, which another device appends
again: the device keeps everything and tries again later. Only
`device_removed` and `group_deleted` are final, and only then does a device
leave the group and drop its keys.

One sync cycle:

1. **Chain:** read operations from the device's last one, which the server
   must still hold, and verify them (§5.4). A different operation there is a
   fork, and the device stops. If a rotation is due (§7), rotate.
2. **Pull:** read `changes` from the cursor until `more` is false. A page
   of changes or operations that says more follow and brings nothing new
   is an error, so a faulty server can't keep a device asking forever.
   - Decrypt each record and merge it into local state against the mirror.
   - A version whose stamp is older than the mirror's newest was rolled back
     by the server. The device refuses it and commits its own version again,
     on the server's `seq`.
   - A record that does not decrypt or parse is skipped and reported, so
     one bad record cannot stop sync.
3. **Push:** commit the outbox with `expectedSeq` taken from the mirror.
   A record larger than `maxRecordBytes` stays in the outbox, reported,
   and the rest goes.
   - `409 conflict`: pull again, merge, and retry. A conflicting version the
     pull could not read is written over: the change is committed again on
     the `seq` the conflict named.
   - `409 stale_epoch`: read the chain, fetch the new root key, seal again.
   - `402 payment_required`: commit only the outbox's deletions, which the
     group may still make, then stop. What was pulled stays applied, and the
     other changes wait until the group pays (§6.14).
   - `507 quota_exceeded`, `507 server_full` or `413 payload_too_large`:
     stop pushing, and report it. What was pulled stays applied.
4. **`410 gone`:** read the whole group from `since=0`, then forget mirrored
   records that are not in it. Their deletions expired.
5. **Rollback:** a server `highSeq` below the seen mark means the server lost
   data, for example after a restore from backup.
   - Read the whole group from `since=0`.
   - Commit again the versions the server lacks or holds older copies of.
   - Take the server's `highSeq` as the new seen mark.
6. **Lost chain:** if the server's chain is a prefix of the device's, the
   device appends the missing operations again, with the wraps each one
   needs. Appending takes a session, so a device added in the lost part,
   which the server doesn't know, waits (`device_unknown`) until one it
   knows does it. If the server lost the whole group, so that logins answer
   `device_unknown`, the device creates the group again from its genesis;
   the rest of the chain then waits for the group's first device, the only
   one the genesis names. A server restored from a backup can therefore be
   repaired by any member it still knows, and one that lost everything only
   while the group's first device remains a member.
7. **When:** sync at start and on foreground, about 2 s after a local
   change, on each `seq` or `chain` event, and periodically while running.

## 9. Limits

These are the defaults. A server may configure others; `/v1/info` reports
the ones clients must respect.

| Limit | Default |
|---|---|
| Record ciphertext | 256 KiB |
| Records per commit | 1000 |
| Request body | 8 MiB for a commit, 256 KiB for other requests with a session, 64 KiB for those without but the payment provider's events (256 KiB) and uploads to a server's own file addresses (the file's size) |
| Stored bytes per group | 64 MiB, each record, tombstone and operation counting 256 bytes more; 8 MiB for a group that doesn't pay (§6.14) |
| Records or operations per page | 1000; a page of records also ends near 2 MiB |
| Devices per group | 25 |
| Operations per chain | 1000, then only those of §6.10 |
| Open pairing slots per server | 4096; 8 per client address |
| Pending login challenges | 100000; 64 per client address |
| Pairing slot lifetime | 10 min |
| Messages per pairing slot | 4 |
| Pairing message | 4096 bytes |
| Wrap size | 4096 bytes |
| Challenge lifetime | 120 s |
| Session lifetime | 1 h |
| Tombstone retention | 180 days |
| Sealed file | 26 MiB |
| File bytes per group | 512 MiB; 32 MiB for a group that doesn't pay |
| Files per group | 1000; 20 for a group that doesn't pay |
| File lifetime | 60 days |
| Unused group lifetime | 2 years without a sign-in |

## 10. Security considerations

- **What the server learns:**
  - group and device ids and public keys
  - the membership chain
  - opaque tags
  - the size of each file, and when it is stored and fetched
  - padded sizes
  - sequence numbers
  - timing
  - the connecting addresses, which it does not log by default
- **What it cannot do:**
  - read records or learn their kind
  - move a ciphertext to another record
  - log in as a device
  - add a device: every operation is signed by a member, and devices verify
    the chain
  - slip a root key of its own to devices: unwrapped keys must match the
    chain's commitment
- **Rollback detection:**
  - A server that rolls a group back is detected through `highSeq` and the
    seen mark (§8).
  - A server that rolls one record back is detected through the record's
    stamp (§4.5).
  - A server that rolls the chain back is detected because devices keep the
    chain they verified, and they append the lost operations again.
  - A server can withhold a record or a deletion from a device that never saw
    it; nothing detects that.
- **Billing:** on a server that charges, the payment provider links a
  paying group to whoever paid: their name, email address and payment
  details. The server stores only the provider's customer and subscription
  ids. Records stay unreadable either way. For a code, the server keeps its
  hash, when it was redeemed, and the end of the group's free period; whoever
  hands out codes knows whom each one went to.
- **Logins:** login signatures are bound to the server URL and to a
  single-use nonce. Session tokens are random and stored only as SHA-256
  hashes.
- **What a refused login reveals:** a challenge request already names a
  group and a device, and is answered the same way whether they exist.
  `device_unknown` doesn't say whether the group, the device or the
  signature was wrong. Only the holder of a removed device's key learns
  that it was removed. Whoever knows a group's id learns whether it was
  deleted. Group and device ids are random; the group's devices and the
  server know them, and a paying group's id also reaches the payment
  provider (§6.14).
- **Removed devices:** a removed device keeps what it already saw. After
  `rotate`, it cannot read anything new.
- **Pairing:**
  - Root keys never pass through a slot: they are wrapped to the new
    device's KEM key and checked against the chain's commitment.
  - With a QR code, the server relays only ciphertext bound to the slot and
    the message's index.
  - With a short code, the server, or whoever guesses the code first, can
    read the invite: the group id, the chain head and the server URL, none of
    them secret. It can only add its own keys if the user accepts approval
    words that differ.
