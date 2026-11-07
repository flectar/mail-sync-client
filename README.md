# Flectar Mail Sync client

The open half of Flectar Mail Sync, the end-to-end encrypted sync of Flectar
Mail's accounts, settings, templates, snoozes, scheduled sends and reply
reminders between a user's devices: the protocol, its cryptography and the
client library that [Flectar Mail](https://github.com/flectar/mail) uses.

Everything is encrypted on the device before it leaves. The server stores only
ciphertext and never holds a key that could read it, which this code lets
anyone check. The server itself is Flectar's hosted service and is not
published.

| Crate | What it is | Licence |
|---|---|---|
| `flectar-mail-sync-proto` | Wire types | Apache-2.0 |
| `flectar-mail-sync-crypto` | Key schedule, record sealing, key wraps, signed membership operations, pairing messages | Apache-2.0 |
| `flectar-mail-sync-client` | Sessions, chain verification, pairing, and the record sync engine behind a storage trait the app implements | Apache-2.0 |

The protocol is specified in [`docs/SPEC.md`](docs/SPEC.md).

This repository is published from Flectar's own repository, where the
server's tests exercise this client end to end. Report problems at
[flectar/mail](https://github.com/flectar/mail/issues), and security issues as
[SECURITY.md](SECURITY.md) describes.
