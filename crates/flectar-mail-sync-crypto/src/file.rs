//! Files too large for a record (SPEC §4.10). Each file is sealed under a
//! key of its own, chosen at random and carried only inside a record, so the
//! server stores ciphertext it cannot open.

use crate::{Error, Result, label, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// The format of a sealed file, its first byte.
const VERSION: u8 = 1;
/// Version byte and nonce before the ciphertext; tag after it.
const OVERHEAD: usize = 1 + 24 + 16;

/// A new random key for one file.
pub fn file_key() -> Result<[u8; 32]> {
    random_bytes()
}

/// The length of `len` bytes once sealed.
pub const fn sealed_file_len(len: usize) -> usize {
    len + OVERHEAD
}

/// Seal a file: the version byte, a random 24-byte nonce, then its
/// XChaCha20-Poly1305 ciphertext and tag.
pub fn seal_file(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<24>()?;
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: label::FILE,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    let mut sealed = Vec::with_capacity(sealed_file_len(plaintext.len()));
    sealed.push(VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Open a file sealed by [`seal_file`].
pub fn open_file(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return Err(Error::Malformed("a sealed file is too short"));
    }
    if sealed[0] != VERSION {
        return Err(Error::Malformed("unknown sealed file version"));
    }
    let nonce: [u8; 24] = sealed[1..25]
        .try_into()
        .map_err(|_| Error::Malformed("a sealed file is too short"))?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &sealed[25..],
                aad: label::FILE,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_opens_with_its_key_only() {
        let key = file_key().unwrap();
        let sealed = seal_file(&key, b"a message with its attachments").unwrap();
        assert_eq!(sealed.len(), sealed_file_len(30));
        assert_eq!(
            open_file(&key, &sealed).unwrap(),
            b"a message with its attachments"
        );
        assert!(matches!(
            open_file(&file_key().unwrap(), &sealed),
            Err(Error::Decrypt)
        ));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(open_file(&key, &tampered), Err(Error::Decrypt)));
        assert!(matches!(
            open_file(&key, &sealed[..10]),
            Err(Error::Malformed(_))
        ));
    }
}
