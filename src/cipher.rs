use argon2::{Algorithm, Argon2, Params, Version};
use blake3::{Hash, Hasher};
use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use std::io::{Read, Write};

pub fn hash_password(password: &[u8], salt: &[u8; 16]) -> argon2::Result<[u8; 32]> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);

    let mut out = [0u8; 32];

    argon2.hash_password_into(password, salt, &mut out)?;

    Ok(out)
}

pub struct Encryptor<W: Write> {
    inner: W,
    cipher: XChaCha20,
    hasher: Hasher,
}

impl<W: Write> Encryptor<W> {
    pub fn new(inner: W, key: &[u8; 32], nonce: &[u8; 24], hash_nonce: &[u8; 32]) -> Self {
        Self {
            inner,
            cipher: XChaCha20::new(key.into(), nonce.into()),
            hasher: Hasher::new_keyed(hash_nonce),
        }
    }

    pub fn finalize(&self) -> Hash {
        self.hasher.finalize()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut encrypted = buf.to_vec();

        self.cipher.apply_keystream(&mut encrypted);

        self.hasher.update(&encrypted);

        self.inner.write(&encrypted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub struct Decryptor<R: Read> {
    inner: R,
    cipher: XChaCha20,
    hasher: Hasher,
    hash: Hash,
}

impl<R: Read> Decryptor<R> {
    pub fn new(
        inner: R,
        key: &[u8; 32],
        nonce: &[u8; 24],
        hash_nonce: &[u8; 32],
        tag: Hash,
    ) -> Self {
        Self {
            inner,
            cipher: XChaCha20::new(key.into(), nonce.into()),
            hasher: Hasher::new_keyed(hash_nonce),
            hash: tag,
        }
    }

    pub fn verify(self) -> bool {
        self.hasher.finalize() == self.hash
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;

        self.hasher.update(&buf[..read]);

        self.cipher.apply_keystream(&mut buf[..read]);

        Ok(read)
    }
}
