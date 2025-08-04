use argon2::{Algorithm, Argon2, Params, Version, password_hash::rand_core::RngCore};
use chacha20poly1305::{
    Key, XChaCha20Poly1305,
    aead::{
        KeyInit, OsRng,
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
    },
};
use std::io::{self, Read, Write};

pub fn hash_password(password: &[u8], salt: &[u8; 16]) -> argon2::Result<[u8; 32]> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);

    let mut out = [0u8; 32];

    argon2.hash_password_into(password, salt, &mut out)?;

    Ok(out)
}

const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 1024;

pub struct Encryptor<W: Write> {
    inner: W,
    encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
    buffer: Vec<u8>,
}

impl<W: Write> Encryptor<W> {
    pub fn new(mut inner: W, key: &[u8]) -> io::Result<Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        inner.write_all(&nonce)?;

        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        inner.write_all(&salt)?;

        let key_hash = hash_password(key, &salt).expect("Hashing password should not fail");

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_hash));
        let encryptor = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce));

        Ok(Self {
            inner,
            encryptor: Some(encryptor),
            buffer: Vec::new(),
        })
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= CHUNK_SIZE {
            let chunk = self.buffer.drain(..CHUNK_SIZE).collect::<Vec<_>>();

            let ciphertext = self
                .encryptor
                .as_mut()
                .unwrap()
                .encrypt_next(&chunk[..])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            self.inner.write_all(&ciphertext)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            if let Some(encryptor) = self.encryptor.take() {
                let ciphertext = encryptor
                    .encrypt_last(&self.buffer[..])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                self.inner.write_all(&ciphertext)?;
                self.buffer.clear();
            }
        }
        self.inner.flush()
    }
}

pub struct Decryptor<R: Read> {
    inner: R,
    decryptor: Option<DecryptorBE32<XChaCha20Poly1305>>,
    buffer: Vec<u8>,        // decrypted data buffer
    encrypted_buf: Vec<u8>, // encrypted buffer
}

impl<R: Read> Decryptor<R> {
    pub fn new(mut inner: R, key: &[u8]) -> io::Result<Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        inner.read_exact(&mut nonce)?;

        let mut salt = [0u8; SALT_SIZE];
        inner.read_exact(&mut salt)?;

        let key_hash = hash_password(key, &salt).expect("Password hashing should not fail");

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_hash));
        let decryptor = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce));

        Ok(Self {
            inner,
            decryptor: Some(decryptor),
            buffer: Vec::new(),
            encrypted_buf: vec![0u8; CHUNK_SIZE + 32],
        })
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, out_buf: &mut [u8]) -> io::Result<usize> {
        // Fill from buffer if there's already decrypted data
        if !self.buffer.is_empty() {
            let to_copy = out_buf.len().min(self.buffer.len());
            out_buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            self.buffer.drain(..to_copy);
            return Ok(to_copy);
        }

        // Read next encrypted chunk
        let n = self.inner.read(&mut self.encrypted_buf)?;
        if n == 0 {
            return Ok(0); // EOF
        }

        let decrypted = self
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_next(&self.encrypted_buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let to_copy = out_buf.len().min(decrypted.len());
        out_buf[..to_copy].copy_from_slice(&decrypted[..to_copy]);

        if to_copy < decrypted.len() {
            self.buffer.extend_from_slice(&decrypted[to_copy..]);
        }

        Ok(to_copy)
    }
}
