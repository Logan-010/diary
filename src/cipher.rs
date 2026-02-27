use crate::consts::{CAPACITY, KEY_LENGTH, NONCE_LENGTH, OVERHEAD, SALT_LENGTH};
use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit,
    aead::stream::{DecryptorBE32, EncryptorBE32},
};
use argon2::Argon2;
use color_eyre::eyre::anyhow;
use rand::Rng;
use std::io::{Read, Write};

pub fn hash_password(key: &[u8], salt: &[u8; SALT_LENGTH]) -> argon2::Result<[u8; KEY_LENGTH]> {
    let mut out = [0u8; KEY_LENGTH];
    Argon2::default().hash_password_into(key, salt, &mut out)?;
    Ok(out)
}

pub fn encrypt(
    mut from: impl Read,
    mut to: impl Write,
    key: [u8; KEY_LENGTH],
) -> color_eyre::Result<()> {
    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    to.write_all(&nonce)?;

    let cipher = Aes256GcmSiv::new(&key.into());
    let mut stream = EncryptorBE32::from_aead(cipher, &nonce.into());

    let mut buf = vec![0u8; CAPACITY];
    loop {
        let read = from.read(&mut buf)?;

        if read == CAPACITY {
            stream
                .encrypt_next_in_place(b"", &mut buf)
                .map_err(|e| anyhow!("Error encrypting full chunk: {}", e))?;
            to.write_all(&buf)?;
            buf.truncate(CAPACITY);
        } else {
            buf.truncate(read);
            stream
                .encrypt_last_in_place(b"", &mut buf)
                .map_err(|e| anyhow!("Error encrypting last chunk: {}", e))?;
            to.write_all(&buf)?;
            break;
        }
    }

    Ok(())
}

pub fn decrypt(
    mut from: impl Read,
    mut to: impl Write,
    key: [u8; KEY_LENGTH],
) -> color_eyre::Result<()> {
    let mut nonce = [0u8; NONCE_LENGTH];
    from.read_exact(&mut nonce)?;

    let cipher = Aes256GcmSiv::new(&key.into());
    let mut stream = DecryptorBE32::from_aead(cipher, &nonce.into());

    let mut buf = vec![0u8; CAPACITY + OVERHEAD];
    loop {
        let read = from.read(&mut buf)?;

        if read == CAPACITY + OVERHEAD {
            stream
                .decrypt_next_in_place(b"", &mut buf)
                .map_err(|e| anyhow!("Error decrypting full chunk: {}", e))?;
            to.write_all(&buf)?;
            buf.resize(CAPACITY + OVERHEAD, 0);
        } else {
            buf.truncate(read);
            stream
                .decrypt_last_in_place(b"", &mut buf)
                .map_err(|e| anyhow!("Error decrypting last chunk: {}", e))?;
            to.write_all(&buf)?;
            break;
        }
    }

    Ok(())
}
