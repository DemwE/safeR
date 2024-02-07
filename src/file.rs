use std::env;
use anyhow::anyhow;
use std::fs::File;
use std::io::{Read, Write};
use chacha20poly1305::aead::stream;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::fs::rename;
use log::debug;
use crate::generate_key::generator;

pub fn encrypt(
    source_file_path: &String,
    dist_file_path: &String,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.into());
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let temp_file_path = temporary_file_creation();

    {
        let mut source_file = File::open(source_file_path)?;
        let mut temp_file = File::create(&temp_file_path)?;

        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Encrypting file: {}", err))?;
                let written = temp_file.write(&ciphertext)?;
                if written != ciphertext.len() {
                    return Err(anyhow!("Failed to write the entire buffer"));
                }
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting file: {}", err))?;
                let written = temp_file.write(&ciphertext)?;
                if written != ciphertext.len() {
                    return Err(anyhow!("Failed to write the entire buffer"));
                }
                break;
            }
        }
    }

    rename(temp_file_path, dist_file_path)?;

    Ok(())
}

pub fn decrypt(
    encrypted_file_path: &str,
    dist_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.into());
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let temp_file_path = temporary_file_creation();

    {
        let mut encrypted_file = File::open(encrypted_file_path)?;
        let mut temp_file = File::create(&temp_file_path)?;

        loop {
            let read_count = encrypted_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let plaintext = stream_decryptor
                    .decrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Decrypting file: {}", err))?;
                let written = temp_file.write(&plaintext)?;
                if written != plaintext.len() {
                    return Err(anyhow!("Failed to write the entire buffer"));
                }
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting file: {}", err))?;
                let written = temp_file.write(&plaintext)?;
                if written != plaintext.len() {
                    return Err(anyhow!("Failed to write the entire buffer"));
                }
                break;
            }
        }
    }

    rename(temp_file_path, dist_file_path)?;

    Ok(())
}

fn temporary_file_creation() -> String {
    // Random key
    let key = generator();
    // Create a temporary file in the system's temporary directory
    let temp_dir = env::temp_dir();
    let temp_file_path = format!("{}safeR_TEMP-{}", temp_dir.display(), key);
    debug!("Temp file path: {:?}", temp_file_path);
    File::create(&temp_file_path).unwrap();
    return temp_file_path;
}