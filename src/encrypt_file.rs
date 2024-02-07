use anyhow::anyhow;
use std::fs::File;
use std::io::{Read, Write};
use chacha20poly1305::aead::stream;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::fs::rename;

pub fn encrypt_file(
    source_file_path: &str,
    dist_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
    temp_file_path: &str,
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.into());
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    {
        let mut source_file = File::open(source_file_path)?;
        let mut temp_file = File::create(temp_file_path)?;

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

    // Rename the temporary file to the original file name
    rename(temp_file_path, dist_file_path)?;

    Ok(())
}