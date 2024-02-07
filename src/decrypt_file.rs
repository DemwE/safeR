use anyhow::anyhow;
use std::fs::File;
use std::io::{Read, Write};
use chacha20poly1305::aead::stream;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::fs::rename;

pub fn decrypt_file(
    encrypted_file_path: &str,
    dist_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
    temp_file_path: &str,
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.into());
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    {
        let mut encrypted_file = File::open(encrypted_file_path)?;
        let mut temp_file = File::create(temp_file_path)?;

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

    // Rename the temporary file to the original file name
    rename(temp_file_path, dist_file_path)?;

    Ok(())
}