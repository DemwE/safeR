mod args;
mod encrypt_file;
mod decrypt_file;
mod generate_key;

use std::env;
use std::fs::File;
use arrayref::array_ref;
use clap::Parser;
use log::{LevelFilter, info, debug, error};
use walkdir::WalkDir;

use sha2::{Sha256, Digest};

fn main() {
    // Initialize logger
    if args::Args::parse().debug {
        env_logger::builder().filter(None, LevelFilter::Debug).init();
        info!("Debug mode is enabled");
    }

    // Parse the command line arguments
    let args = args::Args::parse();
    let directory = args.directory;
    debug!("Directory: {}", directory);

    // Get all files in the directory
    let files = get_all_files(&directory);
    debug!("Files: {:?}", files);

    // Create a temporary file in the system's temporary directory
    let temp_dir = env::temp_dir();
    debug!("Temp dir: {:?}", temp_dir);
    let temp_file_path = format!("{}safeR_TEMP", temp_dir.display());
    debug!("Temp file path: {:?}", temp_file_path);
    File::create(&temp_file_path).unwrap();

    if args.encrypt && !args.decrypt {
        let key = generate_key::generator();
        debug!("Key: {:?}", key);

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();

        let nonce: [u8; 19] = array_ref![result, 0, 19].clone();
        debug!("Nonce: {:?}", nonce);

        // Encrypt all files
        for file in files {
            let file_path = file.as_ref();
            let key_bytes = key.as_bytes();
            let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
            match encrypt_file::encrypt_file(file_path, file_path, &key_array, &nonce, &temp_file_path) {
                Ok(_) => info!("File {} encrypted successfully", file),
                Err(e) => error!("Failed to encrypt file {}: {:?}", file, e),
            }
        }

        info!("All files in {} encrypted", directory);
        println!("Key: {}", key);
    }
    else if args.decrypt && !args.encrypt {
        if args.key.is_none() {
            error!("Please provide a key to decrypt the files");
            println!("Please provide a key to decrypt the files -k <key>");
            return;
        }else {
            let key = args.key.unwrap();
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let result = hasher.finalize();

            let nonce: [u8; 19] = array_ref![result, 0, 19].clone();
            debug!("Nonce: {:?}", nonce);

            info!("Key: {}", key);
            // Decrypt all files
            for file in files {
                let file_path = file.as_ref();
                let key_bytes = key.as_bytes();
                let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
                match decrypt_file::decrypt_file(file_path, file_path, &key_array, &nonce, &temp_file_path) {
                    Ok(_) => info!("File {} decrypted successfully", file),
                    Err(e) => error!("Failed to decrypt file {}: {:?}", file, e),
                }
            }

            info!("All files in {} decrypted", directory);
        }

    }
    else {
        // Ask user to choose either encryption or decryption
        error!("Please choose either encryption or decryption");
        println!("Please choose either encryption or decryption");
        println!("--encrypt or -z: Encrypt files");
        println!("--decrypt or -x: Decrypt files");
    }
}

fn get_all_files(directory: &str) -> Vec<String> {
    WalkDir::new(directory)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

