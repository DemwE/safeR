use std::sync::Arc;
use arrayref::array_ref;
use futures::future::try_join_all;
use log::{debug, error, info};
use sha2::{Sha256, Digest};
use tokio::sync::Semaphore;
use crate::{args, file, generate_key};

pub async fn handle_encryption(args: args::Args, files: Vec<String>, pb: Option<indicatif::ProgressBar>) {
    if files.is_empty() {
        error!("No files found in {}", args.directory);
        println!("No files found in {}", args.directory);
        return;
    }

    let key = generate_key::generator();
    debug!("Key: {:?}", key);

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();

    let nonce: [u8; 19] = *array_ref![result, 0, 19];
    debug!("Nonce: {:?}", nonce);

    // Create a Vec to hold all the tasks
    let mut tasks = Vec::new();
    let semaphore = Arc::new(Semaphore::new(args.workers));

    // Encrypt all files
    for file_path in files.clone() {
        let key_bytes = key.as_bytes();
        let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
        let pb = pb.clone();
        let semaphore = Arc::clone(&semaphore);

        // Create a new task for each file
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            match file::encrypt(&file_path, &file_path, &key_array, &nonce) {
                Ok(_) => {
                    info!("File {} encrypted successfully", file_path);
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                }
                Err(e) => {
                    error!("Failed to encrypt file {}: {:?}", file_path, e);
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                }
            }
        });

        // Add the task to the Vec
        tasks.push(task);
    }
    // Wait for all tasks to complete
    let results = try_join_all(tasks).await;

    // Handle errors (if any)
    if let Err(e) = results {
        error!("Failed to encrypt some files: {:?}", e);
    }

    if !args.debug && !args.progress {
        if let Some(pb) = &pb {
            // Finish the progress bar
            pb.finish_with_message("All files encrypted.");
        }
    }
    info!("All {} files in {} encrypted", files.len(),args.directory);
    println!("Key: {}", key);
}

pub async fn handle_decryption(args: args::Args, files: Vec<String>, pb: Option<indicatif::ProgressBar>) {
    if args.key.is_none() {
        error!("Please provide a key to decrypt the files");
        println!("Please provide a key to decrypt the files -k <key>");
    } else {
        let key = args.key.unwrap();
        info!("Key: {}", key);

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        let nonce: [u8; 19] = *array_ref![result, 0, 19];
        debug!("Nonce: {:?}", nonce);

        // Create a Vec to hold all the tasks
        let mut tasks = Vec::new();
        let semaphore = Arc::new(Semaphore::new(args.workers));

        // Decrypt all files
        for file_path in files.clone() {
            let key_bytes = key.as_bytes();
            let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
            let pb = pb.clone();
            let semaphore = Arc::clone(&semaphore);

            // Create a new task for each file
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                match file::decrypt(&file_path, &file_path, &key_array, &nonce) {
                    Ok(_) => {
                        info!("File {} decrypted successfully", file_path);
                        if let Some(pb) = &pb {
                            pb.inc(1);
                        }
                    }
                    Err(e) => {
                        error!("Failed to decrypt file {}: {:?}", file_path, e);
                        if let Some(pb) = &pb {
                            pb.inc(1);
                        }
                    }
                }
            });

            // Add the task to the Vec
            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = try_join_all(tasks).await;

        // Handle errors (if any)
        if let Err(e) = results {
            error!("Failed to decrypt some files: {:?}", e);
        }

        info!("All {} files in {} decrypted", files.len(),args.directory);

        if !args.debug && !args.progress {
            if let Some(pb) = &pb {
                // Finish the progress bar
                pb.finish_with_message("All files decrypted.");
            }
        }
    }
}