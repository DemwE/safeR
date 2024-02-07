mod args;
mod file;
mod generate_key;

use arrayref::array_ref;
use clap::Parser;
use log::{LevelFilter, info, debug, error};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use futures::future::try_join_all;
use indicatif::{ProgressBar, ProgressStyle};

#[tokio::main]
async fn main() {
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
    debug!("Number of files: {}", files.len());

    let pb = if !args.debug && !args.progress {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {eta}").unwrap()
            .progress_chars("#>-"));
        Some(pb)
    } else {
        info!("Debug mode is enabled - progress bar will not be shown");
        None
    };

    if args.encrypt && !args.decrypt {
        if files.is_empty() {
            error!("No files found in {}", directory);
            println!("No files found in {}", directory);
            return;
        }

        let key = generate_key::generator();
        debug!("Key: {:?}", key);

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();

        let nonce: [u8; 19] = array_ref![result, 0, 19].clone();
        debug!("Nonce: {:?}", nonce);

        // Create a Vec to hold all the tasks
        let mut tasks = Vec::new();

        // Encrypt all files
        for file_path in files.clone() {
            let key_bytes = key.as_bytes();
            let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
            let pb = pb.clone();

            // Create a new task for each file
            let task = tokio::spawn(async move {
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
        info!("All {} files in {} encrypted", files.len(),directory);
        println!("Key: {}", key);
    } else if args.decrypt && !args.encrypt {
        if args.key.is_none() {
            error!("Please provide a key to decrypt the files");
            println!("Please provide a key to decrypt the files -k <key>");
            return;
        } else {
            let key = args.key.unwrap();
            info!("Key: {}", key);

            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let result = hasher.finalize();

            let nonce: [u8; 19] = array_ref![result, 0, 19].clone();
            debug!("Nonce: {:?}", nonce);

            // Create a Vec to hold all the tasks
            let mut tasks = Vec::new();

            // Decrypt all files
            for file_path in files.clone() {
                let key_bytes = key.as_bytes();
                let key_array = <[u8; 32]>::try_from(&key_bytes[0..32]).unwrap();
                let pb = pb.clone();

                // Create a new task for each file
                let task = tokio::spawn(async move {
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

            info!("All {} files in {} decrypted", files.len(),directory);

            if !args.debug && !args.progress {
                if let Some(pb) = &pb {
                    // Finish the progress bar
                    pb.finish_with_message("All files decrypted.");
                }
            }
        }
    } else {
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