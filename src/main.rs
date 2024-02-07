mod args;
mod file;
mod generate_key;
mod handlers;

use clap::Parser;
use log::{LevelFilter, info, debug, error};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use handlers::{handle_encryption, handle_decryption};

#[tokio::main]
async fn main() {
    // Initialize logger
    if args::Args::parse().debug {
        env_logger::builder().filter(None, LevelFilter::Debug).init();
        info!("Debug mode is enabled");
    }

    // Parse the command line arguments
    let args = args::Args::parse();
    let directory = args.directory.clone();
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
        handle_encryption(args.clone(), files, pb).await;
    } else if args.decrypt && !args.encrypt {
        handle_decryption(args.clone(), files, pb).await;
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