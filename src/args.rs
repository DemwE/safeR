use clap::{command, Parser};

#[derive(Debug, Default, Parser, Clone)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(
help_template = "{name} {version} {author-section} {about-with-newline} \n {all-args}"
)]
pub struct Args {
    /// Directory to process
    #[clap(default_value = "/")]
    #[clap(short = 'd', long = "dir")]
    pub directory: String,
    /// Activate debug mode
    #[clap(short = 'D', long = "debug")]
    pub debug: bool,
    /// Key to use for decryption
    #[clap(short = 'k', long = "key")]
    pub key: Option<String>,
    /// Decrypt files
    #[clap(short = 'x', long = "decrypt")]
    pub decrypt: bool,
    /// Encrypt files
    #[clap(short = 'z', long = "encrypt")]
    pub encrypt: bool,
    /// Disable progress bar
    #[clap(short = 'p', long = "progressbar")]
    pub progress: bool,
    /// Workers to use for encryption/decryption
    #[clap(default_value = "256")]
    #[clap(short = 'w', long = "workers")]
    pub workers: usize,
}