# safeR - Password Generator

`safeR` is a simple and secure file encryption tool.

## Features

- Encrypts files using the XChaCha20Poly1305 algorithm, a variant of the ChaCha20-Poly1305 algorithm with an extended nonce.
- Generates a unique key for each encryption process.
- Works on all files within a specified directory.
- Handles errors gracefully, providing informative error messages.
- Supports debug mode for detailed logging.
- Provides a progress bar for the encryption process.
- Support for manual set workers for parallel processing.
