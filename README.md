# Hash Verification Tool (In Development)

A Python command-line utility for verifying file integrity using cryptographic hashes.

## Current Status

This is an active development project. While the core functionality is working, we plan to add several exciting features in the near future!

## Current Features

- Automatic detection of hash algorithms based on hash format
- Support for multiple cryptographic hash algorithms
- File integrity verification
- Clear and informative output
- Built-in error handling

## Planned Features

- User-specified chunk size for file processing
- Support for additional hash algorithms
- Improved error reporting
- More detailed verification statistics
- Additional output formats

## Installation

No installation required. The script uses Python's built-in `hashlib` module.

## Usage

```bash
python hash_detector.py -f <file_path> -H <expected_hash>
or 
py hash_detector.py -f <file_path> -H <expected_hash>

or  if you have more than one python version 

pythonx.xx hash_detector.py -f <file_path> -H <expected_hash>
```

### Required Arguments:
- `-f, --file`: Path to the file you want to verify
- `-H, --Hash`: The expected hash value to verify against

## Example

```bash
python hash_detector.py -f example.txt -H 5d41402abc4b2a76b9719d911017c592
```

## Supported Hash Algorithms

The script automatically detects and supports the following hash algorithms:

- MD5 (32 hexadecimal characters)
- SHA-1 (40 hexadecimal characters)
- SHA-256 (64 hexadecimal characters)
- BLAKE2 (variable length)
- bcrypt (special format starting with $2a$, $2b$, or $2y$)

Note: bcrypt is currently not supported for verification.

## How It Works

1. The script automatically detects the hash algorithm based on:
   - For MD5: 32 hexadecimal characters
   - For SHA-1: 40 hexadecimal characters
   - For SHA-256: 64 hexadecimal characters
   - For bcrypt: starts with $2a$, $2b$, or $2y$

2. If the hash format is not recognized, the script will exit with an error.

3. The script then:
   - Reads the specified file in chunks
   - Generates a hash using the detected algorithm
   - Compares the generated hash with the provided expected hash
   - Displays the verification result

## Output

The script will display:
- The detected hash algorithm
- The computed hash value
- The expected hash value
- A verification result indicating if the file is safe or not

## Error Handling

The script handles the following error cases:
- Missing or inaccessible files
- Unsupported or unknown hash formats
- Invalid hash algorithms
- File processing errors

## Exit Codes

- 0: Success (hash verification completed)
- 1: Error (invalid hash format, file not found, etc.)

## Security Note

This tool is designed for file integrity verification. Always verify files from trusted sources. The script uses Python's built-in `hashlib` module for cryptographic operations.

## Current Limitations

- The `-a` parameter is currently unused and will be ignored
- bcrypt verification is not supported
- The script processes files in 64KB chunks by default
- Limited hash algorithm support
- Basic error reporting only

## Future Enhancements

- Customizable chunk size for file processing
- Support for additional hash algorithms:
  - SHA-3 family
  - Argon2
  - Scrypt
  - PBKDF2
- More detailed verification statistics
- Multiple output formats
- Improved error handling and reporting
- Parallel processing for large files
- Unsupported hash algorithms
- Hash format mismatches
- File access errors

## Exit Codes

- 0: Success
- 1: Error (file not found, unsupported algorithm, etc.)

## Security Note

This tool is for file integrity verification. Always verify files from trusted sources.
