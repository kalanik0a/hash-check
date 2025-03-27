# Hash Check Utility

`hash-check.py` is a Python-based utility for validating file hashes. It supports various hashing algorithms and can be used to verify individual files or multiple files using a checksum file. The program is cross-platform and works on Windows, macOS, Linux, and UNIX systems.

## Features

- Supports all hashing algorithms available in Python's `hashlib` (e.g., MD5, SHA1, SHA256, SHA512, etc.).
- Validates individual files against a provided hash.
- Processes checksum files in the format `<hash> <filename>` to validate multiple files in a directory.
- Multi-threaded processing for efficient validation of large directories.
- Defaults to SHA1 if no hashing algorithm is specified.
- Provides meaningful error messages for invalid inputs or mismatched hashes.

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python's standard library)

## Usage

Run the script using Python and provide the appropriate arguments. Below are the available options:

### Command-Line Arguments

| Argument               | Short | Description                                                                 |
|------------------------|-------|-----------------------------------------------------------------------------|
| `--digest`             | `-d`  | Hash digest algorithm (e.g., `md5`, `sha1`, `sha256`, etc.). Defaults to SHA1. |
| `--hash`               | `-x`  | Hash to compare against (used with `--file`).                              |
| `--file`               | `-f`  | File path to hash and validate.                                            |
| `--checksum-file`      | `-cf` | Path to a checksum file containing `<hash> <filename>` pairs.              |
| `--directory`          | `-dr` | Directory to scan for files when using a checksum file.                    |
| `--output-file`        | `-of` | Output file for hash checksums |
| `--verbose`            | `-v`  | Verbose output |

### Examples

#### Validate a Single File
To validate a single file against a provided hash:
```bash
python hash-check.py -d sha256 -f example.txt -x <hash>
```
### Validate Files Using a Checksum File
To validate multiple files in a directory using a checksum file:
```
python hash-check.py -d sha256 -cf checksums.txt -dr /path/to/directory
```
### Default Digest Algorithm
If no digest algorithm is specified, the program defaults to SHA1:
```
python hash-check.py -f example.txt -x <hash>
```

### Output A Checksum File
```
python hash-check.py -dr /path/to/directory -d sha256 -of checksums.sum -r 

python hash-check.py --directory /path/to/directory --digest sha256 --output-file checksums.sum --recursive 

python hash-check.py --file filename.ext  --digest sha256 --output-file checksum.sum --verbose
```

### Output Messages
- file hashes match - OK: All hashes match successfully.
- hash validation failure - ERROR: One or more hashes do not match.
- Files from checksum list not present within input directory: Some files listed in the checksum file are missing in the directory.
- Files from input directory not present in checksum file: Some files in the directory are not listed in the checksum file.

## How It Works
### 1. Single File Validation:

The program computes the hash of the file using the specified digest algorithm.
It compares the computed hash with the provided hash and outputs the result.
### 2. Checksum File Validation:

The program reads the checksum file and maps file names to their expected hashes.
It validates each file in the directory against the expected hash.
Missing or extra files are reported.
### 3. Multi-Threaded Processing:

When validating a directory, the program uses a queue and multiple threads to process files efficiently.

## Error Handling
- If an invalid digest algorithm is provided, the program exits with an error message.
- If a file or directory does not exist, the program raises a FileNotFoundError.
- If no valid arguments are provided, the program displays a help message and exits.
## License
This project is licensed under the MIT License.

## Author
Developed by [Sean Lum](https://www.github.com/seanlum).

## Contribution
Feel free to submit issues or pull requests to improve the functionality of this utility.
