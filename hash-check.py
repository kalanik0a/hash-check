import argparse
import hashlib
import os
import sys
from pathlib import Path
from queue import Queue
from threading import Thread

DEFAULT_DIGEST = "sha1"
NUM_WORKERS = 4


def parse_arguments():
    """
    Parses command-line arguments.
    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="File hash checker and validator.")
    parser.add_argument("-d", "--digest", type=str, help="Hash digest algorithm (e.g., md5, sha1, sha256, etc.).")
    parser.add_argument("-x", "--hash", type=str, help="Hash to compare against.")
    parser.add_argument("-f", "--file", type=str, help="File path to hash.")
    parser.add_argument("-cf", "--checksum-file", type=str, help="Path to checksum file.")
    parser.add_argument("-dr", "--directory", type=str, help="Directory to scan for files.")
    return parser.parse_args()


def validate_path(path):
    """
    Validates a file or directory path.
    Args:
        path (str): Path to validate.
    Returns:
        Path: Validated Path object.
    """
    resolved_path = Path(path).resolve()
    if not resolved_path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    return resolved_path


def compute_hash(file_path, digest_algorithm):
    """
    Computes the hash of a file using the specified digest algorithm.
    Args:
        file_path (Path): Path to the file.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        str: Computed hash in hexadecimal format.
    """
    hash_func = hashlib.new(digest_algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def process_file(file_path, expected_hash, digest_algorithm):
    """
    Processes a single file, computes its hash, and compares it to the expected hash.
    Args:
        file_path (Path): Path to the file.
        expected_hash (str): Expected hash value.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        bool: True if the hashes match, False otherwise.
    """
    computed_hash = compute_hash(file_path, digest_algorithm)
    return computed_hash == expected_hash


def process_checksum_file(checksum_file, directory, digest_algorithm):
    """
    Processes a checksum file and validates hashes for files in a directory.
    Args:
        checksum_file (Path): Path to the checksum file.
        directory (Path): Path to the directory.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        tuple: (bool, list, list) - Validation result, missing files, extra files.
    """
    with open(checksum_file, "r") as f:
        checksum_lines = f.readlines()

    checksum_map = {}
    for line in checksum_lines:
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2:
            checksum_map[parts[1]] = parts[0]

    missing_files = []
    extra_files = []
    all_match = True

    for file_name, expected_hash in checksum_map.items():
        file_path = directory / file_name
        if not file_path.exists():
            missing_files.append(file_name)
            continue

        if not process_file(file_path, expected_hash, digest_algorithm):
            all_match = False

    for file_path in directory.iterdir():
        if file_path.name not in checksum_map:
            extra_files.append(file_path.name)

    return all_match, missing_files, extra_files


def worker(queue, digest_algorithm, results):
    """
    Worker function for processing files from a queue.
    Args:
        queue (Queue): Queue containing file paths.
        digest_algorithm (str): Hash digest algorithm.
        results (list): Shared list to store results.
    """
    while not queue.empty():
        file_path, expected_hash = queue.get()
        match = process_file(file_path, expected_hash, digest_algorithm)
        results.append((file_path, match))
        queue.task_done()


def process_directory_with_queue(directory, checksum_map, digest_algorithm):
    """
    Processes files in a directory using a queue and multiple threads.
    Args:
        directory (Path): Path to the directory.
        checksum_map (dict): Mapping of file names to expected hashes.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        tuple: (bool, list, list) - Validation result, missing files, extra files.
    """
    queue = Queue()
    results = []
    missing_files = []
    extra_files = []

    for file_name, expected_hash in checksum_map.items():
        file_path = directory / file_name
        if not file_path.exists():
            missing_files.append(file_name)
        else:
            queue.put((file_path, expected_hash))

    threads = []
    for _ in range(NUM_WORKERS):
        thread = Thread(target=worker, args=(queue, digest_algorithm, results))
        thread.start()
        threads.append(thread)

    queue.join()

    for thread in threads:
        thread.join()

    for file_path in directory.iterdir():
        if file_path.name not in checksum_map:
            extra_files.append(file_path.name)

    all_match = all(match for _, match in results)
    return all_match, missing_files, extra_files


def main():
    """
    Main function to handle input arguments and execute the program logic.
    """
    args = parse_arguments()

    digest_algorithm = args.digest or DEFAULT_DIGEST
    if digest_algorithm not in hashlib.algorithms_available:
        print(f"Unsupported digest algorithm: {digest_algorithm}")
        sys.exit(1)

    if args.hash and args.file:
        file_path = validate_path(args.file)
        if process_file(file_path, args.hash, digest_algorithm):
            print("file hashes match - OK")
        else:
            print("hash validation failure - ERROR")
    elif args.checksum_file and args.directory:
        checksum_file = validate_path(args.checksum_file)
        directory = validate_path(args.directory)
        all_match, missing_files, extra_files = process_checksum_file(checksum_file, directory, digest_algorithm)
        if all_match:
            print("file hashes match - OK")
        else:
            print("hash validation failure - ERROR")
        if missing_files:
            print("Files from checksum list not present within input directory:", missing_files)
        if extra_files:
            print("Files from input directory not present in checksum file:", extra_files)
    else:
        print("No valid input arguments provided.")
        print("Use --help for usage information.")
        sys.exit(1)


if __name__ == "__main__":
    main()