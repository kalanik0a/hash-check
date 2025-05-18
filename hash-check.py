import argparse
import hashlib
import os
import sys
from pathlib import Path
import queue
import re
import threading
from multiprocessing import Process, Queue, cpu_count, Manager
from multasker.util import File
from multasker.log import Logger
DEFAULT_DIGEST = "sha1"
NUM_WORKERS = cpu_count()


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
    parser.add_argument("-of", "--output-file", type=str, help="Path to output file for generated hashes.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively traverse directories for hashing.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    return parser.parse_args()


def generate_hash_worker(input_queue, output_queue, digest_algorithm, in_progress_files, verbose):
    """
    Worker function for generating hashes from an input queue and storing results in an output queue.
    """
    while True:
        try:
            file_path = input_queue.get(timeout=5)
            if file_path is None:
                break

            if file_path in in_progress_files:
                continue

            in_progress_files[file_path] = True

            try:
                computed_hash = compute_hash(file_path, digest_algorithm, verbose)
                while True:
                    try:
                        output_queue.put(f"{computed_hash} {file_path}", timeout=5)
                        break
                    except queue.Full:
                        pass
            except TimeoutError as e:
                # output_queue.put(f"TIMEOUT {file_path}: {str(e)}")
                print(f"TIMEOUT {file_path}: {str(e)}")
            except Exception as e:
                # output_queue.put(f"ERROR {file_path}: {str(e)}")
                print(f"ERROR {file_path}: {str(e)}")

            del in_progress_files[file_path]

        except queue.Empty:
            break
        except Exception:
            pass


def natural_sort_key(s):
    """
    Key function for natural sorting.
    Splits the string into parts of digits and non-digits for proper sorting.
    """
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', str(s))]


def generate_hashes(directory, output_file, digest_algorithm, recursive, verbose):
    """
    Generates hashes for files in a directory (recursively or not) and writes them to an output file.
    """
    input_queue = Queue()
    output_queue = Queue(maxsize=1000)

    manager = Manager()
    in_progress_files = manager.dict()

    files_to_process = []
    input_files = os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]
    for root, _, files in input_files:
        for file_name in files:
            file_path = str(Path(root) / file_name)
            if (Path(file_path).is_file()):
                files_to_process.append(file_path)
    files_to_process.sort(key=natural_sort_key)

    for file_path in files_to_process:
        input_queue.put(file_path)

    for _ in range(NUM_WORKERS):
        input_queue.put(None)

    processes = []
    for _ in range(NUM_WORKERS):
        process = Process(target=generate_hash_worker, args=(input_queue, output_queue, digest_algorithm, in_progress_files, verbose))
        process.start()
        processes.append(process)

    with open(output_file, "w") as f:
        while any(p.is_alive() for p in processes) or not output_queue.empty():
            try:
                while not output_queue.empty():
                    result = output_queue.get_nowait()
                    f.write(result + "\n")
            except queue.Empty:
                pass

    for process in processes:
        process.join()


def validate_path(path):
    """
    Validates a file or directory path.
    Args:
        path (str): Path to validate.
    Returns:
        Path: Validated Path object.
    """
    resolved_path = Path(path.strip('"')).resolve()
    if not resolved_path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    return resolved_path

def compute_hash(file_path, digest_algorithm, verbose):
    """
    Computes the hash of a file using the specified digest algorithm with a timeout.
    """
    def hash_file():
        nonlocal result, error
        result = File.hash_file(file_path=file_path, digest_algorithm=digest_algorithm, chunk_size=4096, logger=Logger())

        if result is None:
            error = OSError(f'Could not hash file: {file_path}')

    result = None
    error = None
    thread = threading.Thread(target=hash_file)
    thread.start()
    thread.join()
    if thread.is_alive():
        thread.join()
        raise TimeoutError(f"File processing timed out: {file_path}")
    if error:
        raise error
    return result


def process_file(file_path, expected_hash, digest_algorithm, verbose):
    """
    Processes a single file, computes its hash, and compares it to the expected hash.
    Args:
        file_path (Path): Path to the file.
        expected_hash (str): Expected hash value.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        bool: True if the hashes match, False otherwise.
    """
    computed_hash = compute_hash(file_path, digest_algorithm, verbose)
    print(computed_hash)
    return computed_hash == expected_hash


def process_checksum_file(checksum_file, directory, digest_algorithm, recursive, verbose):
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
            absolute_path = str((directory / parts[1].strip()).resolve())
            checksum_map[absolute_path] = parts[0]

    missing_files = []
    extra_files = []
    all_match = True

    for file_path, expected_hash in checksum_map.items():
        if not Path(file_path).is_file():
            missing_files.append(file_path)
            continue

        if not process_file(Path(file_path), expected_hash, digest_algorithm, verbose):
            all_match = False

    glob = directory.rglob("*") if recursive else directory.glob("*")
    for file_path in glob:
        if file_path.is_file():
            absolute_path = str(file_path.resolve())
            if absolute_path not in checksum_map:
                extra_files.append(absolute_path)

    return all_match, missing_files, extra_files


def worker(input_queue, output_queue, digest_algorithm):
    """
    Worker function for processing files from an input queue and storing results in an output queue.
    Args:
        input_queue (Queue): Queue containing file paths and expected hashes.
        output_queue (Queue): Queue to store results.
        digest_algorithm (str): Hash digest algorithm.
    """
    while not input_queue.empty():
        try:
            file_path, expected_hash = input_queue.get_nowait()
            match = process_file(file_path, expected_hash, digest_algorithm)
            output_queue.put((file_path, match))
        except Exception as e:
            output_queue.put((file_path, False, str(e)))


def process_directory_with_queue(directory, checksum_map, digest_algorithm, recursive):
    """
    Processes files in a directory using multiprocessing with input and output queues.
    Args:
        directory (Path): Path to the directory.
        checksum_map (dict): Mapping of file names to expected hashes.
        digest_algorithm (str): Hash digest algorithm.
    Returns:
        tuple: (bool, list, list) - Validation result, missing files, extra files.
    """
    input_queue = Queue()
    output_queue = Queue()
    results = []
    missing_files = []
    extra_files = []

    for file_name, expected_hash in checksum_map.items():
        file_path = directory / file_name
        if file_path.is_file():
            input_queue.put((file_path, expected_hash))
        else:
            missing_files.append(file_name)

    processes = []
    for _ in range(NUM_WORKERS):
        process = Process(target=worker, args=(input_queue, output_queue, digest_algorithm))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    while not output_queue.empty():
        results.append(output_queue.get())

    glob = directory.rglob("*") if recursive else directory.glob("*")
    for file_path in glob:
        if file_path.is_file() and file_path.name not in checksum_map:
            extra_files.append(file_path.name)

    all_match = all(match for _, match in results if match is not None)
    return all_match, missing_files, extra_files

def split_checksum_file(checksum_file):
    checksum_map = {}
    for line in checksum_lines:
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2:
            absolute_path = str((directory / parts[1].strip()).resolve())
            checksum_map[absolute_path] = parts[0]

def main():
    """
    Main function to handle input arguments and execute the program logic.
    """
    args = parse_arguments()

    digest_algorithm = args.digest or DEFAULT_DIGEST
    if digest_algorithm not in hashlib.algorithms_available:
        print(f"Unsupported digest algorithm: {digest_algorithm}")
        sys.exit(1)

    if args.output_file:
        if args.directory:
            directory = validate_path(args.directory)
            generate_hashes(directory, args.output_file, digest_algorithm, args.recursive, args.verbose)
        elif args.file:
            file_path = validate_path(args.file)
            with open(args.output_file, "w") as f:
                computed_hash = compute_hash(file_path, digest_algorithm, args.verbose)
                f.write(f"{computed_hash} {file_path}\n")
        else:
            print("Error: Must specify either --file or --directory with --output-file.")
            sys.exit(1)
    elif args.checksum_file and args.directory:
        checksum_file = validate_path(args.checksum_file)
        directory = validate_path(args.directory)
        all_match, missing_files, extra_files = process_checksum_file(checksum_file, directory, digest_algorithm, args.recursive, args.verbose)
        if all_match:
            print("file hashes match - OK")
        else:
            print("hash validation failure - ERROR")
        if missing_files:
            print("Files from checksum list not present within input directory:", missing_files)
        if extra_files:
            print("Files from input directory not present in checksum file:", extra_files)
    elif args.hash and args.file:
        file_path = validate_path(args.file)
        if compute_hash(file_path, digest_algorithm, args.verbose) == args.hash:
            print("file hashes match - OK")
        else:
            print("hash validation failure - ERROR")
    else:
        print("No valid input arguments provided.")
        print("Use --help for usage information.")
        sys.exit(1)


if __name__ == "__main__":
    main()