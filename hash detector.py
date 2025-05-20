import hashlib as hash
import re
import argparse
import os

HASH_ALGORITHM_MAP = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
    "BLAKE2": "blake2b",
    "bcrypt": "bcrypt",
}
def detect_hash(hash_str):
    if re.match(r"^[a-f0-9]{32}$", hash_str):
        return "MD5"
    elif re.match(r"^[a-f0-9]{40}$", hash_str):
        return "SHA-1"
    elif re.match(r"^[a-f0-9]{64}$", hash_str):
        return "SHA-256"
    elif re.match(r"^\$2[aby]\$\d{2}\$", hash_str):
        return "bcrypt"
    else:
        return "Unknown"

def generate_hash(file_path, algorithm):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    algorithm = HASH_ALGORITHM_MAP.get(algorithm.upper(), algorithm.lower())
    if algorithm not in HASH_ALGORITHM_MAP.values():
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    hasher = hash.new(algorithm)
    with open(file_path, 'rb') as f:
        while data := f.read(65536):
            hasher.update(data)
    return hasher.hexdigest()

def verify_hash(actual_hash, expected_hash):
    if actual_hash.lower() == expected_hash.lower():
        print("File is safe and unaltered.✅")
    else:
        print("File is not safe (hash mismatch).❌")

def main():
    parser = argparse.ArgumentParser(description="A little description about my script.")
    parser.add_argument("-f","--file",required=True,help="the file you want to verify its hash.")
    parser.add_argument("-H","--Hash",type=str.lower,required=True,help="the Hash you got with the program you just install it. :)")
    parser.add_argument("-a","--algorithm",type=str.lower,required=False,help="the algorithm you want to use to generate the hash or you found it in the hash you got.")
    # parser.add_argument("-s","--size",type=int,default=65536,help="Set the chunk size for file processing.")
    
    args =  parser.parse_args()
    file_path = args.file
    hash_str = args.Hash
    algo = args.algorithm

    print("INFO: Script started")
    algorithm = detect_hash(hash_str)
    print(f"Detected hash algorithm: {algorithm}")
    if not algorithm:
        algorithm = algo

    if algorithm.lower() == "unknown" or algorithm.lower() == "bcrypt":
        print("Unsupported or unknown hash type.")
        exit(1)

    try:
        actual_hash = generate_hash(file_path, algorithm)
        print(f"Computed hash: {actual_hash}")
        print(f"Expected hash: {hash_str}")
        verify_hash(actual_hash, hash_str)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)

if __name__ == "__main__":
    main()