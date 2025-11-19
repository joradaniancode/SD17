#!/usr/bin/env python3

import hashlib
import sys
import re

# Hash types and their corresponding lengths
HASH_LENGTHS = {
    "MD5": 32,
    "SHA1": 40,
    "SHA256": 64,
    "SHA384": 96,
    "SHA512": 128
}

def is_hex(s):
    """Check if the string is a valid hexadecimal."""
    return re.fullmatch(r'[a-fA-F0-9]+', s) is not None

def detect_hash_type(hash_string):
    """Detect the hash type based on its length and if it's valid hex."""
    hash_string = hash_string.strip().lower()

    if not is_hex(hash_string):
        return " Invalid hash: must be hexadecimal characters only (0-9, a-f)."

    for hash_type, length in HASH_LENGTHS.items():
        if len(hash_string) == length:
            return f" Detected hash type: {hash_type}"

    return " Unknown or unsupported hash type."

def generate_md5(plaintext):
    """Generate MD5 hash from a plaintext string."""
    md5_hash = hashlib.md5(plaintext.encode('utf-8')).hexdigest()
    return md5_hash

def interactive_mode():
    print("\n Welcome to the Hash Type Detector & MD5 Generator Tool ")
    print("1. Detect hash type")
    print("2. Generate MD5 from plaintext")
    print("0. Exit")

    while True:
        choice = input("\nEnter your choice (0-2): ").strip()

        if choice == '1':
            hash_input = input("Enter the hash string: ").strip()
            print(detect_hash_type(hash_input))
        elif choice == '2':
            text = input("Enter plaintext to hash: ").strip()
            print(" MD5 Hash:", generate_md5(text))
        elif choice == '0':
            print(" Goodbye!")
            break
        else:
            print(" Invalid choice. Please try again.")

def main():
    if len(sys.argv) == 2:
        # CLI mode: python3 hash_task1.py <hash_string>
        hash_input = sys.argv[1]
        print(detect_hash_type(hash_input))
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
