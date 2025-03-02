import os
import sys
from aesencrypt import Encrypt
from aesdecrypt import Decrypt

def main():
    print("Enter Plaintext. Press Enter for a new line. To finish press Ctrl+D two times (Linux/macOS) or Ctrl+Z + ENTER (Windows):")

    try:
        lines = sys.stdin.read()  # Reads everything until EOF (Ctrl+D / Ctrl+Z)
    except KeyboardInterrupt:
        print("\nInput interrupted. Exiting.")
        return

    plaintext = lines.strip()  # Remove any extra newlines

    if not plaintext:
        print("No input provided. Exiting.")
        return

    key = os.urandom(16).hex()
    ciphertext = Encrypt(key, plaintext).encrypt()

    print("\nKey:", key)
    print("Ciphertext:", ciphertext.hex())

    original_plaintext = Decrypt(key, ciphertext).decrypt()
    print("Original plaintext:", original_plaintext.decode(errors="ignore"))

if __name__ == "__main__":
    main()