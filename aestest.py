import os
import sys

# Windows-specific imports
if os.name == 'nt':
    import msvcrt

from aesencrypt import Encrypt
from aesdecrypt import Decrypt

def read_multiline_input():
    print("Enter your plaintext. Press Enter and Ctrl+D to finish:\n")
    input_lines = []
    
    try:
        if os.name == 'nt':  # Windows handling
            while True:
                line = ""
                while (char := msvcrt.getwch()) not in ('\x04', '\r', '\n'):
                    print(char, end='', flush=True)
                    line += char
                if char == '\x04':  # Ctrl+D
                    raise EOFError
                print()
                if line:
                    input_lines.append(line)
        else:  # Linux/macOS
            while True:
                input_lines.append(input())
    except EOFError:
        print("\n----Input finished----")

    return "\n".join(input_lines).strip()

def main():
    plaintext = read_multiline_input()

    if not plaintext:
        print("No input provided. Exiting.")
        return

    key = os.urandom(16).hex()
    ciphertext = Encrypt(key, plaintext).encrypt()

    print("\nKey:", key)
    print("\nCiphertext:", ciphertext.hex())

    original_plaintext = Decrypt(key, ciphertext).decrypt()
    
    print("\nOriginal plaintext:")
    print(original_plaintext.decode(), "\n")

if __name__ == "__main__":
    main()