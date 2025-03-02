import os
import sys

# Windows-specific imports
if os.name == 'nt':
    import msvcrt

from aesencrypt import Encrypt
from aesdecrypt import Decrypt

def read_multiline_input():
    """ Reads multiline input and exits on Ctrl+D for all OSes (Windows, Linux, macOS) """
    print("Enter your plaintext. Press ENTER for a new line. Press Ctrl+D to finish:")

    input_lines = []
    
    try:
        if os.name == 'nt':  # Windows handling
            while True:
                line = ""
                while True:
                    char = msvcrt.getwch()  # Read one character at a time
                    if char == '\x04':  # Ctrl+D (EOF in ASCII)
                        raise EOFError
                    elif char in ('\r', '\n'):  # Enter key
                        print()  # Move to the next line
                        break
                    print(char, end='', flush=True)  # Show typed characters
                    line += char
                if line:
                    input_lines.append(line)
        else:  # Linux/macOS handling
            while True:
                line = input()
                input_lines.append(line)
    except EOFError:  # Handles Ctrl+D in all OSes
        print("\nInput finished.")

    return "\n".join(input_lines).strip()

def main():
    plaintext = read_multiline_input()

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