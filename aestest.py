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

def initialize_aes_sboxes():
    sbox = [0] * 256
    inv_sbox = [0] * 256
    p, q = 1, 1

    # Loop invariant: p * q == 1 in the Galois field
    while True:
        # Multiply p by 3
        p ^= (p << 1) ^ (0x1B if (p & 0x80) else 0)
        p &= 0xFF  # Keep it within 8 bits

        # Divide q by 3 (equivalent to multiplying by 0xF6)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q ^= 0x09 if (q & 0x80) else 0
        q &= 0xFF  # Keep it within 8 bits

        # Compute the affine transformation
        xformed = q ^ ((q << 1) & 0xFF) ^ ((q << 2) & 0xFF) ^ ((q << 3) & 0xFF) ^ ((q << 4) & 0xFF)

        sbox[p] = xformed ^ 0x63

        if p == 1:
            break

    # Special case for 0
    sbox[0] = 0x63

    # Compute the inverse S-Box
    for i in range(256):
        inv_sbox[sbox[i]] = i

    return sbox, inv_sbox

def generate_rcon(size=10):
    """ Generate the AES Rcon table up to the required size """
    rcon = [0x8D] + [0x01]  # Rcon[0] is not used, Rcon[1] = 1
    for i in range(1, size):
        rcon.append((rcon[i] << 1) ^ (0x11B if rcon[i] & 0x80 else 0))  # Multiply by 2 in GF(2^8)
        rcon[i] &= 0xFF  # Keep it within 8 bits
    return rcon[1:]  # Return only relevant Rcon values

def main():
    plaintext = read_multiline_input()

    if not plaintext:
        print("No input provided. Exiting.")
        return
    
    sbox, inv_sbox = initialize_aes_sboxes()
    rcon = generate_rcon(11)

    key = os.urandom(16).hex()
    ciphertext = Encrypt(key, plaintext, sbox, rcon).encrypt()

    print("\nKey:", key)
    print("\nCiphertext:", ciphertext.hex())

    original_plaintext = Decrypt(key, ciphertext,sbox, inv_sbox, rcon).decrypt()
    
    print("\nOriginal plaintext:")
    print(original_plaintext.decode(), "\n")

if __name__ == "__main__":
    main()