from aesencrypt import Encrypt
from aesdecrypt import Decrypt
import argparse
import os

def main():
    parser = argparse.ArgumentParser(description="Accept an input string")
    parser.add_argument("--plaintext", type=str, required=True, help="Input string")
    
    args = parser.parse_args()
    key = os.urandom(16).hex()
    plaintext = args.plaintext
    
    ciphertext = Encrypt(key, plaintext).encrypt()
    
    print("Key :", key)
    print("Ciphertext :",ciphertext.hex())

    original_plain_text = Decrypt(key, ciphertext).decrypt()

    print("Original plaintext: ",original_plain_text)




if __name__ == "__main__":
    main()