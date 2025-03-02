import os 

class Encrypt:

    def __init__(self, key, plaintext):

        self.key = key.encode('utf-8')
        self.plaintext = plaintext.encode('utf-8')

        self.s_box = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        )

        self.r_con = (
                0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
                0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
                0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
            )

        self.round_keys = self.aes_key_expansion(self.key)
        
        self.encrypt_ecb()

    def sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = self.s_box[s[i][j]]

    def shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    def add_round_key(self, s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]

    # learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    def xtime(self, a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def mix_single_column(self, a):
        # see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ self.xtime(a[0] ^ a[1])
        a[1] ^= t ^ self.xtime(a[1] ^ a[2])
        a[2] ^= t ^ self.xtime(a[2] ^ a[3])
        a[3] ^= t ^ self.xtime(a[3] ^ u)

    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])

    def bytes_to_matrix(self, data):
        return [list(data[i:i+4]) for i in range(0, len(data), 4)]

    def matrix2bytes(self, matrix):
        """ Converts a 4x4 matrix into a 16-byte array.  """
        return bytes(sum(matrix, []))

    def xor_bytes(self, a, b):
        """ Returns a new byte array with the elements xor'ed. """
        return bytes(i^j for i, j in zip(a, b))

    def pad(self, plaintext):
        """
        Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
        Note that if the plaintext size is a multiple of 16,
        a whole block will be added.
        """
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    def split_blocks(self, message, block_size=16, require_padding=True):
            assert len(message) % block_size == 0 or not require_padding
            return [message[i:i+16] for i in range(0, len(message), block_size)]

    def aes_key_expansion(self, key):
        # Convert the key into a list of 4-byte columns (words)
        key_schedule = self.bytes_to_matrix(key)
        key_size = len(key) // 4  

        round_constant = 1  
        
        # Continue key expansion until we reach the required number of words
        while len(key_schedule) < (10 + 1) * 4:
            temp_word = list(key_schedule[-1])  

            if len(key_schedule) % key_size == 0:
                temp_word = temp_word[1:] + temp_word[:1]  # Rotate left
                temp_word = [self.s_box[byte] for byte in temp_word]  
                temp_word[0] ^= self.r_con[round_constant]  
                round_constant += 1  

            elif len(key) == 32 and len(key_schedule) % key_size == 4:
                temp_word = [self.s_box[byte] for byte in temp_word]  

            temp_word = self.xor_bytes(temp_word, key_schedule[-key_size])  
            key_schedule.append(temp_word)  
        
        # Convert the expanded key schedule into groups of 4 words (4x4 matrices)
        return [key_schedule[i * 4: (i + 1) * 4] for i in range(len(key_schedule) // 4)]
    
    def encrypt_block(self, plaintext):
        
        assert len(plaintext) == 16

        plain_state = self.bytes_to_matrix(plaintext)

        self.add_round_key(plain_state, self.round_keys[0])

        for i in range(1, 10):
            self.sub_bytes(plain_state)
            self.shift_rows(plain_state)
            self.mix_columns(plain_state)
            self.add_round_key(plain_state, self.round_keys[i])

        self.sub_bytes(plain_state)
        self.shift_rows(plain_state)
        self.add_round_key(plain_state, self.round_keys[-1])

        return self.matrix2bytes(plain_state)


    def encrypt_ecb(self):
        
        plaintext = self.pad(self.plaintext)

        blocks = []

        for plaintext_block in self.split_blocks(plaintext):

            block = self.encrypt_block(plaintext_block)
            blocks.append(block)

        return b''.join(blocks)
    
