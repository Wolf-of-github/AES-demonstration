import os 

class Encrypt:

    def __init__(self, key, plaintext, s_box, rcon):

        self.key = key.encode('utf-8')
        self.plaintext = plaintext.encode('utf-8')

        self.s_box = s_box

        self.r_con = rcon

        self.round_keys = self.aes_key_expansion(self.key)
        
        self.encrypt()

    def sub_bytes(self, state):
        state[:] = [[self.s_box[byte] for byte in row] for row in state]

    def shift_rows(self, s):
        for i in range(1, 4):
            row = [s[j][i] for j in range(4)]  
            row = row[i:] + row[:i]            # Rotate left by i positions
            for j in range(4):
                s[j][i] = row[j]               # Put the rotated row back

    def add_round_key(self, state, k):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= k[i][j]

    def gf_multiply_by_2(self, byte):
        return (((byte << 1) ^ 0x1B) & 0xFF) if (byte & 0x80) else (byte << 1)

    def mix_single_column(self, column):
        # Compute the XOR of all elements in the column
        xor_sum = column[0] ^ column[1] ^ column[2] ^ column[3]
        
        # Store the original first element for later use
        first_element = column[0]
        
        # Update each element in the column
        column[0] ^= xor_sum ^ self.gf_multiply_by_2(column[0] ^ column[1])
        column[1] ^= xor_sum ^ self.gf_multiply_by_2(column[1] ^ column[2])
        column[2] ^= xor_sum ^ self.gf_multiply_by_2(column[2] ^ column[3])
        column[3] ^= xor_sum ^ self.gf_multiply_by_2(column[3] ^ first_element)
    
    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])

    def bytes_to_matrix(self, data):
        return [list(data[i:i+4]) for i in range(0, len(data), 4)]


    def matrix_to_bytes(self, matrix):
        return bytes([byte for row in matrix for byte in row])

    def xor_bytes(self, b1, b2):
        return bytes(i^j for i, j in zip(b1, b2))

    def pad(self, data):
        padding_len = 16 - (len(data) % 16) or 16
        return data + bytes([padding_len] * padding_len)

    def split_into_chunks(self, data):
        block_size = 16
        if len(data) % block_size != 0:
            raise Exception("Data length must be a multiple of 16.")
        
        return [data[i:i + block_size] for i in range(0, len(data), block_size)]

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

        if len(plaintext) != 16:
            raise ValueError("Data must be exactly 16 bytes.")

        state = self.bytes_to_matrix(plaintext)
        
        #initial iteration of round keys
        self.add_round_key(state, self.round_keys[0])

        for i in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, self.round_keys[i])

        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.round_keys[-1])

        return self.matrix_to_bytes(state)


    def encrypt(self):
        
        plaintext = self.pad(self.plaintext)
        blocks = []
        chunks = self.split_into_chunks(plaintext)

        for pb in chunks:

            block = self.encrypt_block(pb)
            blocks.append(block)

        return b''.join(blocks)
    
