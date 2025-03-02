import sys

class Decrypt:
    
    def __init__(self, key, ciphertext, s_box, inv_s_box, rcon):
        
        if not len(ciphertext) % 16 == 0:
            raise Exception("Cipher text length must be a multiple of 16 bytes")
        
        #converts string to encoded bytes object.
        self.key = key.encode('utf-8')
        #already in bytes format as received from aes encrypt
        self.ciphertext = ciphertext
        

        self.s_box = s_box

        self.inv_s_box = inv_s_box
        self.r_con = rcon
        self.round_keys = self.aes_key_expansion(self.key)

        self.decrypt()

    def inv_sub_bytes(self, s):
        s[:] = [list(map(lambda byte: self.inv_s_box[byte], row)) for row in s]

    def inv_shift_rows(self, s):
        for i in range(1, 4):
            s[0][i], s[1][i], s[2][i], s[3][i] = s[(0 - i) % 4][i], s[(1 - i) % 4][i], s[(2 - i) % 4][i], s[(3 - i) % 4][i]

    def add_round_key(self, s, k):
        s[:] = [[s[i][j] ^ k[i][j] for j in range(4)] for i in range(4)]

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

    def inv_mix_columns(self, s):
        # Apply the inverse MixColumns operation to each column in the state
        for i in range(4):
            # Compute intermediate values
            u = self.gf_multiply_by_2(self.gf_multiply_by_2(s[i][0] ^ s[i][2]))
            v = self.gf_multiply_by_2(self.gf_multiply_by_2(s[i][1] ^ s[i][3]))
            
            # Update the state matrix
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v
        
        # Apply the MixColumns operation to complete the inverse
        self.mix_columns(s)

    def bytes_to_matrix(self, data):
        return [list(data[i:i+4]) for i in range(0, len(data), 4)]

    def matrix_to_bytes(self, matrix):
        return bytes([byte for row in matrix for byte in row])

    def xor_bytes(self,b1, b2):
        return bytes(i^j for i, j in zip(b1, b2))

    def remove_padding(self, plaintext):
        
        padding_len = plaintext[-1]
        if padding_len <= 0 or padding_len > len(plaintext):
            raise ValueError("Invalid padding length.")
        data, padding = plaintext[:-padding_len], plaintext[-padding_len:]
        if any(p != padding_len for p in padding):
            raise ValueError("Invalid padding.")
        return data

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

    def decrypt_block(self, encrypted_data):
        
        if len(encrypted_data) != 16:
            raise ValueError("Encrypted data must be exactly 16 bytes.")

        state = self.bytes_to_matrix(encrypted_data)

        # Initial round key addition
        self.add_round_key(state, self.round_keys[-1])
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)

        # Main decryption rounds
        for round_index in range(9, 0, -1):
            self.add_round_key(state, self.round_keys[round_index])
            self.inv_mix_columns(state)
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)

        # Final round key addition
        self.add_round_key(state, self.round_keys[0])
        
        #returns decrypted block as 1D arr of bytes
        return self.matrix_to_bytes(state)

    def decrypt(self):
        
        blocks = []
        chunks = self.split_into_chunks(self.ciphertext)
        for cipher_block in chunks:
            block = self.decrypt_block(cipher_block)
            blocks.append(block)

        remove_paddingded_block = self.remove_padding(b''.join(blocks))
        return remove_paddingded_block