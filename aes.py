

import secrets
from typing import Annotated
Bytes16 = Annotated[bytes, 16]
Bytes8 = Annotated[bytes, 8]
Bytes4 = Annotated[bytes, 4]


class AES: 
    def __init__(self):
        self.rounds = 10 # 10 rounds by default
        self.mode = 'ctr' # ctr by default for now
        self.NONCE_CTR_SIZE = 8 #bytes
        self.BLOCKSIZE = 16  #bytes
        self.plaintext = ""
        self.ciphertext = b""
        self._master_key = b""
        self.bits_to_bytes = {128: 16, 192: 24, 256: 32}
        self.bits_to_rounds = {128: 10, 192: 12, 256: 14}
        self.MUL_02 = [((i << 1) ^ 0x1B) & 0xFF if (i & 0x80) else (i << 1) & 0xFF for i in range(256)]
        self.MUL_03 = [self.MUL_02[i] ^ i for i in range(256)]
        self.ROUND_CONSTS = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        self.SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

    def _generate_random_token(self, bytes: int=16) -> Bytes16: #AES-128 default
        return secrets.token_bytes(bytes)

    def _expand_key(self, k: bytes, bits: int) -> list[bytes]: 
        Nk = bits // 32  # 4, 6, or 8
        keys = [k[i : i + 4] for i in range(0, len(k), 4)] 
        i = Nk
        total_words = (self.bits_to_rounds[bits] + 1) * 4
        
        while len(keys) < total_words:
            temp = keys[i-1]
            if i % Nk == 0:
                rottedWord = self._rotWord(temp)
                subbedWord = self._subBytes(rottedWord) 
                temp = self._roundConst(subbedWord, i // Nk) 
            elif Nk == 8 and i % Nk == 4:
                # AES-256 needs this extra non-linear substitution
                temp = self._subBytes(temp)
                
            keys.append(self._xOrBlock(keys[i - Nk], temp))
            i += 1
            
        # Group the flat list of 4-byte words into 16-byte round keys
        return [b"".join(keys[i : i + 4]) for i in range(0, len(keys), 4)]

    def _rotWord(self, word: Bytes4) -> Bytes4:
        return word[1:] + word[:1]

    def _subBytes(self, state): #-> Bytes16 || Bytes4
        return bytes(self.SBOX[byte] for byte in state)

    def _roundConst(self, word: Bytes4, i: int) -> Bytes4: 
        rcon_word = bytes([self.ROUND_CONSTS[i], 0, 0, 0])
        return self._xOrBlock(word, rcon_word)

    def _makeBlocks(self, p: bytes, bytes=16) -> list[Bytes16]:
        return [p[i : i + bytes] for i in range(0, len(p), bytes)]

    def _xOrBlock(self, x, y): #-> Bytes16 || Bytes4
        return bytes(a ^ b for a, b in zip(x, y))

    def _ctr_operation(self, plaintext: bytes, nonce: Bytes8, key: Bytes16, bits: int) -> str: #AES-CTR
        c_text = b""
        expanded_key = self._expand_key(key, bits) 
        p_blocks = self._makeBlocks(plaintext, self.BLOCKSIZE)
        for counter, block in enumerate(p_blocks):
            counter_bytes = counter.to_bytes(self.NONCE_CTR_SIZE, byteorder='big')
            nonce_input = nonce + counter_bytes
            encrypted_nonce = self._aes_encrypt(nonce_input, expanded_key, bits) 
            cipher_block = self._xOrBlock(encrypted_nonce, block)
            c_text += cipher_block
        return c_text
    
    def _aes_encrypt(self, plaintext: Bytes16, expanded_key: list[Bytes16], bits: int=128) -> Bytes16:
        self.rounds = self.bits_to_rounds[bits]
        c_text_i = self._addRoundKey(plaintext, expanded_key[0])
        for i in range(1,self.rounds):
            subbedBytes = self._subBytes(c_text_i)
            shiftedRows = self._shiftRows(subbedBytes)
            mixedCols = self._mixCol(shiftedRows)
            c_text_i = self._addRoundKey(mixedCols, expanded_key[i])
        subbedBytes = self._subBytes(c_text_i)
        shiftedRows = self._shiftRows(subbedBytes)
        c_text_i = self._addRoundKey(shiftedRows, expanded_key[self.rounds])
        return c_text_i

    def _addRoundKey(self, b, k):
        return self._xOrBlock(b, k)

    def _shiftRows(self, state: Bytes16) -> Bytes16: 
        return bytes([
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ])

    def _mixCol(self, state: Bytes16) -> Bytes16:
        # Process state as 4 distinct columns
        mutable_state = bytearray(state)
        for i in range(0, 16, 4):
            column = mutable_state[i:i+4]
            mixed = self._mix_single_column_lookup(column)
            mutable_state[i:i+4] = mixed
        return bytes(mutable_state)

    def _mix_single_column_lookup(self, c):
        r0 = self.MUL_02[c[0]] ^ self.MUL_03[c[1]] ^ c[2] ^ c[3]
        r1 = c[0] ^ self.MUL_02[c[1]] ^ self.MUL_03[c[2]] ^ c[3]
        r2 = c[0] ^ c[1] ^ self.MUL_02[c[2]] ^ self.MUL_03[c[3]]
        r3 = self.MUL_03[c[0]] ^ c[1] ^ c[2] ^ self.MUL_02[c[3]]
        return [r0, r1, r2, r3]

    def encrypt(self, plaintext, bits=128):
        plaintext_bytes = plaintext.encode("utf-8")
        nonce = self._generate_random_token(self.NONCE_CTR_SIZE)
        key = self._generate_random_token(self.bits_to_bytes[bits])
        self._master_key = key
        ciphertext = self._ctr_operation(plaintext_bytes, nonce, key, bits)
        return (nonce + ciphertext).hex()

    def decrypt(self, ciphertext, key, bits=128):
        ciphertext_bytes = bytes.fromhex(ciphertext)
        nonce = ciphertext_bytes[:self.NONCE_CTR_SIZE]
        actual_ciphertext = ciphertext_bytes[self.NONCE_CTR_SIZE:]
        plaintext = self._ctr_operation(actual_ciphertext, nonce, key, bits)
        self._master_key = b""
        return plaintext.decode("utf-8")


plaintext = input("give me a text to encrypt \n")
keyoption = input("[1] 128\n[2] 192\n[3] 256\n\n")
keyint = 1 if keyoption.isdigit() == False else keyoption
keysize = 256 if keyoption == 3 else 192 if keyoption == 2 else 128
aes_ctr = AES()
cipher = aes_ctr.encrypt(plaintext, keysize)
key = aes_ctr._master_key
ciphertext_bytes = bytes.fromhex(cipher)
nonce = ciphertext_bytes[:aes_ctr.NONCE_CTR_SIZE]
cont = "c"
while cont != "d" or cont != "":
    cont = input(f'\n\npress [k] to view key \npress [c] to see ciphertext \npress [n] to see nonce \npress [d] or anything else to decrypt\n:\n')
    if cont == "k":
        print(f"{key.hex()}")
    elif cont == "c":
        print(f"{ciphertext_bytes.hex()}")
    elif cont == "n":
        print(f"{nonce.hex()}")
    else:
        break
print(f"decrypted message: {aes_ctr.decrypt(cipher, key, keysize)}")





