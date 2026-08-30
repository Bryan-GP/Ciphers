
import secrets
from Symmetric_Ciphers.aes import AES

class Mode: 
    def __init__(self):
        self._master_key = b""

    def _xOrBits(self, x, y) -> bytes: 
        return bytes(a ^ b for a, b in zip(x, y))

    def _generate_random_token(self, bytes: int=16) -> bytes: #AES-128 default
        return secrets.token_bytes(bytes)

    def _makeBlocks(self, p: bytes, size=16) -> list[bytes]:
        return [p[i : i + size] for i in range(0, len(p), size)]



#### AES-CTR ####
class AES_CTR(Mode):
    def __init__(self):
        self.aes = AES()
        self.NONCE_CTR_SIZE = 8

    def _operation(self, plaintext: bytes, nonce: bytes, nonce_size: int, key: bytes, bits: int, start_count: int=0): #AES-CTR
        c_text = b""
        expanded_key = self.aes._expand_key(key, bits) 
        p_blocks = self._makeBlocks(plaintext, self.aes.BLOCKSIZE)
        for counter, block in enumerate(p_blocks, start_count):
            counter_bytes = counter.to_bytes(nonce_size, byteorder='big')
            nonce_input = nonce + counter_bytes
            encrypted_nonce = self.aes.encrypt(nonce_input, expanded_key, bits) 
            cipher_block = self._xOrBits(encrypted_nonce, block)
            c_text += cipher_block
        return c_text
        
    def encrypt(self, plaintext: str, bits: int=128, nonce_size: int=8) -> bytes:
        plaintext_bytes = plaintext.encode("utf-8")
        nonce = self._generate_random_token(nonce_size)
        key = self._generate_random_token(self.aes.bits_to_bytes[bits])
        self._master_key = key
        ciphertext = self._operation(plaintext_bytes, nonce, key, bits)
        return (nonce + ciphertext).hex()

    def decrypt(self, ciphertext, key, bits=128, nonce_size: int=8):
        ciphertext_bytes = bytes.fromhex(ciphertext)
        nonce = ciphertext_bytes[:nonce_size]
        actual_ciphertext = ciphertext_bytes[nonce_size:]
        plaintext = self._operation(actual_ciphertext, nonce, key, bits)
        self._master_key = b""
        return plaintext.decode("utf-8")

    def _attack(self, c_text: bytes, p_text: bytes, dp_text: bytes, offset: int) -> bytes:
        if len(p_text) != len(dp_text):
            raise ValueError("Target and plaintext must be the same size")
        if offset < 0 or offset + len(p_text) > len(c_text):
            raise ValueError("Attack range is outside ciphertext bounds")
        delta = self.aes._xOrBits(p_text, dp_text)
        new_c_text = bytearray(c_text)
        for i, delta_byte in enumerate(delta):
            new_c_text[offset + i] ^= delta_byte
        return bytes(new_c_text)


#### AES-GCM ####
class AES_GCM(Mode):
    def __init__(self):
        self.aes = AES()
        self.ctr = AES_CTR()
        self.NONCE_GCM_SIZE : bytes = 12
        self.GHASH_SIZE : bytes = 16

    def _generate_h(self, key: bytes, bits: int) -> bytes:
        expanded_key = self.aes._expand_key(key, bits)
        zero_block = b"\x00" * 16
        return self.aes.encrypt(zero_block, expanded_key, bits)

    def _gf_mult_128(self, x: bytes, y: bytes) -> bytes: 
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')
        Z = 0
        V = y_int
        for i in range(128):
            if ( x_int >> 127 ) & 1 : 
                Z ^= V
            x_int <<= 1
            lowest_bit = V & 1
            V >>= 1
            if lowest_bit:
                V ^= 0xE1000000000000000000000000000000
        return Z.to_bytes(16, byteorder='big')

    def _ghash(self, h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        pad_aad = (16 - (len(aad) % 16)) % 16 if aad else 0
        padded_aad = aad + (b'\x00' * pad_aad)

        pad_cipher = (16 - (len(ciphertext) % 16)) % 16
        padded_ciphertext = ciphertext + (b'\x00' * pad_cipher)

        add_len = (len(aad) * 8 if aad else 0).to_bytes(8, byteorder='big')
        ciphertext_len = (len(ciphertext) * 8).to_bytes(8, byteorder='big')
        length_block = add_len + ciphertext_len

        ghash_payload = padded_aad + padded_ciphertext + length_block
        payload_blocks = self.ctr._makeBlocks(ghash_payload, 16)

        Y = b'\x00' * 16
        for block in payload_blocks:
            Y_xor_Block = self._xOrBits(Y, block)
            Y = self._gf_mult_128(Y_xor_Block, h)
        return Y
    
    def _operation(self, plaintext: bytes, nonce: bytes, key: bytes, bits: int, nonce_size: int=12, start_counter: int=2) -> str: #AES-CTR
        return self.ctr._operation(plaintext, nonce, nonce_size//3, key, bits, start_counter)
        
    def encrypt(self, plaintext: str, key_bits: int=128, aad: bytes=b"") -> bytes:
        plaintext_bytes = plaintext.encode("utf-8")
        nonce = self._generate_random_token(self.NONCE_GCM_SIZE)
        key = self._generate_random_token(self.aes.bits_to_bytes[key_bits])
        self._master_key = key
        ciphertext = self._operation(plaintext_bytes, nonce, key, key_bits)

        expanded_key = self.aes._expand_key(key, key_bits)
        counter_1 = nonce + b"\x00\x00\x00\x01"
        encrypted_counter_1 = self.aes.encrypt(counter_1, expanded_key, key_bits)

        h_key = self._generate_h(key, key_bits)
        ghash = self._ghash(h_key, aad, ciphertext)
        auth_tag = self._xOrBits(ghash, encrypted_counter_1)
        self._auth_tag = auth_tag
        return (nonce + ciphertext + auth_tag).hex()

    def decrypt(self, ciphertext, key, key_bits=128, aad=b"") -> str:
        ciphertext_bytes = bytes.fromhex(ciphertext)
        nonce = ciphertext_bytes[:self.NONCE_GCM_SIZE]
        auth_tag = ciphertext_bytes[-self.GHASH_SIZE:]
        actual_ciphertext = ciphertext_bytes[self.NONCE_GCM_SIZE:-self.GHASH_SIZE]

        expanded_key = self.aes._expand_key(key, key_bits)
        new_counter_1 = nonce + b"\x00\x00\x00\x01"
        new_encrypted_counter_1 = self.aes.encrypt(new_counter_1, expanded_key, key_bits)

        h_key = self._generate_h(key, key_bits)
        new_ghash = self._ghash(h_key, aad, actual_ciphertext)

        new_auth_tag = self._xOrBits(new_ghash, new_encrypted_counter_1)
        if auth_tag != new_auth_tag:
            raise ValueError("Authentication failed, data tampered or key is wrong")
        plaintext = self._operation(actual_ciphertext, nonce, key, key_bits)
        self._master_key = b""
        return plaintext.decode("utf-8")



    #def gcm_attack(self, c_text: bytes, p_text: bytes, dp_text: bytes, offset: int):
    #    pass