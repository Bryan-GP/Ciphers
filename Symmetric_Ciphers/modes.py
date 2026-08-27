
import secrets
from Symmetric_Ciphers.ciphers import AES

class Mode: 
    def __init__(self):
        self._master_key = b""

    def _xOrBits(self, x, y) -> bytes: 
        return bytes(a ^ b for a, b in zip(x, y))

    def _generate_random_token(self, bytes: int=16) -> bytes: #AES-128 default
        return secrets.token_bytes(bytes)

    def _makeBlocks(self, p: bytes, size=16) -> list[bytes]:
        return [p[i : i + size] for i in range(0, len(p), size)]


class AES_CTR(Mode):
    def __init__(self):
        self.aes = AES()
        self.NONCE_CTR_SIZE = 8

    def _operation(self, plaintext: bytes, nonce: bytes, key: bytes, bits: int) -> str: #AES-CTR
        c_text = b""
        expanded_key = self.aes._expand_key(key, bits) 
        p_blocks = self._makeBlocks(plaintext, self.aes.BLOCKSIZE)
        for counter, block in enumerate(p_blocks):
            counter_bytes = counter.to_bytes(self.NONCE_CTR_SIZE, byteorder='big')
            nonce_input = nonce + counter_bytes
            encrypted_nonce = self.aes._aes_encrypt(nonce_input, expanded_key, bits) 
            cipher_block = self._xOrBits(encrypted_nonce, block)
            c_text += cipher_block
        return c_text
        
    def encrypt(self, plaintext: str, bits: int=128) -> bytes:
        plaintext_bytes = plaintext.encode("utf-8")
        nonce = self._generate_random_token(self.NONCE_CTR_SIZE)
        key = self._generate_random_token(self.aes.bits_to_bytes[bits])
        self._master_key = key
        ciphertext = self.aes._operation(plaintext_bytes, nonce, key, bits)
        return (nonce + ciphertext).hex()

    def decrypt(self, ciphertext, key, bits=128):
        ciphertext_bytes = bytes.fromhex(ciphertext)
        nonce = ciphertext_bytes[:self.NONCE_CTR_SIZE]
        actual_ciphertext = ciphertext_bytes[self.aes.NONCE_CTR_SIZE:]
        plaintext = self.aes._operation(actual_ciphertext, nonce, key, bits)
        self._master_key = b""
        return plaintext.decode("utf-8")

    def ctr_attack(self, c_text: bytes, p_text: bytes, dp_text: bytes, offset: int) -> bytes:
        if len(p_text) != len(dp_text):
            raise ValueError("Target and plaintext must be the same size")
        if offset < 0 or offset + len(p_text) > len(c_text):
            raise ValueError("Attack range is outside ciphertext bounds")
        delta = self.aes._xOrBits(p_text, dp_text)
        new_c_text = bytearray(c_text)
        for i, delta_byte in enumerate(delta):
            new_c_text[offset + i] ^= delta_byte
        return bytes(new_c_text)

class AES_GCM(Mode):
    def __init__(self):
        self.aes = AES()
    
    def _gcm_operation(self, plaintext: bytes, nonce: bytes, key: bytes, bits: int) -> str: #AES-CTR
        pass

    def _gf_mult(self, x: bytes, y: bytes) -> bytes: 
        pass

    def _generate_h(self, key: bytes, bits: int) -> bytes:
        pass

    def _ghash(self, h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        pass
        
    def encrypt(self, plaintext: str, bits: int=128) -> bytes:
        pass

    def decrypt(self, ciphertext, key, bits=128) -> str:
        pass

    #def gcm_attack(self, c_text: bytes, p_text: bytes, dp_text: bytes, offset: int):
    #    pass