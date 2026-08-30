
from Symmetric_Ciphers.modes import AES_CTR

print("To test a bit flipping attack use message => 'amount=00010'")
plaintext = input("give me a text to encrypt \n")
keyoption = input("[1] 128\n[2] 192\n[3] 256\n\n")
keysize = 256 if keyoption == "3" else 192 if keyoption == "2" else 128
aes_ctr = AES_CTR()
cipher = aes_ctr.encrypt(plaintext, keysize)
key = aes_ctr._master_key
ciphertext_bytes = bytes.fromhex(cipher)
nonce = ciphertext_bytes[:aes_ctr.NONCE_CTR_SIZE]
cont:str = "c"
while cont not in ("d", ""):
    cont = input(f'\n\npress [k] to view key \npress [c] to see ciphertext \npress [n] to see nonce \npress [a] to do an attack example\npress [d] or anything else to decrypt\n:\n')
    if cont == "k":
        print(f"{key.hex()}")
    elif cont == "c":
        print(f"{ciphertext_bytes.hex()}")
    elif cont == "n":
        print(f"{nonce.hex()}")
    elif cont == "a":
        print(f"Original text: {plaintext}")
        tampered = aes_ctr._attack(ciphertext_bytes, b"amount=00010", b"amount=99999", aes_ctr.NONCE_CTR_SIZE).hex()
        decrypted_tampered = aes_ctr.decrypt(tampered, key, keysize)
        print(f"Tampered text: {decrypted_tampered}")
    else:
        break
print(f"decrypted message: {aes_ctr.decrypt(cipher, key, keysize)}")