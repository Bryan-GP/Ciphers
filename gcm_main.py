
import os
from Symmetric_Ciphers.modes import AES_GCM

plaintext = input("\n\ngive me a text to encrypt \n")
keyoption = input("\n[1] 128\n[2] 192\n[3] 256\n")
keysize : int = 256 if keyoption == "3" else 192 if keyoption == "2" else 128
aes_gcm : AES_GCM = AES_GCM()
cipher = aes_gcm.encrypt(plaintext, keysize)
key : bytes = aes_gcm._master_key
ciphertext_bytes = bytes.fromhex(cipher)
nonce : bytes = ciphertext_bytes[:aes_gcm.NONCE_GCM_SIZE]
actual_ciphertext = ciphertext_bytes[aes_gcm.NONCE_GCM_SIZE:-aes_gcm.GHASH_SIZE]
auth_tag : bytes = ciphertext_bytes[-aes_gcm.GHASH_SIZE:]
cont : str = "c"

while cont not in ("d", ""):
    #os.system('clear')
    print(f"\nKEY := {key.hex()}")
    print(f"CIPHERTEXT := {cipher} = \n{nonce.hex()} + {actual_ciphertext.hex()} + {auth_tag.hex()}")
    print(f"ABOVE: NONCE + CIPHERTEXT + GMAC_TAG")
    cont = input(f'\npress [a] for auth test\npress [k] to test different key\npress [s] to change key size\npress [d] or anything else to decrypt\n:\n')
    if cont == "a":
        random_bits = aes_gcm._generate_random_token(len(actual_ciphertext))
        new_ciphertext = aes_gcm._xOrBits(random_bits, actual_ciphertext)
        new_cipher = (nonce + new_ciphertext + auth_tag).hex()
        try:
            print(aes_gcm.decrypt(new_cipher, key, keysize))
        except ValueError:
            print(f"new ciphertext: {new_ciphertext.hex()}\nAUTHENTICATION FAILURE: data tampered")
            input("(press anything)\n\n")
    elif cont == "k":
        new_key = aes_gcm._generate_random_token(keysize//8)
        try:
            print(aes_gcm.decrypt(cipher, new_key, keysize))
        except:
            print(f"new key: {new_key.hex()}\nAUTHENTICATION FAILURE: key is wrong")
            input("(press anything)\n\n")
    elif cont == "s":
        plaintext = aes_gcm.decrypt(cipher, key, keysize)
        keyoption = input("\n[1] 128\n[2] 192\n[3] 256\n")
        keysize : int = 256 if keyoption == "3" else 192 if keyoption == "2" else 128
        cipher = aes_gcm.encrypt(plaintext, keysize)
        key : bytes = aes_gcm._master_key
        ciphertext_bytes = bytes.fromhex(cipher)
        nonce : bytes = ciphertext_bytes[:aes_gcm.NONCE_GCM_SIZE]
        actual_ciphertext = ciphertext_bytes[aes_gcm.NONCE_GCM_SIZE:-aes_gcm.GHASH_SIZE]
        auth_tag : bytes = ciphertext_bytes[-aes_gcm.GHASH_SIZE:]
    else:
        break
print(f"decrypted message: {aes_gcm.decrypt(cipher, key, keysize)}\n")