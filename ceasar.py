import random

def generate_key(): # key_generation
    return random.randint(26)

def encrypt(s, key): #text -> cipher_text
    pass

def decrypt(c, key): #cipher_text -> text
    pass



key = generate_key()
string = input("give me a text to encrypt \n")
cipher = encrypt(string, key)
input(f'{cipher}\n\n press anything to decrypt\n')
print(decrypt(cipher, key))