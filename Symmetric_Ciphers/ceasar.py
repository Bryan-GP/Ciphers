

import random



#ASCII Set
upper = 126
lower = 32
char_space = upper-lower + 1


def generate_key(): # key_generation
    return random.randint(lower, upper)

def encrypt(s, key): #text -> cipher_text
    cipher_text = []
    for letter in s:
        cipher_text.append(chr(( ord(letter) - lower + key) % char_space + lower ))
    return ''.join(cipher_text)
        

def decrypt(c, key): #cipher_text -> text
    plain_text = []
    for letter in c:
        plain_text.append(chr(( ord(letter) - lower - key) % char_space + lower ))
    return ''.join(plain_text)



key = generate_key()
string = input("give me a text to encrypt \n")
cipher = encrypt(string, key)
input(f'{cipher}\n\n press anything to decrypt\n')
print(decrypt(cipher, key))