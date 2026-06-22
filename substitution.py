
import random

def generate_key(): # key_generation
    nums = [i for i in range(33,126)]
    for i in range(len(nums) - 1, 0, -1):
        j = random.randint(0, i)
        nums[i], nums[j] = nums[j], nums[i]
    return dict(zip(range(33, 126), nums))


def encrypt(s, key): #text -> cipher_text
    return s.translate(key)

def decrypt(c, key): #cipher_text -> text
    reverse_key = {v:k for k,v in key.items()}
    return c.translate(reverse_key)


key = generate_key()
string = input("give me a text to encrypt \n")
cipher = encrypt(string, key)
input(f'{cipher}\n\n press anything to decrypt\n')
print(decrypt(cipher, key))