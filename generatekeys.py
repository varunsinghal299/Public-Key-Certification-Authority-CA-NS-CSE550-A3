import random
import socket
max_PrimLength = 1000000000000

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


'''
checks if a number is a prime
'''
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def generateRandomPrim():
    while (1):
        ranPrime = random.randint(0, max_PrimLength)
        if is_prime(ranPrime):
            return ranPrime


def generate_keyPairs():
    p = generateRandomPrim()
    q = generateRandomPrim()

    n = p * q
    #print("n ", n)
    '''phi(n) = phi(p)*phi(q)'''
    phi = (p - 1) * (q - 1)
    #print("phi ", phi)

    '''choose e coprime to n and 1 > e > phi'''
    e = random.randint(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randint(1, phi)
        g = gcd(e, phi)

    #print("e=", e, " ", "phi=", phi)
    '''d[1] = modular inverse of e and phi'''
    d = egcd(e, phi)[1]

    '''make sure d is positive'''
    d = d % phi
    if (d < 0):
        d += phi

    return ((e, n), (d, n))


def decrypt(ctext, private_key):
    try:
        key, n = private_key
        text = [chr(pow(char, key, n)) for char in ctext]
        return "".join(text)
    except TypeError as e:
        print(e)


def encrypt(text, public_key):
    key, n = public_key
    ctext = [pow(ord(char), key, n) for char in text]
    return ctext

# generate all clientA , clientB and CA private ad public keys.
public_keyA, private_keyA = generate_keyPairs()
public_keyB, private_keyB = generate_keyPairs()
public_keyCA, private_keyCA = generate_keyPairs()


print("public_keyA = ",public_keyA)
print("public_keyB = ",public_keyB)
print("public_keyCA = ",public_keyCA)

print("private_keyA = ",private_keyA)
print("private_keyB = ",private_keyB)
print("private_keyCA = ",private_keyCA)


public_key, private_key = generate_keyPairs()
print("Public: ", public_key)
print("Private: ", private_key)

ctext = encrypt("Hello World", public_key)
print("encrypted  =", ctext)

print(ctext)
print(type(ctext))
print(type(ctext[0]))
print(len(ctext))
plaintext = decrypt(ctext, private_key)
print("decrypted =", plaintext)


