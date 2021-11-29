import random
import socket
max_PrimLength = 1000000000000

###############################

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

class Certificate:
    def __init__(self, id, PUC, T, DUR, info):
        self.id = id
        self.PUC = PUC
        self.T = T
        self.DUR = DUR
        self.info = info


class CertificationAuthority:
    # default constructor
    def __init__(self, private_keyCA, public_keyCA, public_keyA, public_keyB):
        self.PUCA = public_keyCA
        self.PRCA = private_keyCA
        self.PUA = public_keyA
        self.PUB = public_keyB

    def get_PUCA(self):
        return self.PUCA
    def get_PRCA(self):
        return self.PRCA
    def get_PUA(self):
        return self.PUA
    def get_PUB(self):
        return self.PUB


class ClientA:
    def __init__(self, private_keyA, public_keyA, public_keyCA):
        self.id = 1
        self.PUA = private_keyA
        self.PRA = public_keyA
        self.PUCA = public_keyCA

    def get_PUA(self):
        return (self.PUA)

    def get_PRA(self):
        return (self.PRA)

class ClientB:
    def __init__(self, private_keyB, public_keyB, public_keyCA):
        self.id = 2
        self.PUB = public_keyB
        self.PRB = private_keyB
        self.PUCA = public_keyCA

    def get_PUB(self):
        return (self.PUB)

    def get_PRB(self):
        return (self.PRB)


# generate all clientA , clientB and CA private ad public keys.
# public_keyA, private_keyA = generate_keyPairs()
# public_keyB, private_keyB = generate_keyPairs()
# public_keyCA, private_keyCA = generate_keyPairs()
public_keyA = (172957699960078939422503, 234374918935161346996429)
public_keyB = (739391734375150085299, 10527062671309662558337)
public_keyCA = (187552164648382559142261, 332114470423576738955527)
private_keyA = (234134174470944638240687, 234374918935161346996429)
private_keyB = (8216711647716209678107, 10527062671309662558337)
private_keyCA = (217529080004088592466701, 332114470423576738955527)

A = ClientA(private_keyA, public_keyA, public_keyCA)
B = ClientB(private_keyB, public_keyB, public_keyCA)
CA = CertificationAuthority(private_keyCA, public_keyCA, public_keyA, public_keyB)


###############################

s = socket.socket()
print("Socket Created between client A and client B")

s.bind(("localhost", 9996))
s.listen(3)

while True:

    c, address = s.accept()
    print("Connected with client B", address)

    name = c.recv(1024).decode()
    name = name.split('~')
    ciphertext = []
    for i in range(0, len(name)):
        ciphertext.append(int(name[i]))
    text = decrypt(ciphertext, private_keyB)
    print("Received ", text)
    c.send(bytes('Ack1', 'utf-8'))

    name = c.recv(1024).decode()
    name = name.split('~')
    ciphertext = []
    for i in range(0, len(name)):
        ciphertext.append(int(name[i]))
    text = decrypt(ciphertext, private_keyB)
    print("Received ", text)
    c.send(bytes('Ack1', 'utf-8'))

    name = c.recv(1024).decode()
    name = name.split('~')
    ciphertext = []
    for i in range(0, len(name)):
        ciphertext.append(int(name[i]))
    text = decrypt(ciphertext, private_keyB)
    print("Received ", text)
    c.send(bytes('Ack1', 'utf-8'))

    c.close()
