import random
import math

def gcd(a, b):
    """ This iterative method avoids the stack overflow risk of a recursive algorithm"""
    while a != 0:
        a, b = b % a, a
    return b


def is_prime(a):
    """Tests the primality of the integer a."""
    if a == 2:
        return True
    if a < 2 or a % 2 == 0:
        return False
    for n in range(3, int(math.sqrt(a)) + 1, 2):
        if a % n == 0:
            return False
    return True


def carmichael_for_rsa(p, q):
    """ Charmichael function returns the totient of n = p * q 
    Warning in this implementation, p and q must be prime"""
    return lcm(p-1, q-1)


def lcm(a, b):
    """ Computes the leas common multiple of a and b"""
    return abs(a*b)//gcd(a, b)


def gcd_extended(a, b, x=1, y=1):
    """ Computes the greatest common divider and the """
    if a == 0:
        x = 0
        y = 1
        return b, x, y
    gcd, x1, y1 = gcd_extended(b % a, a, x, y)
    x = y1 - (b//a) * x1
    y = x1
    return gcd, x, y


def modulo_multiplicative_inverse(a, m):
    # Warning assert that A and M are co-prime
    """ This returns the multiplicative inverse of the number a modulo m """
    gcd, x, y = gcd_extended(a, m)
    if x < 0:
        x += m
    return x

def generate_keys(p, q):
    """ Computes a public and private key for the RSA cryptography using the primes p and q"""
    assert p != q and is_prime(p) and is_prime(q)
    n = p*q
    phi = carmichael_for_rsa(p, q)
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = modulo_multiplicative_inverse(e, phi)
    return (e, n), (d, n)


def encrypt(public_key, message):
    """ Returns the RSA encryption of the message with the given public key"""
    key, n = public_key
    cipher = [pow(ord(char), key, n) for char in message]
    return cipher


def decrypt(private_key, cipher):
    """ Returns the RSA decryption of the message with the given private key"""
    key, n = private_key
    message = [chr(pow(code, key, n)) for code in cipher]
    return ''.join(message)

# -------Example of communication--------------
print("---------Example of communication with RSA-----------")
# Parameters
p, q = 1299721, 1302929
message = "Hi Alice, it's Bob !"
# Computed by Alice
public_key, private_key = generate_keys(p, q)
# Computed by Bob
cipher = encrypt(public_key, message)
# Computed by Alice
decrypted_cipher = decrypt(private_key, cipher)

print(decrypted_cipher)

# --------Attack on RSA-------------

# The goal of this attack is to find the factors p and q from n, deduce d to then decrypt the message
print("----------Encryption attack-------------")


def get_two_prime_factors(n):
    assert not is_prime(n)
    if n % 2 == 0:
        return 2, n/2
    for a in range(3, int(math.sqrt(n))+1, 2):
        if n % a == 0:
            return a, int(n/a)


def break_rsa(public_key, cipher):
    e, n = public_key
    p, q = get_two_prime_factors(n)
    phi = carmichael_for_rsa(p, q)
    d = modulo_multiplicative_inverse(e, phi)
    private_key = (d, n)
    return decrypt(private_key, cipher)

# Computed by Alice
public_key, private_key = generate_keys(p, q)
# Computed by Bob
cipher = encrypt(public_key, message)
# Computed by Eve (an eavesdropper)
attack_message = break_rsa(public_key, cipher)
if attack_message == message:
    print("The code has ben successfully broken")
    print(attack_message)



