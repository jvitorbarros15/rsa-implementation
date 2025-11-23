# -----------------------------------------------------------------------
# FA25 CMPSC 360 Extra Credit Assignment 2
# RSA Implementation
# 
# Name: Joao Vitor Barros da Silva
# ID: 
# 
# 
# You cannot use any external/built-in libraries to help compute gcd
# or modular inverse. You cannot use RSA, cryptography, or similar libs
# for this assignment. You must write your own implementation for generating
# large primes. You must wirte your own implementation for modular exponentiation and
# modular inverse. Please refer to the documentation for more details.
# 
# You are allowed to use randint from the built-in random library
# -----------------------------------------------------------------------

from typing import Tuple
from random import randint
import math

# Type defs
Key = Tuple[int, int]

# Helper functions

def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return abs (a)

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e: int, phi: int) -> int:
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % phi
    
def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def random_n_bit_odd_int(n: int) -> int:

    x = randint(0, (1 << n ) - 1)
    x |= (1 << (n - 1))  # Ensure n-bit
    x |= 1               # Ensure odd
    return x

def is_probable_prime(n: int, rounds: int = 20) -> bool:
    # Reject small values that are not prime
    if n < 2:
        return False
    
    # Quick elimination using a list of known small primes
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False
    
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Each round uses a random base a to test whether n behaves like a prime
    for _ in range(rounds):
        a = randint(2, n - 2)
        x = modular_exponentiation(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False
    
    return True


def generate_prime(n: int) -> int:
    '''
    Description: Generate an n-bit prime number
    Args: n (No. of bits)
    Returns: prime number
    
    NOTE: This needs to be sufficiently fast or you may not get
    any credit even if you correctly return a prime number.
    '''
    while True:
            candidate = random_n_bit_odd_int(n)
            if is_probable_prime(candidate):
                return candidate


def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
    '''
    Description: Generates the public and private key pair
    if p and q are distinct primes. Otherwise, raise a value error
    
    Args: p, q (input integers)

    Returns: Keypair in the form of (Pub Key, Private Key)
    PubKey = (n,e) and Private Key = (n,d)
    '''
    raise NotImplementedError
    


def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> int:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    raise NotImplementedError


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    raise NotImplementedError


def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    raise NotImplementedError


def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    raise NotImplementedError