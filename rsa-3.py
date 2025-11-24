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
    if p == q:
        raise ValueError("p and q must be distinct primes")
    
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p and q must be prime numbers")
    
    n = p * q

    phi = (p - 1) * (q - 1)

    e = 65537  

    if gcd(e, phi) != 1:
        while True :
            e = randint(2, phi - 1)
            if gcd(e, phi) == 1:
                break
    
    d = mod_inverse(e, phi)

    pub_key = (n, e)
    priv_key = (n, d)
    return pub_key, priv_key


def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> int:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    n, e = pub_key

    # Set modulus for chunk conversion
    set_chunk_modulus(n)

    # Pad the message so its length is a multiple of blocksize
    if len(m) % blocksize != 0:
        pad_len = blocksize - (len(m) % blocksize)
        m = m + (" " * pad_len)

    # Split into chunks
    chunks = [m[i:i+blocksize] for i in range(0, len(m), blocksize)]

    encrypted_chunks = []

    for chunk in chunks:
        v = chunk_to_num(chunk)
        c = modular_exponentiation(v, e, n)
        encrypted_chunks.append(c)

    encrypted_chunks.append(pad_len)

    return encrypted_chunks


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    n, d = priv_key

    # Set modulus for chunk conversion
    set_chunk_modulus(n)

    pad_len = c[-1]
    c = c[:-1]

    recovered_text = ""

    for cipher in c:
        m_int = modular_exponentiation(cipher, d, n)
        chunk = num_to_chunk(m_int, blocksize)
        recovered_text += chunk

    # Remove padding spaces added during encryption
    if pad_len > 0:
        recovered_text = recovered_text[:-pad_len]

    return recovered_text.rstrip()

# Global variable to hold modulus for chunk conversion
CHUNK_MODULUS = None

def set_chunk_modulus(n: int) -> None:
    global CHUNK_MODULUS
    CHUNK_MODULUS = n

def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    if CHUNK_MODULUS is None:
        raise ValueError("Chunk modulus not set")

    n = CHUNK_MODULUS
    result = 0

    # Interpret the chunk as a base n number
    for ch in chunk:
        v = ord(ch)          # Get ASCII value
        result = result * n + v

    return result


def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    if CHUNK_MODULUS is None:
        raise ValueError("Chunk modulus not set")

    n = CHUNK_MODULUS
    chars = []

    # Recover characters in reverse order using base n expansion
    for _ in range(chunksize):
        v = num % n
        num //= n
        chars.append(chr(v))
        
    chars.reverse()
    return ''.join(chars)