# test.py
# Simple sanity tests for your RSA implementation
# -----------------------------------------------------------------------
import importlib.util
import os

from numpy import gcd

_rsa_path = os.path.join(os.path.dirname(__file__), "rsa-3.py")
spec = importlib.util.spec_from_file_location("rsa_module", _rsa_path)
rsa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rsa)

for _name in (
    "gcd",
    "extended_gcd",
    "mod_inverse",
    "modular_exponentiation",
    "random_n_bit_odd_int",
    "is_probable_prime",
    "generate_prime",
    "generate_keypair",
    "set_chunk_modulus",
    "chunk_to_num",
    "num_to_chunk",         
    "rsa_encrypt",       
    "rsa_decrypt",
):

    if not hasattr(rsa, _name):
        raise ImportError(f"{_name} not found in rsa-3.py")
    globals()[_name] = getattr(rsa, _name)


def test_gcd():
    print("Testing gcd...")
    assert gcd(30, 21) == 3
    assert gcd(17, 13) == 1
    assert gcd(0, 5) == 5
    print("gcd ok")


def test_extended_gcd_and_modinv():
    print("Testing extended_gcd and mod_inverse...")
    g, x, y = extended_gcd(30, 21)
    assert g == 3
    assert 30 * x + 21 * y == g

    inv = mod_inverse(7, 40)
    assert (7 * inv) % 40 == 1
    print("extended_gcd and mod_inverse ok")


def test_modexp():
    print("Testing modular_exponentiation...")
    assert modular_exponentiation(2, 10, 1000) == 1024 % 1000
    assert modular_exponentiation(5, 0, 13) == 1
    assert modular_exponentiation(7, 1, 13) == 7 % 13
    print("modular_exponentiation ok")


def test_prime_generation():
    print("Testing generate_prime and is_probable_prime...")
    p = generate_prime(16)
    q = generate_prime(16)

    print("p =", p, "bit length =", p.bit_length())
    print("q =", q, "bit length =", q.bit_length())

    assert is_probable_prime(p)
    assert is_probable_prime(q)
    assert p.bit_length() == 16
    assert q.bit_length() == 16
    print("prime generation ok")


def test_keypair_and_chunk():
    print("Testing generate_keypair and chunk_to_num...")
    # small known primes for sanity check
    p = 61
    q = 53
    pub, priv = generate_keypair(p, q)
    n, e = pub
    n2, d = priv

    assert n == n2
    print("Public key:", pub)
    print("Private key:", priv)

    # set modulus for chunk conversion
    set_chunk_modulus(n)

    # chunk tests
    v1 = chunk_to_num("he")
    v2 = chunk_to_num("ll")
    v3 = chunk_to_num("o ")

    print("Chunk values:", v1, v2, v3)
    assert v1 != v2 != v3
    print("keypair and chunk_to_num ok")

def test_chunk_roundtrip():
    print("Testing chunk_to_num and num_to_chunk roundtrip...")
    p = 61
    q = 53
    pub, _ = generate_keypair(p, q)
    n, _ = pub

    set_chunk_modulus(n)

    chunk = "he"
    num = chunk_to_num(chunk)
    recovered = num_to_chunk(num, len(chunk))

    print("Original:", chunk, "Number:", num, "Recovered:", recovered)
    assert chunk == recovered
    print("chunk roundtrip ok")

def test_rsa_full_pipeline():
    print("Testing RSA full pipeline...")

    # Small primes for sanity check
    p = 61
    q = 53
    pub, priv = generate_keypair(p, q)

    message = "hello world"
    blocksize = 2

    encrypted = rsa_encrypt(message, pub, blocksize)
    decrypted = rsa_decrypt(encrypted, priv, blocksize)

    print("Original:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

    assert decrypted == message
    print("RSA full pipeline ok")



if __name__ == "__main__":
    test_gcd()
    test_extended_gcd_and_modinv()
    test_modexp()
    test_prime_generation()
    test_keypair_and_chunk()
    test_chunk_roundtrip()   
    test_rsa_full_pipeline()
    print("All tests passed")

