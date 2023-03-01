import random
from hashlib import sha256
import p_and_g
from p_and_g import PrimesAndCreators
from globals import *
from decimal import Decimal
import hashlib
import binascii

SECURITY_LEVEL = 1
def hash_msg(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed

def hash512(x: bytes) -> bytes:
    hx = hashlib.sha256(x).digest()
    idx = len(hx) // 2
    return hashlib.sha256(hx[:idx]).digest() + hashlib.sha256(hx[idx:]).digest()
def hash_to_int(x: bytes) -> int:
    hx = hash512(x)
    for _ in range(SECURITY_LEVEL - 1):
        hx += hash512(hx)
    return int.from_bytes(hx, 'little')

def generate_keys():
    PAC = p_and_g.PrimesAndCreators()
    p = PAC.get_random_numbermod4() #not forget to do new func that reseive to integer and found prime number=3mod 4
    q = PAC.get_random_numbermod4()
   
    return (p, q)


def create_signiture(x ,Message):
    """
    :param p: part of private key
    :param q: part of private key
    :param digest: message digest to sign
    :return: rabin signature (S: int, padding: int)
    """
    p=x[0]
    q=x[1]
    n = p * q
    i = 0
    while True:
        h = hash_to_int(Message + b'\x00' * i) % n
        if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
            break
        i += 1
    lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
    rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
    s = (lp + rp) % n
    return s, i

def verify_rabin(keys, message: bytes, x) -> bool:
    """
    :param n: rabin public key
    :param digest: digest of signed message
    :param s: S of signature
    :param padding: the number of padding bytes
    """
    n=keys[0]*keys[1]
    digest=message
    padding=x[1]
    s=x[0]
    msg1=hash_to_int(digest + b'\x00' * padding) % n
    msg2=(s * s) % n
    
    return msg1==msg2


def hash_func(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed
def H( m, u):
	c = m + u
	return c
	
def verify(HashedMessage, decriptedSignature):
   # ourHashed = hashFunction(message)
    if HashedMessage == decriptedSignature:
        # print("Verification successful: ", )
        # print(HashedMessage, " = ", decriptedSignature)
        return True
    else:

        # print("Verification failed")
        # print(HashedMessage, " != ", decriptedSignature)
        return False

