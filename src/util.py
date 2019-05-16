from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
import binascii
import base64


def hash256(data):
    """double sha256"""
    h = SHA256.new()
    h.update(data)
    h.update(h.digest())
    rst = h.hexdigest()
    return rst


def hash160(data):
    """sha256 + ripemd160"""
    h1 = SHA256.new()
    h1.update(data)
    h2 = RIPEMD.new()
    h2.update(h1.digest())
    rst = h2.hexdigest()
    return rst


def pubkey2address(pubkey):
    """ECC public key to address"""
    extended_pubkey = '00' + pubkey
    h = hash160(binascii.unhexlify(extended_pubkey))
    checksum = h[32:40]
    hex_pubkcy = extended_pubkey + checksum
    address = base64.b64encode(binascii.unhexlify(hex_pubkcy))
    return address.decode('utf-8')


__all__ = ['hash256', 'hash160', 'pubkey2address']
