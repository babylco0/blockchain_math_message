from util import *
from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from secp256k1 import PrivateKey
from kivy.utils import platform
from kivy.storage.jsonstore import JsonStore
import json
import binascii


demo_user_names = ('Alice', 'Bob', 'Charlie', 'Mark', 'King', 'Wu', 'Paige')
default_key_size = 1024

if platform == 'linux':
    default_path = './demo_users.json'
elif platform == 'android':
    default_path = '/sdcard/demo_users.json'


def create_demo_users():
    """create demo users"""
    try:
        store = JsonStore(default_path)
        for name in demo_user_names:
            # RSA keys
            key = RSA.generate(default_key_size)
            rsa_prikey = key.exportKey('PEM')
            rsa_pubkey = key.publickey().exportKey('PEM')
            readable_rsa_prikey = rsa_prikey.decode('utf-8')
            readable_rsa_pubkey = rsa_pubkey.decode('utf-8')
            # ECC keys
            h = hash256(rsa_prikey)
            ecc_prikey = PrivateKey(bytes(bytearray.fromhex(h)))
            ecc_pubkey = ecc_prikey.pubkey
            readable_ecc_prikey = ecc_prikey.serialize()
            readable_ecc_pubkey = binascii.hexlify(ecc_pubkey.serialize()).decode('utf-8')
            # AES key & iv
            h = hash256(binascii.unhexlify(ecc_prikey.serialize()))
            aes_key = h[0:32]
            aes_iv = h[32:]
            # address
            address = pubkey2address(readable_ecc_pubkey)
            # save keys
            store.put(name,
                      address=address,
                      rsa_prikey=readable_rsa_prikey,
                      rsa_pubkey=readable_rsa_pubkey,
                      ecc_prikey=readable_ecc_prikey,
                      ecc_pubkey=readable_ecc_pubkey,
                      aes_key=aes_key,
                      aes_iv=aes_iv)
    except Exception as e:
        print(str(e))
        

create_demo_users()
