# AES 256 encryption/decryption using pycryptodome library

from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

salt = "8/bpKSnu4NIXxhWlz4VLiw=="
nonce = "BzZDHOX05R7NsMF9zbFBjw=="
tag = "I2Su7vTmmiNDu07wMOz3IA=="
private_key = b'\x16\x8eQ\xf5\x86\x9d\xb1NV\xf8\x82\xa8\xe5r\x19\xeb\xad\xe9\x9a\x88vV?\x069\xd1\x10k#Sm\x83'

def encrypt(plain_text, password):
    # generate a random salt
    # salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    # private_key = hashlib.scrypt(
    #     password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(password, 'utf-8'))

    print('cipher_text', b64encode(cipher_text).decode('utf-8'),flush=True)
    print('salt', b64encode(salt).decode('utf-8'),flush=True)
    print('nonce', b64encode(cipher_config.nonce).decode('utf-8'),flush=True)
    print('tag', b64encode(tag).decode('utf-8'), flush=True)
    print('private_key', private_key, flush=True)

    return  b64encode(cipher_text).decode('utf-8')


def decrypt(cipher_text):
    
    # create the cipher config
    cipher = AES.new(b64decode(private_key), AES.MODE_GCM, nonce=b64decode(nonce))

    # decrypt the cipher text
    decrypted = cipher.decrypt(b64decode(cipher_text)).decode('utf-8')

    return decrypted

def decrypt_old(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted