import base64
import os
from base64 import b64decode, b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

data = b"a secret message"
aad = b"authenticated but unencrypted data"
SECRET_KEY = b"My_message" # Password Encode Secret Key Before Password Encrypt

# if ("key_256" in os.environ):
#     key = os.environ["key_256"]
# else:
salt = b"sAlT"*8

kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
key = AESGCM.generate_key(bit_length=256)
print(" before environment key", key, flush=True)
os.environ["key_256"] = base64.urlsafe_b64encode(kdf.derive(SECRET_KEY))

# key.decode("utf-8")

# if ("nonce" in os.environ):
#     nonce = os.environ["nonce"]
# else:
nonce = os.urandom(12)
print("nonce", nonce, flush=True)
os.environ["nonce"] = str(nonce, 'utf-8', 'ignore')
# aesgcm = AESGCM(key)
# nonce = os.urandom(12)
# ct = aesgcm.encrypt(nonce, data, aad)
# aesgcm.decrypt(nonce, ct, aad)


def encrypt(data, aad):
    key = os.environ["key_256"].encode('utf-8')
    nonce = os.environ["nonce"].encode('utf-8')
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, aad)

def decrypt(ct, aad): 
    key = os.environ["key_256"].encode()
    nonce = os.environ["nonce"].encode() 
    print("decrypt key ", key, flush=True)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)
