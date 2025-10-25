import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .utils import randbytes, b64e, b64d

PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(in_path: str, out_path: str, password: str):
    salt = randbytes(SALT_LEN)
    key = _derive_key(password, salt, PBKDF2_ITERS)
    aes = AESGCM(key)
    nonce = randbytes(NONCE_LEN)
    with open(in_path, 'rb') as f: pt = f.read()
    ct = aes.encrypt(nonce, pt, None)
    header = {"type":"pass-aesgcm","kdf":"pbkdf2","iter":PBKDF2_ITERS,"salt":b64e(salt),"nonce":b64e(nonce),"alg":"AES-256-GCM","v":1}
    with open(out_path, 'wb') as f:
        f.write(json.dumps(header).encode('utf-8')+b"\n"); f.write(ct)

def decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, 'rb') as f:
        header_line = f.readline(); ct = f.read()
    header = json.loads(header_line.decode('utf-8'))
    assert header.get("type")=="pass-aesgcm"
    salt = b64d(header["salt"]); nonce = b64d(header["nonce"]); iters = int(header["iter"])
    key = _derive_key(password, salt, iters)
    aes = AESGCM(key); pt = aes.decrypt(nonce, ct, None)
    with open(out_path, 'wb') as f: f.write(pt)
