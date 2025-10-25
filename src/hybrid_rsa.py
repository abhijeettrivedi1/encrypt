import json
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from .utils import randbytes, b64e, b64d

NONCE_LEN = 12
KEY_LEN = 32

def encrypt_file(in_path: str, out_path: str, public_key_pem: bytes):
    pub = serialization.load_pem_public_key(public_key_pem)
    aes_key = randbytes(KEY_LEN); aes = AESGCM(aes_key); nonce = randbytes(NONCE_LEN)
    with open(in_path, 'rb') as f: pt = f.read()
    ct = aes.encrypt(nonce, pt, None)
    ekey = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    header = {"type":"hybrid-rsa","wrap":"RSA-OAEP-SHA256","nonce":b64e(nonce),"ekey":b64e(ekey),"alg":"AES-256-GCM","v":1}
    with open(out_path, 'wb') as f: f.write(json.dumps(header).encode('utf-8')+b"\n"); f.write(ct)

def decrypt_file(in_path: str, out_path: str, private_key_pem: bytes, password: Optional[bytes]=None):
    priv = serialization.load_pem_private_key(private_key_pem, password=password)
    with open(in_path, 'rb') as f: header_line = f.readline(); ct = f.read()
    header = json.loads(header_line.decode('utf-8'))
    assert header.get("type")=="hybrid-rsa"
    nonce = b64d(header["nonce"]); ekey = b64d(header["ekey"])
    aes_key = priv.decrypt(ekey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    aes = AESGCM(aes_key); pt = aes.decrypt(nonce, ct, None)
    with open(out_path, 'wb') as f: f.write(pt)
