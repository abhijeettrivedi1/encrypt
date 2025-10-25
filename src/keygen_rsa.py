from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(bits: int = 3072, passphrase: Optional[str] = None):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = serialization.BestAvailableEncryption(passphrase.encode('utf-8')) if passphrase else serialization.NoEncryption()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=enc)
    pub_pem = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem
