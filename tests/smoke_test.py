import os, tempfile
from src import aes_password
from src.keygen_rsa import generate_keypair
from src import hybrid_rsa

def test_roundtrip_password():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "in.txt"); enc = os.path.join(td, "out.enc"); dec = os.path.join(td, "out.txt")
        open(src,"wb").write(b"hello crypt world")
        aes_password.encrypt_file(src, enc, "passw0rd!"); aes_password.decrypt_file(enc, dec, "passw0rd!")
        assert open(dec,"rb").read() == b"hello crypt world"

def test_roundtrip_hybrid():
    with tempfile.TemporaryDirectory() as td:
        priv, pub = generate_keypair(2048, None)
        src = os.path.join(td, "in.txt"); enc = os.path.join(td, "out.hy.enc"); dec = os.path.join(td, "out.txt")
        open(src,"wb").write(b"hybrid test")
        hybrid_rsa.encrypt_file(src, enc, pub); hybrid_rsa.decrypt_file(enc, dec, priv, password=None)
        assert open(dec,"rb").read() == b"hybrid test"
