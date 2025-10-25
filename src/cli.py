import argparse, getpass, os
from . import aes_password, hybrid_rsa
from .keygen_rsa import generate_keypair
from .utils import sha256_file

def _read(path): 
    with open(path, 'rb') as f: return f.read()

def main():
    ap = argparse.ArgumentParser(description="FileCrypt — AES/RSA file crypto tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("keygen-rsa")
    sp.add_argument("--out", type=str, default="keys")
    sp.add_argument("--bits", type=int, default=3072)
    sp.add_argument("--protect", type=str, default=None)

    sp = sub.add_parser("encrypt-pass")
    sp.add_argument("--in", dest="inp", required=True)
    sp.add_argument("--out", dest="out", required=True)
    sp.add_argument("--password", type=str, default=None)

    sp = sub.add_parser("decrypt-pass")
    sp.add_argument("--in", dest="inp", required=True)
    sp.add_argument("--out", dest="out", required=True)
    sp.add_argument("--password", type=str, default=None)

    sp = sub.add_parser("encrypt-hybrid")
    sp.add_argument("--in", dest="inp", required=True)
    sp.add_argument("--out", dest="out", required=True)
    sp.add_argument("--pub", dest="pub", required=True)

    sp = sub.add_parser("decrypt-hybrid")
    sp.add_argument("--in", dest="inp", required=True)
    sp.add_argument("--out", dest="out", required=True)
    sp.add_argument("--priv", dest="priv", required=True)
    sp.add_argument("--key-pass", dest="kpass", default=None)

    sp = sub.add_parser("hash")
    sp.add_argument("--in", dest="inp", required=True)

    args = ap.parse_args()

    if args.cmd=="keygen-rsa":
        os.makedirs(args.out, exist_ok=True)
        priv_pem, pub_pem = generate_keypair(bits=args.bits, passphrase=args.protect)
        open(os.path.join(args.out,"private.pem"),"wb").write(priv_pem)
        open(os.path.join(args.out,"public.pem"),"wb").write(pub_pem)
        print("Wrote", os.path.join(args.out,"private.pem")); print("Wrote", os.path.join(args.out,"public.pem")); return

    if args.cmd=="encrypt-pass":
        pwd = args.password or getpass.getpass("Password: ")
        aes_password.encrypt_file(args.inp, args.out, pwd); print("Encrypted ->", args.out); return

    if args.cmd=="decrypt-pass":
        pwd = args.password or getpass.getpass("Password: ")
        aes_password.decrypt_file(args.inp, args.out, pwd); print("Decrypted ->", args.out); return

    if args.cmd=="encrypt-hybrid":
        pub_pem = _read(args.pub); hybrid_rsa.encrypt_file(args.inp, args.out, pub_pem); print("Encrypted (hybrid) ->", args.out); return

    if args.cmd=="decrypt-hybrid":
        priv_pem = _read(args.priv); kpass = args.kpass.encode('utf-8') if args.kpass else None
        hybrid_rsa.decrypt_file(args.inp, args.out, priv_pem, password=kpass); print("Decrypted (hybrid) ->", args.out); return

    if args.cmd=="hash":
        print("SHA-256:", sha256_file(args.inp)); return

if __name__ == "__main__":
    main()
