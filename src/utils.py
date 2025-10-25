import base64, os, hashlib
def b64e(b: bytes) -> str: return base64.b64encode(b).decode('ascii')
def b64d(s: str) -> bytes: return base64.b64decode(s.encode('ascii'))
def randbytes(n: int) -> bytes: return os.urandom(n)
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()
