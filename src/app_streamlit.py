import io
import json
import base64
import streamlit as st
from typing import Optional

from src import aes_password, hybrid_rsa
from src.keygen_rsa import generate_keypair

st.set_page_config(page_title="FileCrypt — AES/RSA", page_icon="🛡️", layout="centered")
st.title("🛡️ FileCrypt — AES/RSA File Encryption & Decryption")

tab_keygen, tab_pass, tab_hybrid, tab_hash = st.tabs(["🔑 RSA Keygen", "🔒 Password AES-GCM", "🧬 Hybrid RSA (AES+RSA)", "🔍 SHA-256 Hash"])

# Helpers
def download_bytes(label: str, data: bytes, file_name: str, mime: str = "application/octet-stream"):
    st.download_button(label, data=data, file_name=file_name, mime=mime, use_container_width=True)

with tab_keygen:
    st.subheader("Generate RSA Keypair")
    bits = st.selectbox("Key size (bits)", [2048, 3072, 4096], index=1)
    passphrase = st.text_input("Private key passphrase (optional)", type="password")
    if st.button("Generate keypair", type="primary"):
        priv_pem, pub_pem = generate_keypair(bits=bits, passphrase=passphrase or None)
        st.success("Keypair generated.")
        download_bytes("⬇️ Download private.pem", priv_pem, "private.pem", "application/x-pem-file")
        download_bytes("⬇️ Download public.pem", pub_pem, "public.pem", "application/x-pem-file")
        with st.expander("Preview public key (first lines)"):
            st.code(pub_pem.decode("utf-8").splitlines()[0] + "\n...\n" + pub_pem.decode("utf-8").splitlines()[-1])

with tab_pass:
    st.subheader("Password-based AES-256-GCM")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
    password = st.text_input("Password", type="password")
    up = st.file_uploader("Select file", type=None)
    if up and password and st.button("Run", type="primary"):
        buf_in = up.read()
        if mode == "Encrypt":
            # write to tmp, use existing function, then read result back
            import tempfile, os
            with tempfile.TemporaryDirectory() as td:
                in_path = os.path.join(td, up.name)
                out_path = os.path.join(td, up.name + ".enc")
                open(in_path, "wb").write(buf_in)
                aes_password.encrypt_file(in_path, out_path, password)
                out_bytes = open(out_path, "rb").read()
            st.success("Encrypted with AES-256-GCM (PBKDF2).")
            download_bytes("⬇️ Download encrypted (.enc)", out_bytes, up.name + ".enc")
        else:
            import tempfile, os
            with tempfile.TemporaryDirectory() as td:
                in_path = os.path.join(td, up.name)
                out_name = up.name.rsplit(".enc", 1)[0] or (up.name + ".dec")
                out_path = os.path.join(td, out_name)
                open(in_path, "wb").write(buf_in)
                try:
                    aes_password.decrypt_file(in_path, out_path, password)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
                else:
                    out_bytes = open(out_path, "rb").read()
                    st.success("Decrypted successfully.")
                    download_bytes("⬇️ Download decrypted", out_bytes, out_name)

with tab_hybrid:
    st.subheader("Hybrid RSA (AES session key + RSA-OAEP-SHA256)")
    mode = st.radio("Mode", ["Encrypt with PUBLIC key", "Decrypt with PRIVATE key"], horizontal=True)
    up = st.file_uploader("Select file", key="hyfile")
    if mode.startswith("Encrypt"):
        pub_pem_file = st.file_uploader("Public key (PEM)", type=["pem"], key="pubpem")
        if up and pub_pem_file and st.button("Encrypt", type="primary"):
            import tempfile, os
            with tempfile.TemporaryDirectory() as td:
                in_path = os.path.join(td, up.name)
                out_path = os.path.join(td, up.name + ".hy.enc")
                open(in_path, "wb").write(up.read())
                hybrid_rsa.encrypt_file(in_path, out_path, pub_pem_file.read())
                out_bytes = open(out_path, "rb").read()
            st.success("Hybrid encryption complete (AES-256-GCM + RSA-OAEP).")
            download_bytes("⬇️ Download encrypted (.hy.enc)", out_bytes, up.name + ".hy.enc")
    else:
        priv_pem_file = st.file_uploader("Private key (PEM)", type=["pem"], key="privpem")
        key_pass = st.text_input("Private key passphrase (if protected)", type="password")
        if up and priv_pem_file and st.button("Decrypt", type="primary"):
            import tempfile, os
            with tempfile.TemporaryDirectory() as td:
                in_path = os.path.join(td, up.name)
                out_name = up.name.rsplit(".hy.enc", 1)[0] or (up.name + ".dec")
                out_path = os.path.join(td, out_name)
                open(in_path, "wb").write(up.read())
                try:
                    hybrid_rsa.decrypt_file(in_path, out_path, priv_pem_file.read(), password=(key_pass.encode("utf-8") if key_pass else None))
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
                else:
                    out_bytes = open(out_path, "rb").read()
                    st.success("Decrypted successfully.")
                    download_bytes("⬇️ Download decrypted", out_bytes, out_name)

with tab_hash:
    st.subheader("SHA-256 File Hash")
    up = st.file_uploader("Select file to hash", key="hashfile")
    if up and st.button("Compute SHA-256", type="primary"):
        import hashlib
        h = hashlib.sha256(up.read()).hexdigest()
        st.code(h)
        st.caption("Use this to verify integrity before/after encryption.")
