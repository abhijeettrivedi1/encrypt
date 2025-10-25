#  FileCrypt — AES/RSA File Encryption & Decryption Tool

A complete cybersecurity project demonstrating **core cryptography concepts**:
- AES-256-GCM authenticated encryption (confidentiality + integrity)
- RSA-OAEP key wrapping for hybrid encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- SHA-256 integrity hashing
- Streamlit web UI for secure file operations

---

##  Overview
FileCrypt provides both **password-based** and **RSA hybrid** encryption for files of any type.  
It showcases how to apply *real-world cryptography* — secure key generation, key management, and integrity verification — using the `cryptography` library.

### Core Cybersecurity Principles:
| Concept | Implementation | Purpose |
|----------|----------------|----------|
| **Confidentiality** | AES-256-GCM | Encrypts file contents securely |
| **Integrity** | GCM tag + SHA-256 | Detects tampering or corruption |
| **Authentication** | RSA-OAEP wrapping | Ensures only intended keypair can decrypt |
| **Key Management** | PBKDF2 + RSA PEMs | Securely derives & stores encryption keys |

---

##  Installation

```bash
# Clone this repository
git clone https://github.com/<your-username>/FileCrypt.git
cd FileCrypt

# (Optional) Create a virtual environment
python -m venv .venv
.\.venv\Scripts\activate        # Windows
# source .venv/bin/activate     # Linux / Mac

# Install dependencies
pip install -r requirements.txt
