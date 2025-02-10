# 🛡️ Secure Blockchain Text Editor

A **secure text storage application** that encrypts secrets and stores them in a blockchain-based ledger, ensuring integrity and security.

## 📌 Features
- **Blockchain-based storage**: Ensures data integrity and tamper-proof security.
- **AES Encryption**: Uses **Fernet** encryption to securely store secrets.
- **Digital Signature**: Uses **RSA** signing to authenticate blocks.
- **Blockchain Validation**: Checks for tampering and integrity.
- **Streamlit UI**: Easy-to-use graphical interface.

---

## 🚀 Installation

### **1️⃣ Clone the repository**
```bash
git clone https://github.com/your-username/secure-blockchain-text-editor.git
cd secure-blockchain-text-editor


2️⃣ Install dependencies
Ensure you have Python installed (≥ 3.8), then run:

bash

pip install -r requirements.txt
3️⃣ Run the application
bash

streamlit run app.py

🛠️ Usage
🔐 Add Secret
Enter a secret text.
Click "Add Secret" to securely store it.


🔓 View Secrets
Enter the correct password (AndrieseiTudor).
Retrieve all stored secrets.


✅ Validate Blockchain
Ensures all blocks are intact and unchanged.


📜 Display Blockchain
View all stored blocks with encrypted data.


🛡️ Security Features
Encryption: Uses cryptography.Fernet for AES-based encryption.
Blockchain Integrity: Uses SHA-256 for block hashes.
Digital Signatures: Uses RSA-based private key signatures.


📝 Future Improvements
Allow dynamic passwords instead of a hardcoded one.
Implement multi-user authentication.
Add better error handling.
