import hashlib
import json
import os
import streamlit as st
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class DataBlock:
    def __init__(self, index, timestamp, previous_hash, data, signature=""):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.data = data
        self.hash = self.calculate_hash()
        self.signature = signature

    def calculate_hash(self):
        hash_input = f"{self.index}{self.timestamp}{self.previous_hash}{self.data}".encode()
        return hashlib.sha256(hash_input).hexdigest()

class Blockchain:
    def __init__(self):
        self.file_name = "blockchain.json"
        self.chain = self.load_blocks_from_file()
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = DataBlock(0, str(datetime.now()), "0", "Genesis Block")
        self.chain.append(genesis_block)
        self.save_blocks_to_file()

    def add_block(self, data, signature):
        last_block = self.chain[-1]
        new_block = DataBlock(len(self.chain), str(datetime.now()), last_block.hash, data, signature)
        self.chain.append(new_block)
        self.save_blocks_to_file()

    def save_blocks_to_file(self):
        with open(self.file_name, "w") as file:
            json.dump([block.__dict__ for block in self.chain], file, indent=4)

    def load_blocks_from_file(self):
        if os.path.exists(self.file_name):
            with open(self.file_name, "r") as file:
                data = json.load(file)
            return [DataBlock(block["index"], block["timestamp"], block["previous_hash"], block["data"], block["signature"]) for block in data]
        return []


    def validate_blockchain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.calculate_hash() != current_block.hash:
                return False
        return True

class SecureTextEditor:
    def __init__(self):
        self.blockchain = Blockchain()
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)

    def load_or_generate_key(self):
        key_file = 'encryption.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as file:
                file.write(key)
            return key

    def encrypt_text(self, text):
        return self.cipher.encrypt(text.encode()).decode()

    def decrypt_text(self, encrypted_text):
        return self.cipher.decrypt(encrypted_text.encode()).decode()

    def generate_signature(self, message):
        private_key_file = 'private_key.pem'
        if os.path.exists(private_key_file):
            with open(private_key_file, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            with open(private_key_file, "wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def add_secret(self, secret):
        encrypted_secret = self.encrypt_text(secret)
        signature = self.generate_signature(encrypted_secret)
        self.blockchain.add_block(encrypted_secret, signature)

    def retrieve_secrets(self):
        return [self.decrypt_text(block.data) for block in self.blockchain.chain[1:]]

    def display_chain(self):
        return self.blockchain.chain

if "editor" not in st.session_state:
    st.session_state.editor = SecureTextEditor()

if "auth_pass" not in st.session_state:
    st.session_state.auth_pass = False

editor = st.session_state.editor

st.title("Secure Blockchain Text Editor")

menu = ["Add Secret", "View Secrets", "Validate Blockchain", "Display Blockchain"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Add Secret":
    secret = st.text_input("Enter the secret text:")
    if st.button("Add Secret"):
        editor.add_secret(secret)
        st.success("Secret added securely.")

elif choice == "View Secrets":
    if not st.session_state.auth_pass:
        password = st.text_input("Enter the password to view secrets:", type="password")
        if st.button("Submit"):
            if password == "AndrieseiTudor":
                st.session_state.auth_pass = True
                st.success("Access granted.")
            else:
                st.error("Incorrect password.")
    if st.session_state.auth_pass:
        secrets = editor.retrieve_secrets()
        st.subheader("Decrypted Secrets:")
        for idx, secret in enumerate(secrets, start=1):
            st.write(f"{idx}. {secret}")

elif choice == "Validate Blockchain":
    is_valid = editor.blockchain.validate_blockchain()
    if is_valid:
        st.success("Blockchain is valid and has not been tampered with.")
    else:
        st.error("Blockchain integrity check failed! Potential tampering detected.")

elif choice == "Display Blockchain":
    chain = editor.display_chain()
    st.subheader("Blockchain:")
    for block in chain:
        st.json({"Index": block.index, "Timestamp": block.timestamp, "Previous Hash": block.previous_hash, "Hash": block.hash, "Data": block.data, "Signature": block.signature})
