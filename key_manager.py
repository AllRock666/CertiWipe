# key_manager.py
#
# Handles the creation, storage, and loading of persistent RSA keys.

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- Constants ---
PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"

def ensure_keys():
    """
    Generates and saves an RSA keypair if they don't already exist.
    Returns True if keys were newly created, False otherwise.
    """
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        return False

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return True

def load_private_key():
    """Loads the private key from its PEM file."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise FileNotFoundError(f"Private key '{PRIVATE_KEY_FILE}' not found. Please run the app once to generate keys.")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    """Loads the public key from its PEM file."""
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError(f"Public key '{PUBLIC_KEY_FILE}' not found. Please run the app once to generate keys.")
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())