# utils/encryption.py

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger("encryption_utils")


def generate_key_from_passphrase(passphrase: str, salt: bytes = None) -> bytes:
    """
    Generate a Fernet key from a passphrase using PBKDF2.

    Args:
        passphrase: The passphrase to use
        salt: Optional salt bytes (will generate if not provided)

    Returns:
        Fernet key bytes
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt


def encrypt_string(plaintext: str, passphrase: str, salt: bytes = None) -> tuple:
    """
    Encrypt a string using Fernet symmetric encryption with a passphrase.

    Args:
        plaintext: The string to encrypt
        passphrase: The passphrase to use for encryption
        salt: Optional salt bytes (will generate if not provided)

    Returns:
        Tuple of (encrypted_text, salt) where encrypted_text is base64-encoded
    """
    key, salt = generate_key_from_passphrase(passphrase, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(plaintext.encode())
    return base64.b64encode(encrypted_data).decode(), base64.b64encode(salt).decode()


def decrypt_string(encrypted_text: str, passphrase: str, salt_b64: str) -> str:
    """
    Decrypt a string that was encrypted with Fernet symmetric encryption.

    Args:
        encrypted_text: The base64-encoded encrypted string
        passphrase: The passphrase used for encryption
        salt_b64: The base64-encoded salt used for key derivation

    Returns:
        The decrypted plaintext string
    """
    try:
        salt = base64.b64decode(salt_b64)
        key, _ = generate_key_from_passphrase(passphrase, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(base64.b64decode(encrypted_text))
        return decrypted_data.decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise ValueError("Failed to decrypt: Invalid passphrase or corrupted data")
