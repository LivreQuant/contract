# services/crypto_service.py
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from typing import Tuple, Union, Optional, Any


def generate_key_pair(
    save_dir: Optional[Union[str, Path]] = None,
    passphrase: Optional[str] = None,
    encrypt_private: bool = True,
) -> Tuple[bytes, bytes]:
    """
    Generate an RSA key pair for signing and verification.

    Args:
        save_dir: Optional directory to save keys to files
        passphrase: Optional passphrase to encrypt the private key
        encrypt_private: Whether to encrypt the private key with passphrase

    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Choose encryption algorithm based on passphrase availability
    encryption_algorithm = serialization.NoEncryption()
    if passphrase and encrypt_private:
        encryption_algorithm = serialization.BestAvailableEncryption(
            passphrase.encode()
        )

    # Serialize the private key with optional encryption
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    # Serialize the public key (always unencrypted)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save to files if directory provided
    if save_dir:
        save_dir = Path(save_dir)

        # Use separate directories for private and public keys
        public_dir = save_dir
        private_dir = save_dir / "private"

        # Ensure directories exist with appropriate permissions
        public_dir.mkdir(exist_ok=True, parents=True)
        private_dir.mkdir(exist_ok=True, parents=True)

        # Set restrictive permissions on private key directory (Unix-like systems)
        try:
            import os

            os.chmod(private_dir, 0o700)  # Only owner can read/write/execute
        except Exception as e:
            print(f"Warning: Could not set permissions on private key directory: {e}")

        # Save private key with restrictive permissions
        private_key_path = private_dir / "private_key.pem"
        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        # Set restrictive permissions on private key file
        try:
            os.chmod(private_key_path, 0o600)  # Only owner can read/write
        except Exception as e:
            print(f"Warning: Could not set permissions on private key file: {e}")

        # Save public key
        with open(public_dir / "public_key.pem", "wb") as f:
            f.write(public_pem)

        print(f"Keys generated and saved to:")
        print(f"  Private key (restricted): {private_key_path}")
        print(f"  Public key: {public_dir / 'public_key.pem'}")

    return private_pem, public_pem


def load_private_key(
    private_key_path: Union[str, Path], passphrase: Optional[str] = None
) -> Any:
    """
    Load a private key from a file, handling encrypted keys.

    Args:
        private_key_path: Path to the private key PEM file
        passphrase: Optional passphrase to decrypt the key if encrypted

    Returns:
        The loaded private key object
    """
    with open(private_key_path, "rb") as f:
        private_key_pem = f.read()

    try:
        # Try loading with no password first
        return serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )
    except Exception as e:
        # If that fails and we have a passphrase, try with the passphrase
        if passphrase:
            try:
                return serialization.load_pem_private_key(
                    private_key_pem,
                    password=passphrase.encode(),
                )
            except Exception as e2:
                raise ValueError(f"Failed to decrypt private key: {e2}")
        else:
            raise ValueError(
                f"Key appears to be encrypted but no passphrase provided: {e}"
            )


def sign_hash(hash_value: str, private_key_pem: bytes) -> str:
    """
    Sign a hash value with the private key.

    Args:
        hash_value: Hash string to sign
        private_key_pem: PEM-encoded private key

    Returns:
        Hex-encoded signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    signature = private_key.sign(
        hash_value.encode(),
        padding.PSS(
            mgf=padding.MGF1(crypto_hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        crypto_hashes.SHA256(),
    )

    return signature.hex()


def verify_signature(
    hash_value: str, signature_hex: str, public_key_pem: bytes
) -> bool:
    """
    Verify a signature against a hash value using the public key.

    Args:
        hash_value: Original hash that was signed
        signature_hex: Hex-encoded signature to verify
        public_key_pem: PEM-encoded public key

    Returns:
        True if signature is valid, False otherwise
    """
    public_key = serialization.load_pem_public_key(public_key_pem)

    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            hash_value.encode(),
            padding.PSS(
                mgf=padding.MGF1(crypto_hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            crypto_hashes.SHA256(),
        )
        return True
    except Exception:
        return False
