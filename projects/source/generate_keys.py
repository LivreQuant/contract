# generate_keys.py
import argparse
import os
from pathlib import Path
from services.crypto_service import generate_key_pair
import config
from dotenv import load_dotenv, set_key


def main():
    parser = argparse.ArgumentParser(
        description="Generate cryptographic keys for secure file verification"
    )
    parser.add_argument(
        "--private-output",
        help="Directory to save private key (defaults to config.PRIVATE_KEYS_DIR)",
    )
    parser.add_argument(
        "--public-output",
        help="Directory to save public key (defaults to config.KEYS_DIR)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt private key with SECRET_PASS_PHRASE",
    )
    parser.add_argument(
        "--update-env", action="store_true", help="Update .env file with key paths"
    )
    parser.add_argument(
        "--name", default="default", help="Name prefix for the key files"
    )
    args = parser.parse_args()

    # Use arguments or defaults
    private_dir = args.private_output or config.PRIVATE_KEYS_DIR
    public_dir = args.public_output or config.KEYS_DIR
    encrypt = args.encrypt or config.ENCRYPT_PRIVATE_KEYS

    # Ensure directories exist
    private_dir = Path(private_dir)
    public_dir = Path(public_dir)

    private_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    # Set secure permissions on private key directory
    try:
        import os

        os.chmod(private_dir, 0o700)  # Owner only
    except Exception as e:
        print(f"Warning: Could not set permissions on {private_dir}: {e}")

    # Determine filenames
    private_key_path = private_dir / f"{args.name}_private_key.pem"
    public_key_path = public_dir / f"{args.name}_public_key.pem"

    print(f"Generating RSA key pair for secure file verification...")

    # Get passphrase if encrypting
    passphrase = None
    if encrypt:
        if config.SECRET_PASS_PHRASE:
            passphrase = config.SECRET_PASS_PHRASE
            print("Using SECRET_PASS_PHRASE from environment to encrypt private key")
        else:
            import getpass

            passphrase = getpass.getpass("Enter passphrase to encrypt private key: ")

    # Generate the keys
    private_pem, public_pem = generate_key_pair(
        passphrase=passphrase, encrypt_private=encrypt
    )

    # Save keys manually to have more control
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    # Set secure permissions on private key file
    try:
        os.chmod(private_key_path, 0o600)  # Owner read/write only
    except Exception as e:
        print(f"Warning: Could not set permissions on {private_key_path}: {e}")

    print(f"Keys generated successfully:")
    print(f"  Private key: {private_key_path}" + (" (encrypted)" if encrypt else ""))
    print(f"  Public key: {public_key_path}")

    # Update .env file if requested
    if args.update_env:
        dotenv_path = Path(".env")

        # Create .env file if it doesn't exist
        if not dotenv_path.exists():
            dotenv_path.touch()

        # Update the variables
        set_key(dotenv_path, "PRIVATE_KEY_PATH", str(private_key_path))
        set_key(dotenv_path, "PUBLIC_KEY_PATH", str(public_key_path))

        print(f"\n.env file updated with key paths")
        print(
            "IMPORTANT: Keep your .env file secure and never commit it to version control"
        )


if __name__ == "__main__":
    main()
