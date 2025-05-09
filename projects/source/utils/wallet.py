# utils/wallet.py (updated with encryption)

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from dotenv import load_dotenv
from algosdk import account, mnemonic

from utils.encryption import encrypt_string, decrypt_string
from utils.algorand import get_algod_client, check_balance, fund_account

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger("wallet_utils")

# Get secret passphrase from environment
SECRET_PASS_PHRASE = os.getenv("SECRET_PASS_PHRASE")


def generate_algorand_wallet(
    name: str = "wallet", encrypt: bool = True
) -> Dict[str, Any]:
    """
    Generate a new Algorand wallet including private key, address, and mnemonic.

    Args:
        name: A name to identify this wallet (e.g. "admin" or "user")
        encrypt: Whether to encrypt sensitive data

    Returns:
        Dictionary with wallet information
    """
    # Generate a new private key and address
    private_key, address = account.generate_account()

    # Generate the mnemonic for the private key
    wallet_mnemonic = mnemonic.from_private_key(private_key)

    # Encrypt sensitive data if requested
    if encrypt and SECRET_PASS_PHRASE:
        mnemonic_encrypted, salt1 = encrypt_string(wallet_mnemonic, SECRET_PASS_PHRASE)
        private_key_encrypted, salt2 = encrypt_string(
            private_key.hex(), SECRET_PASS_PHRASE
        )

        # Create wallet info object with encrypted data
        wallet_info = {
            "name": name,
            "address": address,
            "mnemonic": mnemonic_encrypted,
            "mnemonic_salt": salt1,
            "private_key_str": private_key_encrypted,
            "private_key_salt": salt2,
            "encrypted": True,
        }
    else:
        # Create wallet info object with plaintext data
        wallet_info = {
            "name": name,
            "address": address,
            "private_key": private_key,
            "mnemonic": wallet_mnemonic,
            "encrypted": False,
        }

    return wallet_info


def save_wallet_info(wallet_info: Dict[str, Any], filename: str) -> None:
    """
    Save wallet information to a file.

    Args:
        wallet_info: The wallet information dictionary
        filename: The name of the file to save to
    """
    # Create a version safe for serialization
    save_info = {
        "name": wallet_info["name"],
        "address": wallet_info["address"],
        "encrypted": wallet_info.get("encrypted", False),
    }

    if wallet_info.get("encrypted", False):
        # Save encrypted data and salts
        save_info["mnemonic"] = wallet_info["mnemonic"]
        save_info["mnemonic_salt"] = wallet_info["mnemonic_salt"]
        save_info["private_key_str"] = wallet_info["private_key_str"]
        save_info["private_key_salt"] = wallet_info["private_key_salt"]
    else:
        # Save plaintext mnemonic
        save_info["mnemonic"] = wallet_info["mnemonic"]

        # Add private_key_hex if possible
        if isinstance(wallet_info.get("private_key"), bytes):
            save_info["private_key_hex"] = wallet_info["private_key"].hex()
        elif hasattr(wallet_info.get("private_key", ""), "__bytes__"):
            # Try to convert to bytes if possible
            save_info["private_key_hex"] = bytes(wallet_info["private_key"]).hex()
        else:
            # Store as string if can't convert to hex
            save_info["private_key_str"] = str(wallet_info.get("private_key", ""))

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, "w") as f:
        json.dump(save_info, f, indent=2)

    logger.info(f"Wallet information saved to {filename}")


def load_wallet_info(filename: str) -> Dict[str, Any]:
    """
    Load wallet information from a file.

    Args:
        filename: Path to the wallet file

    Returns:
        Wallet information dictionary
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Wallet file not found: {filename}")

    with open(filename, "r") as f:
        wallet_info = json.load(f)

    return wallet_info


def get_wallet_credentials(
    wallet_info: Dict[str, Any], passphrase: str = None
) -> Tuple[str, str]:
    """
    Get private key and address from wallet info, decrypting if necessary.

    Args:
        wallet_info: The wallet information dictionary
        passphrase: The passphrase for decryption (uses SECRET_PASS_PHRASE if None)

    Returns:
        Tuple of (private_key, address)
    """
    address = wallet_info["address"]

    if wallet_info.get("encrypted", False):
        # Use provided passphrase or the environment variable
        if passphrase is None:
            passphrase = SECRET_PASS_PHRASE

        if not passphrase:
            raise ValueError("Passphrase is required for decrypting wallet")

        # Decrypt mnemonic and get private key
        try:
            wallet_mnemonic = decrypt_string(
                wallet_info["mnemonic"], passphrase, wallet_info["mnemonic_salt"]
            )
            private_key = mnemonic.to_private_key(wallet_mnemonic)
            return private_key, address
        except Exception as e:
            logger.error(f"Failed to decrypt mnemonic: {e}")

            # Try with private key if available
            try:
                if (
                    "private_key_str" in wallet_info
                    and "private_key_salt" in wallet_info
                ):
                    private_key_hex = decrypt_string(
                        wallet_info["private_key_str"],
                        passphrase,
                        wallet_info["private_key_salt"],
                    )
                    return bytes.fromhex(private_key_hex), address
            except Exception as e2:
                logger.error(f"Failed to decrypt private key: {e2}")
                raise ValueError("Could not decrypt wallet credentials")
    else:
        # Handle unencrypted wallet info
        if "private_key" in wallet_info:
            return wallet_info["private_key"], address
        elif "private_key_hex" in wallet_info:
            return bytes.fromhex(wallet_info["private_key_hex"]), address
        elif "mnemonic" in wallet_info:
            return mnemonic.to_private_key(wallet_info["mnemonic"]), address
        else:
            raise ValueError("No private key or mnemonic found in wallet info")


def update_env_file(admin_mnemonic: str, encrypt: bool = True) -> None:
    """
    Update the .env file with the admin wallet mnemonic.

    Args:
        admin_mnemonic: The mnemonic for the admin wallet
        encrypt: Whether to encrypt the mnemonic
    """
    env_path = Path(".env")

    # Read existing .env file if it exists
    if env_path.exists():
        with open(env_path, "r") as f:
            env_content = f.read()
    else:
        env_content = """# Algorand node connection
ALGOD_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_SERVER=http://localhost
ALGOD_PORT=4001

INDEXER_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
INDEXER_SERVER=http://localhost
INDEXER_PORT=8980

"""

    # Encrypt mnemonic if requested
    if encrypt and SECRET_PASS_PHRASE:
        mnemonic_encrypted, salt = encrypt_string(admin_mnemonic, SECRET_PASS_PHRASE)
        admin_value = f"{mnemonic_encrypted}:{salt}"
    else:
        admin_value = admin_mnemonic

    # Update or add the admin mnemonic
    if "ADMIN_MNEMONIC" in env_content:
        env_content = env_content.replace(
            env_content[
                env_content.find("ADMIN_MNEMONIC=") : env_content.find(
                    "\n", env_content.find("ADMIN_MNEMONIC=")
                )
            ],
            f"ADMIN_MNEMONIC={admin_value}",
        )
    else:
        env_content += f"\n# Admin wallet (deployer)\nADMIN_MNEMONIC={admin_value}\n"

    # Write updated content back to .env file
    with open(env_path, "w") as f:
        f.write(env_content)

    logger.info(f"Updated .env file with admin mnemonic")


def decrypt_admin_mnemonic() -> str:
    """
    Decrypt the admin mnemonic from environment variables.

    Returns:
        Decrypted admin mnemonic
    """
    admin_mnemonic_env = os.getenv("ADMIN_MNEMONIC")

    if not admin_mnemonic_env:
        raise ValueError("ADMIN_MNEMONIC not found in environment variables")

    # Check if encrypted (contains a colon separator)
    if ":" in admin_mnemonic_env:
        encrypted_mnemonic, salt = admin_mnemonic_env.split(":", 1)

        if not SECRET_PASS_PHRASE:
            raise ValueError("SECRET_PASS_PHRASE is required to decrypt admin mnemonic")

        return decrypt_string(encrypted_mnemonic, SECRET_PASS_PHRASE, salt)
    else:
        # Not encrypted
        return admin_mnemonic_env


def load_or_create_wallet(
    name: str, env_var: str, encrypt: bool = True
) -> Dict[str, Any]:
    """
    Load wallet from environment variable or create a new one.

    Args:
        name: Name of the wallet (admin or user)
        env_var: Environment variable name for the mnemonic
        encrypt: Whether to encrypt sensitive data

    Returns:
        Dictionary with wallet information
    """
    # For admin wallet, special handling
    if name == "admin" and env_var == "ADMIN_MNEMONIC":
        try:
            # Try to decrypt existing admin mnemonic
            admin_mnemonic = decrypt_admin_mnemonic()
            private_key = mnemonic.to_private_key(admin_mnemonic)
            address = account.address_from_private_key(private_key)

            logger.info(f"Loaded existing admin wallet: {address}")

            # Return in requested format
            if encrypt and SECRET_PASS_PHRASE:
                mnemonic_encrypted, salt1 = encrypt_string(
                    admin_mnemonic, SECRET_PASS_PHRASE
                )
                private_key_encrypted, salt2 = encrypt_string(
                    private_key.hex(), SECRET_PASS_PHRASE
                )

                return {
                    "name": name,
                    "address": address,
                    "mnemonic": mnemonic_encrypted,
                    "mnemonic_salt": salt1,
                    "private_key_str": private_key_encrypted,
                    "private_key_salt": salt2,
                    "encrypted": True,
                }
            else:
                return {
                    "name": name,
                    "address": address,
                    "private_key": private_key,
                    "mnemonic": admin_mnemonic,
                    "encrypted": False,
                }
        except Exception as e:
            logger.warning(f"Could not load admin wallet: {e}")
            # Continue to create new wallet

    # For regular environment variables
    mnemonic_phrase = os.getenv(env_var)

    if mnemonic_phrase:
        # Check if it's encrypted (contains a colon)
        if ":" in mnemonic_phrase:
            try:
                encrypted_mnemonic, salt = mnemonic_phrase.split(":", 1)
                if not SECRET_PASS_PHRASE:
                    raise ValueError(
                        "SECRET_PASS_PHRASE is required to decrypt mnemonic"
                    )

                mnemonic_phrase = decrypt_string(
                    encrypted_mnemonic, SECRET_PASS_PHRASE, salt
                )
            except Exception as e:
                logger.error(f"Error decrypting mnemonic: {e}")
                # Continue to create new wallet
                mnemonic_phrase = None

        if mnemonic_phrase:
            # Load existing wallet
            private_key = mnemonic.to_private_key(mnemonic_phrase)
            address = account.address_from_private_key(private_key)

            logger.info(f"Loaded existing {name} wallet: {address}")

            # Return in requested format
            if encrypt and SECRET_PASS_PHRASE:
                mnemonic_encrypted, salt1 = encrypt_string(
                    mnemonic_phrase, SECRET_PASS_PHRASE
                )
                private_key_encrypted, salt2 = encrypt_string(
                    private_key.hex(), SECRET_PASS_PHRASE
                )

                return {
                    "name": name,
                    "address": address,
                    "mnemonic": mnemonic_encrypted,
                    "mnemonic_salt": salt1,
                    "private_key_str": private_key_encrypted,
                    "private_key_salt": salt2,
                    "encrypted": True,
                }
            else:
                return {
                    "name": name,
                    "address": address,
                    "private_key": private_key,
                    "mnemonic": mnemonic_phrase,
                    "encrypted": False,
                }

    # Create new wallet
    wallet_info = generate_algorand_wallet(name, encrypt)

    # For admin wallet, update .env file
    if name == "admin" and env_var == "ADMIN_MNEMONIC":
        if wallet_info.get("encrypted", False):
            # Need to get the plaintext mnemonic for updating env
            wallet_mnemonic = decrypt_string(
                wallet_info["mnemonic"],
                SECRET_PASS_PHRASE,
                wallet_info["mnemonic_salt"],
            )
        else:
            wallet_mnemonic = wallet_info["mnemonic"]

        update_env_file(wallet_mnemonic, encrypt)

    logger.info(f"Created new {name} wallet: {wallet_info['address']}")
    return wallet_info


def fund_wallets(encrypt: bool = True) -> None:
    """
    Ensure admin and user wallets are created and funded.

    Args:
        encrypt: Whether to encrypt sensitive data
    """
    # Load algod client
    algod_client = get_algod_client()

    # Load or create admin wallet
    admin_wallet = load_or_create_wallet("admin", "ADMIN_MNEMONIC", encrypt)

    # Get admin credentials
    admin_private_key, admin_address = get_wallet_credentials(admin_wallet)

    # Load or create user wallet
    user_wallet = load_or_create_wallet("user", "USER_MNEMONIC", encrypt)

    # Get user credentials
    user_private_key, user_address = get_wallet_credentials(user_wallet)

    # Check admin balance
    admin_balance = check_balance(algod_client, admin_address)

    # Check user balance
    user_balance = check_balance(algod_client, user_address)

    # Fund user wallet if needed
    if user_balance < 1:  # If user has less than 1 Algo
        if admin_balance >= 5:  # If admin has at least 5 Algos
            logger.info(f"Funding user wallet with 5 Algos from admin wallet...")
            fund_account(
                algod_client,
                admin_private_key,
                admin_address,
                user_address,
                5,  # Sending 5 Algos
            )

            # Check updated user balance
            user_balance = check_balance(algod_client, user_address)
        else:
            logger.warning("Admin wallet doesn't have enough funds to transfer.")
    else:
        logger.info(f"User wallet already has sufficient funds ({user_balance} Algos).")

    # Create wallets directory if it doesn't exist
    wallets_dir = Path("wallets")
    wallets_dir.mkdir(exist_ok=True)

    # Display wallet information for reference
    logger.info("\n=== WALLET INFORMATION ===")
    logger.info(f"Admin Address: {admin_address}")
    logger.info(f"User Address: {user_address}")

    # Save wallet information to files
    save_wallet_info(admin_wallet, wallets_dir / "admin_wallet.json")
    save_wallet_info(user_wallet, wallets_dir / f"user_{user_address[:8]}_wallet.json")

    logger.info(f"Wallet information saved to the wallets directory.")
