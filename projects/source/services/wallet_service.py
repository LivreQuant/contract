# services/wallet_service.py
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import config
from algosdk import account, mnemonic
from utils.algorand import (
    get_algod_client,
    fund_account,
    check_balance,
    get_account_from_mnemonic,
)
from utils.encryption import encrypt_string, decrypt_string

logger = logging.getLogger(__name__)


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
    if encrypt and config.SECRET_PASS_PHRASE:
        mnemonic_encrypted, salt1 = encrypt_string(
            wallet_mnemonic, config.SECRET_PASS_PHRASE
        )
        # Note: private_key is already a string, no need to call hex()
        private_key_encrypted, salt2 = encrypt_string(
            private_key, config.SECRET_PASS_PHRASE
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


def get_admin_wallet() -> Tuple[str, str]:
    """
    Get admin wallet private key and address.

    Returns:
        Tuple of (private_key, address)
    """
    try:
        admin_mnemonic = decrypt_admin_mnemonic()
        return get_account_from_mnemonic(admin_mnemonic)
    except Exception as e:
        logger.error(f"Error getting admin credentials: {e}")
        raise ValueError("Could not retrieve admin credentials")


def decrypt_admin_mnemonic() -> str:
    """
    Decrypt the admin mnemonic from environment variables.

    Returns:
        Decrypted admin mnemonic
    """
    admin_mnemonic_env = config.ADMIN_MNEMONIC

    if not admin_mnemonic_env:
        raise ValueError("ADMIN_MNEMONIC not found in environment variables")

    # Check if encrypted (contains a colon separator)
    if ":" in admin_mnemonic_env:
        encrypted_mnemonic, salt = admin_mnemonic_env.split(":", 1)

        if not config.SECRET_PASS_PHRASE:
            raise ValueError("SECRET_PASS_PHRASE is required to decrypt admin mnemonic")

        return decrypt_string(encrypted_mnemonic, config.SECRET_PASS_PHRASE, salt)
    else:
        # Not encrypted
        return admin_mnemonic_env


def get_or_create_user_wallet(user_id: str) -> Dict[str, Any]:
    """
    Get a user wallet from database or create if it doesn't exist.

    Args:
        user_id: Unique identifier for the user

    Returns:
        Dictionary with wallet information
    """
    wallet_path = config.WALLETS_DIR / f"{user_id}_wallet.json"

    # Check if wallet already exists
    if wallet_path.exists():
        with open(wallet_path, "r") as f:
            wallet_info = json.load(f)
        logger.info(f"Retrieved existing wallet for user {user_id}")
        return wallet_info

    # Create a new wallet if it doesn't exist
    wallet_info = generate_algorand_wallet(f"user_{user_id}", config.ENCRYPT_WALLETS)

    # Save the wallet info
    with open(wallet_path, "w") as f:
        json.dump(wallet_info, f, indent=2)

    logger.info(f"Created new wallet for user {user_id}")
    return wallet_info


def get_wallet_credentials(
    wallet_info: Dict[str, Any], passphrase: str = None
) -> Tuple[str, str]:
    """
    Get private key and address from wallet info, decrypting if necessary.

    Args:
        wallet_info: The wallet information dictionary
        passphrase: The passphrase for decryption (uses config.SECRET_PASS_PHRASE if None)

    Returns:
        Tuple of (private_key, address)
    """
    address = wallet_info["address"]

    if wallet_info.get("encrypted", False):
        # Use provided passphrase or the environment variable
        if passphrase is None:
            passphrase = config.SECRET_PASS_PHRASE

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
                    private_key = decrypt_string(
                        wallet_info["private_key_str"],
                        passphrase,
                        wallet_info["private_key_salt"],
                    )
                    return private_key, address
            except Exception as e2:
                logger.error(f"Failed to decrypt private key: {e2}")
                raise ValueError("Could not decrypt wallet credentials")
    else:
        # Handle unencrypted wallet info
        if "private_key" in wallet_info:
            return wallet_info["private_key"], address
        elif "mnemonic" in wallet_info:
            return mnemonic.to_private_key(wallet_info["mnemonic"]), address
        else:
            raise ValueError("No private key or mnemonic found in wallet info")


def ensure_user_wallet_funded(user_id: str, min_balance: float = 1.0) -> bool:
    """
    Ensure user wallet has sufficient funds, fund if necessary.

    Args:
        user_id: User identifier
        min_balance: Minimum balance in Algos

    Returns:
        True if wallet is funded, False if funding failed
    """
    # Get the algod client
    algod_client = get_algod_client()

    # Get user wallet
    user_wallet = get_or_create_user_wallet(user_id)
    user_private_key, user_address = get_wallet_credentials(user_wallet)

    # Check user balance
    user_balance = check_balance(algod_client, user_address)

    # If user has sufficient balance, return True
    if user_balance >= min_balance:
        logger.info(
            f"User {user_id} wallet already has sufficient funds ({user_balance} Algos)"
        )
        return True

    # Get admin wallet to fund user
    admin_private_key, admin_address = get_admin_wallet()

    # Check admin balance
    admin_balance = check_balance(algod_client, admin_address)

    # Fund user wallet if admin has sufficient balance
    if admin_balance < min_balance + 1:
        logger.warning(
            f"Admin wallet doesn't have enough funds to transfer ({admin_balance} Algos)"
        )
        return False

    # Fund user wallet
    amount_to_fund = min_balance + 1  # Add extra for transaction fees
    try:
        fund_account(
            algod_client, admin_private_key, admin_address, user_address, amount_to_fund
        )
        logger.info(f"Funded user {user_id} wallet with {amount_to_fund} Algos")
        return True
    except Exception as e:
        logger.error(f"Error funding user wallet: {e}")
        return False
