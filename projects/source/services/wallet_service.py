# services/wallet_service.py
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import config
from utils.wallet import (
    generate_algorand_wallet,
    get_wallet_credentials,
    decrypt_admin_mnemonic,
)
from utils.algorand import (
    get_algod_client,
    fund_account,
    check_balance,
    get_account_from_mnemonic,
)

logger = logging.getLogger(__name__)


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
