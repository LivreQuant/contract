# utils/wallet.py - Wallet management utilities

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from dotenv import load_dotenv
from algosdk import account, mnemonic

from utils.algorand import get_algod_client, check_balance, fund_account

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger("wallet_utils")


def generate_algorand_wallet(name: str = "wallet") -> Dict[str, Any]:
    """
    Generate a new Algorand wallet including private key, address, and mnemonic.

    Args:
        name: A name to identify this wallet (e.g. "admin" or "user")

    Returns:
        Dictionary with wallet information
    """
    # Generate a new private key and address
    private_key, address = account.generate_account()

    # Generate the mnemonic for the private key
    wallet_mnemonic = mnemonic.from_private_key(private_key)

    # Create wallet info object
    wallet_info = {
        "name": name,
        "address": address,
        "private_key": private_key,
        "mnemonic": wallet_mnemonic,
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
        "mnemonic": wallet_info["mnemonic"],
    }

    # Add private_key_hex only if private_key is bytes
    if isinstance(wallet_info["private_key"], bytes):
        save_info["private_key_hex"] = wallet_info["private_key"].hex()
    elif hasattr(wallet_info["private_key"], "__bytes__"):
        # Try to convert to bytes if possible
        save_info["private_key_hex"] = bytes(wallet_info["private_key"]).hex()
    else:
        # Just store as string if we can't convert to hex
        save_info["private_key_str"] = str(wallet_info["private_key"])

    with open(filename, "w") as f:
        json.dump(save_info, f, indent=2)

    logger.info(f"Wallet information saved to {filename}")


def update_env_file(admin_mnemonic: str, user_mnemonic: str) -> None:
    """
    Update the .env file with the wallet mnemonics.

    Args:
        admin_mnemonic: The mnemonic for the admin wallet
        user_mnemonic: The mnemonic for the user wallet
    """
    env_path = Path("../.env")

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

    # Update or add the mnemonics
    if "ADMIN_MNEMONIC" in env_content:
        env_content = env_content.replace(
            env_content[
                env_content.find("ADMIN_MNEMONIC=") : env_content.find(
                    "\n", env_content.find("ADMIN_MNEMONIC=")
                )
            ],
            f"ADMIN_MNEMONIC={admin_mnemonic}",
        )
    else:
        env_content += f"\n# Admin wallet (deployer)\nADMIN_MNEMONIC={admin_mnemonic}\n"

    if "USER_MNEMONIC" in env_content:
        env_content = env_content.replace(
            env_content[
                env_content.find("USER_MNEMONIC=") : env_content.find(
                    "\n", env_content.find("USER_MNEMONIC=")
                )
            ],
            f"USER_MNEMONIC={user_mnemonic}",
        )
    else:
        env_content += f"\n# User wallet\nUSER_MNEMONIC={user_mnemonic}\n"

    # Write updated content back to .env file
    with open(env_path, "w") as f:
        f.write(env_content)

    logger.info(f"Updated .env file with wallet mnemonics")


def load_or_create_wallet(name: str, env_var: str) -> Dict[str, Any]:
    """
    Load wallet from environment variable or create a new one.

    Args:
        name: Name of the wallet (admin or user)
        env_var: Environment variable name for the mnemonic

    Returns:
        Dictionary with wallet information
    """
    mnemonic_phrase = os.getenv(env_var)

    if mnemonic_phrase:
        # Load existing wallet
        from utils.algorand import get_account_from_mnemonic

        private_key, address = get_account_from_mnemonic(mnemonic_phrase)
        wallet_info = {
            "name": name,
            "address": address,
            "private_key": private_key,
            "mnemonic": mnemonic_phrase,
        }
        logger.info(f"Loaded existing {name} wallet: {address}")
        return wallet_info
    else:
        # Create new wallet
        private_key, address = account.generate_account()
        wallet_mnemonic = mnemonic.from_private_key(private_key)

        wallet_info = {
            "name": name,
            "address": address,
            "private_key": private_key,
            "mnemonic": wallet_mnemonic,
        }

        # Update .env file
        env_path = Path("../.env")
        if env_path.exists():
            with open(env_path, "r") as f:
                env_content = f.read()
        else:
            env_content = ""

        if f"{env_var}=" in env_content:
            env_content = env_content.replace(
                env_content[
                    env_content.find(f"{env_var}=") : env_content.find(
                        "\n", env_content.find(f"{env_var}=")
                    )
                ],
                f"{env_var}={wallet_mnemonic}",
            )
        else:
            env_content += (
                f"\n# {name.capitalize()} wallet\n{env_var}={wallet_mnemonic}\n"
            )

        with open(env_path, "w") as f:
            f.write(env_content)

        logger.info(f"Created new {name} wallet: {address}")
        return wallet_info


def fund_wallets() -> None:
    """
    Ensure admin and user wallets are created and funded.
    """
    # Load algod client
    algod_client = get_algod_client()

    # Load or create admin wallet
    admin_wallet = load_or_create_wallet("admin", "ADMIN_MNEMONIC")

    # Load or create user wallet
    user_wallet = load_or_create_wallet("user", "USER_MNEMONIC")

    # Check admin balance
    admin_balance = check_balance(algod_client, admin_wallet["address"])

    # Check user balance
    user_balance = check_balance(algod_client, user_wallet["address"])

    # Fund user wallet if needed
    if user_balance < 1:  # If user has less than 1 Algo
        if admin_balance >= 5:  # If admin has at least 5 Algos
            logger.info(f"Funding user wallet with 5 Algos from admin wallet...")
            fund_account(
                algod_client,
                admin_wallet["private_key"],
                admin_wallet["address"],
                user_wallet["address"],
                5,  # Sending 5 Algos
            )

            # Check updated user balance
            user_balance = check_balance(algod_client, user_wallet["address"])
        else:
            logger.warning("Admin wallet doesn't have enough funds to transfer.")
    else:
        logger.info(f"User wallet already has sufficient funds ({user_balance} Algos).")

    # Create wallets directory if it doesn't exist
    wallets_dir = Path("wallets")
    wallets_dir.mkdir(exist_ok=True)

    # Display wallet information for reference
    logger.info("\n=== WALLET INFORMATION ===")
    logger.info(f"Admin Address: {admin_wallet['address']}")
    logger.info(f"Admin Mnemonic: {admin_wallet['mnemonic']}")
    logger.info(f"User Address: {user_wallet['address']}")
    logger.info(f"User Mnemonic: {user_wallet['mnemonic']}")

    # Save wallet information to files
    save_wallet_info(admin_wallet, wallets_dir / "admin_wallet.json")
    save_wallet_info(user_wallet, wallets_dir / "user_wallet.json")

    logger.info(f"Wallet information saved to the wallets directory.")
