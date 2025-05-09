# wallet_create.py - Create and manage wallets

import os
import logging
from pathlib import Path

from utils.wallet import (
    generate_algorand_wallet,
    save_wallet_info,
    update_env_file,
    fund_wallets,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("wallet_create")


def main():
    """Create and manage wallets."""
    # Create wallet directories
    wallets_dir = Path("wallets")
    wallets_dir.mkdir(exist_ok=True)

    print(f"Current working directory: {os.getcwd()}")
    print(f"Full path to wallets directory: {os.path.abspath(wallets_dir)}")

    # Fund wallets
    fund_wallets()

    print("\n=== IMPORTANT ===")
    print(
        "The wallets have been saved to the wallets directory and added to the .env file."
    )


if __name__ == "__main__":
    main()
