# wallet_create.py

import os
import logging
import argparse
from pathlib import Path

from utils.wallet import fund_wallets

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("wallet_create")


def main():
    """Create and manage wallets."""
    parser = argparse.ArgumentParser(description="Create and manage Algorand wallets")

    parser.add_argument(
        "--no-encrypt", action="store_true", help="Don't encrypt wallet credentials"
    )
    parser.add_argument("--passphrase", help="Custom passphrase for encryption")

    args = parser.parse_args()

    # Set encryption flag
    encrypt = not args.no_encrypt

    # If custom passphrase provided, set it in environment
    if args.passphrase:
        os.environ["SECRET_PASS_PHRASE"] = args.passphrase
    elif encrypt and not os.getenv("SECRET_PASS_PHRASE"):
        # Generate a random passphrase if not provided and encryption is requested
        import secrets

        passphrase = secrets.token_hex(16)
        os.environ["SECRET_PASS_PHRASE"] = passphrase
        logger.info(f"Generated random passphrase: {passphrase}")
        logger.warning(
            "STORE THIS PASSPHRASE SECURELY! You will need it to decrypt wallet credentials."
        )

        # Update .env file with passphrase
        env_path = Path(".env")
        if env_path.exists():
            with open(env_path, "r") as f:
                env_content = f.read()
        else:
            env_content = ""

        if "SECRET_PASS_PHRASE" in env_content:
            env_content = env_content.replace(
                env_content[
                    env_content.find("SECRET_PASS_PHRASE=") : env_content.find(
                        "\n", env_content.find("SECRET_PASS_PHRASE=")
                    )
                ],
                f"SECRET_PASS_PHRASE={passphrase}",
            )
        else:
            env_content += f"\nSECRET_PASS_PHRASE={passphrase}\n"

        with open(env_path, "w") as f:
            f.write(env_content)

    # Create wallet directories
    wallets_dir = Path("db")
    wallets_dir.mkdir(exist_ok=True)

    print(f"Current working directory: {os.getcwd()}")
    print(f"Full path to wallets directory: {os.path.abspath(wallets_dir)}")

    # Fund wallets
    fund_wallets(encrypt=encrypt)

    print("\n=== IMPORTANT ===")
    print(
        "The wallets have been saved to the wallets directory and added to the .env file."
    )
    if encrypt:
        print(
            "Wallet credentials are encrypted. Make sure to securely store your passphrase."
        )


if __name__ == "__main__":
    main()
