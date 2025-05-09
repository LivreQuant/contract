import json
import os
import subprocess
from pathlib import Path
from algosdk import account, mnemonic


def generate_algorand_wallet(name="wallet"):
    """
    Generate a new Algorand wallet including private key, address, and mnemonic.

    Args:
        name: A name to identify this wallet (e.g. "admin" or "user")

    Returns:
        dict: A dictionary containing the wallet information
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


def save_wallet_info(wallet_info, filename):
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

    print(f"Wallet information saved to {filename}")


def update_env_file(admin_mnemonic, user_mnemonic):
    """
    Update the .env file with the wallet mnemonics.

    Args:
        admin_mnemonic: The mnemonic for the admin wallet
        user_mnemonic: The mnemonic for the user wallet
    """
    env_path = Path("../source/.env")

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

    print(f"Updated .env file with wallet mnemonics")


def get_funded_account_from_localnet():
    """
    Get a funded account from the LocalNet.

    Returns:
        str: The address of a funded account on LocalNet
    """
    try:
        # Run the algokit goal account list command
        result = subprocess.run(
            ["algokit", "goal", "account", "list"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse the output to find accounts with sufficient funds
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if "online" in line and "microAlgos" in line:
                parts = line.split()
                address = parts[1]  # The address should be the second item
                # Extract the balance (ensure it's at least 100 Algos)
                for i, part in enumerate(parts):
                    if "microAlgos" in part and i > 0:
                        balance = int(parts[i - 1])
                        if balance >= 100_000_000:  # At least 100 Algos
                            return address

        # If we didn't find a suitable account
        raise ValueError("No account with sufficient funds found in LocalNet")

    except subprocess.CalledProcessError as e:
        print(f"Error running algokit goal account list: {e}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")
        raise


def fund_account(target_address, amount_algos=10):
    """
    Fund an account with Algos from a LocalNet funded account.

    Args:
        target_address: The address to fund
        amount_algos: The amount of Algos to send (default: 10)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get a funded account from LocalNet
        source_address = get_funded_account_from_localnet()

        # Calculate amount in microAlgos
        amount_microalgos = amount_algos * 1_000_000

        print(
            f"Funding {target_address} with {amount_algos} Algos from {source_address}..."
        )

        # Send the transaction
        result = subprocess.run(
            [
                "algokit",
                "goal",
                "clerk",
                "send",
                "-a",
                str(amount_microalgos),
                "-f",
                source_address,
                "-t",
                target_address,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        print(result.stdout)
        return True

    except Exception as e:
        print(f"Error funding account: {e}")
        return False


if __name__ == "__main__":
    # Create wallet directories
    wallets_dir = Path("wallets")
    wallets_dir.mkdir(exist_ok=True)

    print(f"Current working directory: {os.getcwd()}")
    print(f"Full path to wallets directory: {os.path.abspath(wallets_dir)}")

    # Generate admin wallet
    admin_wallet = generate_algorand_wallet(name="admin")
    save_wallet_info(admin_wallet, wallets_dir / "admin_wallet.json")

    # Generate user wallet
    user_wallet = generate_algorand_wallet(name="user")
    save_wallet_info(user_wallet, wallets_dir / "user_wallet.json")

    # Update .env file with mnemonics
    update_env_file(admin_wallet["mnemonic"], user_wallet["mnemonic"])

    # Display wallet information
    print("\n=== ADMIN WALLET ===")
    print(f"Address: {admin_wallet['address']}")
    print(f"Mnemonic: {admin_wallet['mnemonic']}")

    print("\n=== USER WALLET ===")
    print(f"Address: {user_wallet['address']}")
    print(f"Mnemonic: {user_wallet['mnemonic']}")

    # Fund the admin wallet
    print("\n=== FUNDING ADMIN WALLET ===")
    success = fund_account(admin_wallet["address"], 100)  # Fund with 100 Algos

    if success:
        print(f"Successfully funded admin wallet with 100 Algos")
    else:
        print("Failed to fund admin wallet automatically.")
        print(
            "You will need to manually fund the admin wallet before deploying contracts."
        )

    print("\n=== IMPORTANT ===")
    print(
        "The wallets have been saved to the wallets directory and added to the .env file."
    )
