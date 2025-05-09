import os
import json
from pathlib import Path
from dotenv import load_dotenv
from algosdk.v2client import algod
from algosdk import account, mnemonic, transaction

load_dotenv()


def get_algod_client():
    """
    Create and return an algod client.
    """
    algod_token = os.getenv(
        "ALGOD_TOKEN",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    algod_server = os.getenv("ALGOD_SERVER", "http://localhost")
    algod_port = os.getenv("ALGOD_PORT", "4001")

    algod_address = f"{algod_server}:{algod_port}"

    # Initialize an algod client
    return algod.AlgodClient(algod_token, algod_address)


def get_account_from_mnemonic(mnemonic_phrase):
    """
    Get account information from a mnemonic phrase.

    Args:
        mnemonic_phrase: The mnemonic phrase for the account

    Returns:
        Tuple containing private key and address
    """
    private_key = mnemonic.to_private_key(mnemonic_phrase)
    address = account.address_from_private_key(private_key)
    return private_key, address


def fund_account(
    algod_client, sender_private_key, sender_address, receiver_address, amount_in_algos
):
    """
    Fund an account by sending Algos from sender to receiver.

    Args:
        algod_client: The algod client instance
        sender_private_key: Private key of the sender
        sender_address: Address of the sender
        receiver_address: Address of the receiver
        amount_in_algos: Amount to send in Algos (not microAlgos)

    Returns:
        The transaction ID
    """
    # Get suggested parameters from the algod
    params = algod_client.suggested_params()

    # Convert Algos to microAlgos (1 Algo = 1,000,000 microAlgos)
    amount_in_microalgos = int(amount_in_algos * 1_000_000)

    # Create a payment transaction
    txn = transaction.PaymentTxn(
        sender=sender_address,
        sp=params,
        receiver=receiver_address,
        amt=amount_in_microalgos,
        note=b"Funding account for contract interaction",
    )

    # Sign the transaction
    signed_txn = txn.sign(sender_private_key)

    # Send the transaction
    txid = algod_client.send_transaction(signed_txn)
    print(f"Transaction ID: {txid}")

    # Wait for confirmation
    try:
        confirmed_txn = transaction.wait_for_confirmation(algod_client, txid, 4)
        print(f"Transaction confirmed in round: {confirmed_txn['confirmed-round']}")
        print(f"Funded {receiver_address} with {amount_in_algos} Algos")
        return txid
    except Exception as e:
        print(f"Error confirming transaction: {e}")
        return None


def check_balance(algod_client, address):
    """
    Check the balance of an account.

    Args:
        algod_client: The algod client instance
        address: The address to check

    Returns:
        The balance in Algos
    """
    account_info = algod_client.account_info(address)
    balance_in_microalgos = account_info.get("amount")
    balance_in_algos = balance_in_microalgos / 1_000_000
    print(f"Account {address} has {balance_in_algos} Algos")
    return balance_in_algos


def load_or_create_wallet(name, env_var):
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
        private_key, address = get_account_from_mnemonic(mnemonic_phrase)
        wallet_info = {
            "name": name,
            "address": address,
            "private_key": private_key,
            "mnemonic": mnemonic_phrase,
        }
        print(f"Loaded existing {name} wallet: {address}")
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
        env_path = Path("../source/.env")
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

        print(f"Created new {name} wallet: {address}")
        return wallet_info


def main():
    """
    Main function to fund user wallet from admin wallet.
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
            print(f"Funding user wallet with 5 Algos from admin wallet...")
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
            print("Admin wallet doesn't have enough funds to transfer.")
    else:
        print(f"User wallet already has sufficient funds ({user_balance} Algos).")

    # Display wallet information for reference
    print("\n=== WALLET INFORMATION ===")
    print(f"Admin Address: {admin_wallet['address']}")
    print(f"Admin Mnemonic: {admin_wallet['mnemonic']}")
    print(f"User Address: {user_wallet['address']}")
    print(f"User Mnemonic: {user_wallet['mnemonic']}")

    # Save wallet information to files
    wallets_dir = Path("wallets")
    wallets_dir.mkdir(exist_ok=True)

    with open(wallets_dir / "admin_wallet.json", "w") as f:
        json.dump(
            {
                "name": admin_wallet["name"],
                "address": admin_wallet["address"],
                "mnemonic": admin_wallet["mnemonic"],
            },
            f,
            indent=2,
        )

    with open(wallets_dir / "user_wallet.json", "w") as f:
        json.dump(
            {
                "name": user_wallet["name"],
                "address": user_wallet["address"],
                "mnemonic": user_wallet["mnemonic"],
            },
            f,
            indent=2,
        )

    print(f"Wallet information saved to the wallets directory.")


if __name__ == "__main__":
    main()
