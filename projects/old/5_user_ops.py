import logging
import json
import os
import argparse
from pathlib import Path
from dotenv import load_dotenv
import base64

from algosdk import account, mnemonic
from algosdk.v2client import algod

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("user_operations")

# Get environment variables
ALGOD_TOKEN = os.getenv(
    "ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")
USER_MNEMONIC = os.getenv("USER_MNEMONIC")


def get_algod_client():
    """Create and return an algod client."""
    algod_address = f"{ALGOD_SERVER}:{ALGOD_PORT}"
    return algod.AlgodClient(ALGOD_TOKEN, algod_address)


def get_account_from_mnemonic(mnemonic_phrase):
    """Get account information from a mnemonic phrase."""
    private_key = mnemonic.to_private_key(mnemonic_phrase)
    address = account.address_from_private_key(private_key)
    return private_key, address


def wait_for_confirmation(client, txid):
    """Wait for a transaction to be confirmed."""
    last_round = client.status().get("last-round")
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get("confirmed-round") and txinfo.get("confirmed-round") > 0):
        logger.info("Waiting for confirmation...")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    logger.info(
        f"Transaction {txid} confirmed in round {txinfo.get('confirmed-round')}"
    )
    return txinfo


def create_method_signature(method_signature):
    """
    Create a method signature for ARC-4 compatible smart contracts.
    This creates the first 4 bytes of the SHA-512/256 hash of the method signature.
    """
    from algosdk import encoding

    return encoding.checksum(method_signature.encode())[:4]


def format_local_state(local_state):
    """Format local state for better debugging."""
    formatted_state = {}
    for item in local_state:
        key_bytes = base64.b64decode(item["key"])
        try:
            key = key_bytes.decode("utf-8")
        except:
            key = key_bytes.hex()

        if item["value"]["type"] == 1:  # bytes value
            value_bytes = base64.b64decode(item["value"]["bytes"])
            try:
                formatted_state[key] = f"String: {value_bytes.decode('utf-8')}"
            except:
                formatted_state[key] = f"Bytes: {value_bytes.hex()}"
        else:  # uint value
            formatted_state[key] = f"UInt: {item['value']['uint']}"

    return formatted_state


def check_application_exists(app_id):
    """Check if an application exists."""
    try:
        algod_client = get_algod_client()
        algod_client.application_info(app_id)
        return True
    except Exception as e:
        if "application does not exist" in str(e) or "not exist" in str(e):
            logger.error(f"Application {app_id} does not exist")
            return False
        raise


def check_if_opted_in(app_id, user_address):
    """Check if a user is already opted in to a contract."""
    algod_client = get_algod_client()

    # Get account info
    account_info = algod_client.account_info(user_address)

    # Check if the account has opted in to this app
    for app_local_state in account_info.get("apps-local-state", []):
        if app_local_state.get("id") == app_id:
            return True

    return False


def get_user_local_state(app_id, user_address):
    """
    Get the local state for a specific user.

    Args:
        app_id: Application ID
        user_address: User address

    Returns:
        dict: Formatted local state
    """
    algod_client = get_algod_client()

    # Get account info
    account_info = algod_client.account_info(user_address)

    # Find the app in local state
    local_state = None
    for app_local_state in account_info.get("apps-local-state", []):
        if app_local_state.get("id") == app_id:
            local_state = app_local_state.get("key-value", [])
            break

    if not local_state:
        logger.info(f"No local state found for app ID {app_id} and user {user_address}")
        return {}

    return format_local_state(local_state)


def check_account_balance(address):
    """Check the balance of an account."""
    algod_client = get_algod_client()
    account_info = algod_client.account_info(address)
    balance = account_info.get("amount") / 1_000_000  # Convert from microAlgos to Algos
    logger.info(f"Account {address} has balance: {balance} Algos")
    return balance


def opt_in_to_contract(app_id):
    """
    Opt in to a contract.

    Args:
        app_id: Application ID
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    # Check if application exists
    if not check_application_exists(app_id):
        raise ValueError(f"Application {app_id} does not exist")

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if already opted in
    if check_if_opted_in(app_id, user_address):
        logger.info(
            f"User {user_address} is already opted in to app {app_id}, skipping opt-in step"
        )

        # Display local state
        local_state = get_user_local_state(app_id, user_address)
        logger.info("Current local state:")
        for key, value in local_state.items():
            logger.info(f"  {key}: {value}")

        return

    # Check balance before opt-in
    balance_before = check_account_balance(user_address)

    logger.info(f"Opting into contract with app ID: {app_id}")

    # Create the method selector for opt_in
    opt_in_selector = create_method_signature("opt_in()uint64")

    # Create the transaction
    params = algod_client.suggested_params()
    opt_in_txn = algod.transaction.ApplicationOptInTxn(
        sender=user_address, sp=params, index=app_id, app_args=[opt_in_selector]
    )

    signed_opt_in_txn = opt_in_txn.sign(user_private_key)
    opt_in_txid = algod_client.send_transaction(signed_opt_in_txn)

    logger.info(f"Opt-in transaction sent with ID: {opt_in_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, opt_in_txid)
    logger.info(f"User successfully opted in to contract: {app_id}")

    # Check balance after opt-in
    balance_after = check_account_balance(user_address)

    # Show the difference (should be negative due to minimum balance requirement)
    difference = balance_after - balance_before
    logger.info(f"Account balance changed by {difference} Algos after opt-in")

    # Display local state after opt-in
    local_state = get_user_local_state(app_id, user_address)
    logger.info("Local state after opt-in:")
    for key, value in local_state.items():
        logger.info(f"  {key}: {value}")


def update_local_state(app_id, book_hash, research_hash, params_str):
    """
    Update the local state of a contract.

    Args:
        app_id: Application ID
        book_hash: Book hash value
        research_hash: Research hash value
        params_str: Parameters string
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    # Check if application exists
    if not check_application_exists(app_id):
        raise ValueError(f"Application {app_id} does not exist")

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if opted in
    if not check_if_opted_in(app_id, user_address):
        logger.error(
            f"User {user_address} is not opted in to app {app_id}. Please opt in first."
        )
        raise ValueError(f"User not opted in to app {app_id}")

    logger.info(f"Updating local state for app ID: {app_id}")
    logger.info(f"Book hash: {book_hash}")
    logger.info(f"Research hash: {research_hash}")
    logger.info(f"Parameters: {params_str}")

    # Add ABI encoding (2-byte length prefix) to match what the contract expects
    book_hash_bytes = len(book_hash).to_bytes(2, byteorder="big") + book_hash.encode()
    research_hash_bytes = (
        len(research_hash).to_bytes(2, byteorder="big") + research_hash.encode()
    )
    params_bytes = len(params_str).to_bytes(2, byteorder="big") + params_str.encode()

    # Create the method selector for update_local
    update_local_selector = create_method_signature(
        "update_local(byte[],byte[],byte[])uint64"
    )

    # Create the transaction
    params = algod_client.suggested_params()
    update_txn = algod.transaction.ApplicationNoOpTxn(
        sender=user_address,
        sp=params,
        index=app_id,
        app_args=[
            update_local_selector,
            book_hash_bytes,
            research_hash_bytes,
            params_bytes,
        ],
    )

    signed_update_txn = update_txn.sign(user_private_key)
    update_txid = algod_client.send_transaction(signed_update_txn)

    logger.info(f"Update local state transaction sent with ID: {update_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, update_txid)
    logger.info(f"Local state updated successfully")

    # Display updated local state
    local_state = get_user_local_state(app_id, user_address)
    logger.info("Updated local state:")
    for key, value in local_state.items():
        logger.info(f"  {key}: {value}")


def close_out_from_contract(app_id):
    """
    Close out (opt out) from a contract.

    Args:
        app_id: Application ID
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    # Check if application exists
    if not check_application_exists(app_id):
        raise ValueError(f"Application {app_id} does not exist")

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if opted in
    if not check_if_opted_in(app_id, user_address):
        logger.info(
            f"User {user_address} is not opted in to app {app_id}, nothing to close out from"
        )
        return

    # Check balance before close-out
    balance_before = check_account_balance(user_address)

    logger.info(f"Closing out from contract with app ID: {app_id}")

    # Create the method selector for close_out
    close_out_selector = create_method_signature("close_out()uint64")

    # Create the transaction
    params = algod_client.suggested_params()
    close_out_txn = algod.transaction.ApplicationCloseOutTxn(
        sender=user_address, sp=params, index=app_id, app_args=[close_out_selector]
    )

    signed_close_out_txn = close_out_txn.sign(user_private_key)
    close_out_txid = algod_client.send_transaction(signed_close_out_txn)

    logger.info(f"Close-out transaction sent with ID: {close_out_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, close_out_txid)
    logger.info(f"User successfully closed out from contract: {app_id}")

    # Check balance after close-out
    balance_after = check_account_balance(user_address)

    # Show the difference (should be positive due to released minimum balance requirement)
    difference = balance_after - balance_before
    logger.info(f"Account balance changed by {difference} Algos after close-out")

    # Try to get local state (should be empty now)
    local_state = get_user_local_state(app_id, user_address)
    if not local_state:
        logger.info("No local state found after close-out, as expected")
    else:
        logger.info("Unexpectedly, local state still exists after close-out:")
        for key, value in local_state.items():
            logger.info(f"  {key}: {value}")


def get_latest_contract_id():
    """Get the latest contract ID from the most recent contract info file."""
    contract_files = list(Path("../source").glob("contract_*_info.json"))
    if not contract_files:
        raise FileNotFoundError("No contract info files found")

    # Sort by modification time (newest first)
    latest_file = max(contract_files, key=lambda f: f.stat().st_mtime)

    # Load the file
    with open(latest_file, "r") as f:
        contract_info = json.load(f)

    return contract_info["app_id"]


def run_test_sequence(app_id):
    """
    Run a test sequence of user operations on a contract.

    Args:
        app_id: Application ID
    """
    logger.info(f"Starting user test sequence for app ID: {app_id}")

    # Get user address
    _, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Step 1: Opt in to the contract (or skip if already opted in)
    opt_in_to_contract(app_id)

    # Pause for user to check
    input("Press Enter to update local state for the first time...")

    # Step 2: Update local state
    update_local_state(
        app_id,
        "book_hash_123",
        "research_hash_456",
        "local_param1:value1|local_param2:value2",
    )

    # Pause for user to check
    input("Press Enter to update local state for the second time...")

    # Step 3: Update local state again with different values
    update_local_state(
        app_id,
        "book_hash_updated",
        "research_hash_updated",
        "local_param1:new_value1|local_param2:new_value2|local_param3:value3",
    )

    # Pause for user to check
    input("Press Enter to close out from the contract...")

    # Step 4: Close out from the contract
    close_out_from_contract(app_id)

    logger.info("User test sequence completed successfully!")


def main():
    """Command-line interface for user operations."""
    parser = argparse.ArgumentParser(
        description="User operations for the trader contract"
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # Test sequence command
    test_parser = subparsers.add_parser(
        "test", help="Run a test sequence of operations"
    )
    test_parser.add_argument(
        "app_id", type=int, help="Application ID (use 0 for latest)"
    )

    # Opt-in command
    opt_in_parser = subparsers.add_parser("opt-in", help="Opt in to a contract")
    opt_in_parser.add_argument("app_id", type=int, help="Application ID")

    # Update local state command
    update_parser = subparsers.add_parser("update-local", help="Update local state")
    update_parser.add_argument("app_id", type=int, help="Application ID")
    update_parser.add_argument("--book-hash", required=True, help="Book hash value")
    update_parser.add_argument(
        "--research-hash", required=True, help="Research hash value"
    )
    update_parser.add_argument("--parameters", required=True, help="Parameters string")

    # Close-out command
    close_out_parser = subparsers.add_parser(
        "close-out", help="Close out from a contract"
    )
    close_out_parser.add_argument("app_id", type=int, help="Application ID")

    # Get local state command
    state_parser = subparsers.add_parser("local-state", help="Get local state")
    state_parser.add_argument("app_id", type=int, help="Application ID")
    state_parser.add_argument(
        "--address", help="User address (defaults to address from USER_MNEMONIC)"
    )

    # Get latest contract command
    latest_parser = subparsers.add_parser("latest", help="Get the latest contract ID")

    args = parser.parse_args()

    try:
        # Special case for app_id = 0 (use latest)
        if hasattr(args, "app_id") and args.app_id == 0:
            args.app_id = get_latest_contract_id()
            logger.info(f"Using latest contract ID: {args.app_id}")

        # For local-state command, parse the address argument
        if args.command == "local-state" and not args.address and USER_MNEMONIC:
            _, user_address = get_account_from_mnemonic(USER_MNEMONIC)
            args.address = user_address

        if args.command == "test":
            run_test_sequence(args.app_id)

        elif args.command == "opt-in":
            opt_in_to_contract(args.app_id)

        elif args.command == "update-local":
            update_local_state(
                args.app_id, args.book_hash, args.research_hash, args.parameters
            )

        elif args.command == "close-out":
            close_out_from_contract(args.app_id)

        elif args.command == "local-state":
            if not args.address:
                parser.error(
                    "User address is required for local-state command when USER_MNEMONIC is not set"
                )

            state = get_user_local_state(args.app_id, args.address)
            if state:
                print(json.dumps(state, indent=2))
            else:
                print(
                    f"No local state found for app ID {args.app_id} and address {args.address}"
                )

        elif args.command == "latest":
            latest_id = get_latest_contract_id()
            print(f"Latest contract ID: {latest_id}")

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)


if __name__ == "__main__":
    main()

# python3.12 5_user_ops.py test 1085
