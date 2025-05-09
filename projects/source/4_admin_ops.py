import logging
import json
import time
import os
import argparse
from pathlib import Path
from dotenv import load_dotenv
import base64

from algosdk import account, mnemonic, encoding
from algosdk.v2client import algod

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("admin_operations")

# Get environment variables
ALGOD_TOKEN = os.getenv(
    "ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")


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


def format_global_state(global_state):
    """Format global state for better debugging."""
    formatted_state = {}
    for item in global_state:
        key_bytes = base64.b64decode(item["key"])
        try:
            key = key_bytes.decode("utf-8")
        except:
            key = key_bytes.hex()

        if item["value"]["type"] == 1:  # bytes value
            value_bytes = base64.b64decode(item["value"]["bytes"])
            if key == "address":
                # If it's an address, convert it properly
                if len(value_bytes) == 32:
                    try:
                        addr = encoding.encode_address(value_bytes)
                        formatted_state[key] = f"Address: {addr}"
                    except:
                        formatted_state[key] = f"Bytes: {value_bytes.hex()}"
                else:
                    formatted_state[key] = f"Bytes: {value_bytes.hex()}"
            else:
                # Try to decode as UTF-8
                try:
                    formatted_state[key] = f"String: {value_bytes.decode('utf-8')}"
                except:
                    formatted_state[key] = f"Bytes: {value_bytes.hex()}"
        else:  # uint value
            formatted_state[key] = f"UInt: {item['value']['uint']}"

    return formatted_state


def extract_user_address_from_global_state(global_state):
    """
    Extract the user address from the global state.

    Args:
        global_state: The global state of the contract

    Returns:
        str: The user address, or None if not found
    """
    for item in global_state:
        key_bytes = base64.b64decode(item["key"])
        try:
            key = key_bytes.decode("utf-8")
        except:
            key = key_bytes.hex()

        if key == "address" and item["value"]["type"] == 1:  # bytes value for address
            addr_bytes = base64.b64decode(item["value"]["bytes"])
            if len(addr_bytes) == 32:
                try:
                    return encoding.encode_address(addr_bytes)
                except Exception as e:
                    logger.error(f"Error decoding address: {e}")

    return None


def check_if_user_opted_in(app_id):
    """
    Check if the authorized user (stored in g_address) is opted into the contract.

    Args:
        app_id: The application ID

    Returns:
        tuple: (bool, str) - (is_opted_in, user_address)
    """
    algod_client = get_algod_client()

    try:
        # Get the application's global state
        app_info = algod_client.application_info(app_id)
        global_state = (
            app_info["params"]["global-state"]
            if "global-state" in app_info["params"]
            else []
        )

        # Extract the user address from global state
        user_address = extract_user_address_from_global_state(global_state)

        if not user_address:
            logger.warning(
                f"No valid user address found in global state for app {app_id}"
            )
            return False, None

        # Check if this address has opted into the app
        account_info = algod_client.account_info(user_address)

        # Check all apps this account has opted into
        for app_local_state in account_info.get("apps-local-state", []):
            if app_local_state.get("id") == app_id:
                logger.info(
                    f"User {user_address} is currently opted in to app {app_id}"
                )
                return True, user_address

        logger.info(f"User {user_address} is not opted in to app {app_id}")
        return False, user_address
    except Exception as e:
        logger.error(f"Error checking if user is opted in: {e}")
        return False, None


def get_contract_state(app_id):
    """
    Get the current state of the contract.
    """
    # Initialize Algorand client
    algod_client = get_algod_client()

    # Get application information
    app_info = algod_client.application_info(app_id)

    # Get global state
    global_state = (
        app_info["params"]["global-state"]
        if "global-state" in app_info["params"]
        else []
    )

    # Format and return state
    return format_global_state(global_state), global_state


def update_contract_global(app_id, user_id, book_id, user_address, parameters):
    """
    Update the global parameters of a contract.

    Args:
        app_id: Application ID
        user_id: New user ID
        book_id: New book ID
        user_address: New user address
        parameters: New parameters string
    """
    # Initialize Algorand client
    algod_client = get_algod_client()

    # Get account information
    admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

    # Add ABI encoding (2-byte length prefix) to match what the contract expects
    user_id_bytes = len(user_id).to_bytes(2, byteorder="big") + user_id.encode()
    book_id_bytes = len(book_id).to_bytes(2, byteorder="big") + book_id.encode()
    params_bytes = len(parameters).to_bytes(2, byteorder="big") + parameters.encode()

    # Debug logging
    logger.info(f"Updating global parameters for app ID: {app_id}")
    logger.info(f"New user_id: {user_id}")
    logger.info(f"New book_id: {book_id}")
    logger.info(f"New address: {user_address}")
    logger.info(f"New parameters: {parameters}")

    # Create application call transaction to update global parameters
    params = algod_client.suggested_params()

    # For the update_global method
    update_app_args = [
        create_method_signature("update_global(byte[],byte[],account,byte[])uint64"),
        user_id_bytes,
        book_id_bytes,
        (0).to_bytes(8, "big"),  # Index 0 in accounts array
        params_bytes,
    ]

    update_txn = algod.transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=algod.transaction.OnComplete.NoOpOC,
        app_args=update_app_args,
        accounts=[
            user_address
        ],  # Pass the user address as the first entry in the accounts array
    )

    signed_update_txn = update_txn.sign(admin_private_key)
    update_txid = algod_client.send_transaction(signed_update_txn)
    logger.info(f"Update global parameters transaction sent with ID: {update_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, update_txid)
    logger.info(f"Contract global parameters updated successfully")

    # Display the updated state
    updated_state, _ = get_contract_state(app_id)
    logger.info("Updated contract state:")
    for key, value in updated_state.items():
        logger.info(f"  {key}: {value}")


def update_contract_status(app_id, new_status):
    """
    Update the status of a contract.

    Args:
        app_id: Application ID
        new_status: New status value ('ACTIVE', 'INACTIVE-STOP', or 'INACTIVE-SOLD')
    """
    # Validate status
    valid_statuses = ["ACTIVE", "INACTIVE-STOP", "INACTIVE-SOLD"]
    if new_status not in valid_statuses:
        raise ValueError(f"Status must be one of {valid_statuses}")

    # Initialize Algorand client
    algod_client = get_algod_client()

    # Get account information
    admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

    # Add ABI encoding to status
    status_bytes = len(new_status).to_bytes(2, byteorder="big") + new_status.encode()

    # Debug logging
    logger.info(f"Updating status for app ID: {app_id}")
    logger.info(f"New status: {new_status}")

    # Create application call transaction to update status
    params = algod_client.suggested_params()
    app_args = [create_method_signature("update_status(string)uint64"), status_bytes]

    update_txn = algod.transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=algod.transaction.OnComplete.NoOpOC,
        app_args=app_args,
    )

    signed_update_txn = update_txn.sign(admin_private_key)
    update_txid = algod_client.send_transaction(signed_update_txn)
    logger.info(f"Update status transaction sent with ID: {update_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, update_txid)
    logger.info(f"Contract status updated to {new_status}")

    # Display the updated state
    updated_state, _ = get_contract_state(app_id)
    logger.info("Updated contract state:")
    for key, value in updated_state.items():
        logger.info(f"  {key}: {value}")


def delete_contract(app_id, force=False):
    """
    Delete a contract.

    Args:
        app_id: Application ID
        force: If True, delete the contract even if the user is still opted in
    """
    # Initialize Algorand client
    algod_client = get_algod_client()

    # Check if user is opted in
    is_opted_in, user_address = check_if_user_opted_in(app_id)

    if is_opted_in and not force:
        raise ValueError(
            f"User {user_address} is still opted in to app {app_id}. "
            f"The user must opt out before the contract can be deleted. "
            f"Use --force to override this check."
        )

    # Get account information
    admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

    # Debug logging
    logger.info(f"Deleting contract with app ID: {app_id}")
    if is_opted_in and force:
        logger.warning(
            f"CAUTION: Deleting contract with user {user_address} still opted in. "
            f"This may lead to locked funds that the user cannot recover!"
        )

    # Create application call transaction to delete application
    params = algod_client.suggested_params()

    app_args = [create_method_signature("delete_application()uint64")]

    delete_txn = algod.transaction.ApplicationDeleteTxn(
        sender=admin_address, sp=params, index=app_id, app_args=app_args
    )

    signed_delete_txn = delete_txn.sign(admin_private_key)
    delete_txid = algod_client.send_transaction(signed_delete_txn)
    logger.info(f"Delete transaction sent with ID: {delete_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, delete_txid)
    logger.info(f"Contract deleted successfully")


def run_test_sequence(app_id, contract_info):
    """
    Run a test sequence of admin operations on a contract.

    Args:
        app_id: Application ID
        contract_info: Contract information dictionary
    """
    logger.info(f"Starting test sequence for app ID: {app_id}")

    # Step 1: Display current state
    current_state, _ = get_contract_state(app_id)
    logger.info("Current contract state:")
    for key, value in current_state.items():
        logger.info(f"  {key}: {value}")

    # Check if user is opted in
    is_opted_in, user_address = check_if_user_opted_in(app_id)
    if is_opted_in:
        logger.info(f"User {user_address} is opted in to the contract")
    else:
        logger.info(f"User {user_address} is not opted in to the contract")

    # Step 2: Update global parameters
    input("Press Enter to update global parameters...")

    # Make a small change to the parameters
    new_user_id = "user123_updated"
    new_book_id = "book456_updated"
    new_parameters = "region:EMEA|asset_class:FOREX|instrument_class:OPTIONS"
    user_address = contract_info["user_address"]

    update_contract_global(
        app_id, new_user_id, new_book_id, user_address, new_parameters
    )

    # Pause for user to check
    input("Press Enter to continue to status update...")

    # Step 3: Update status to INACTIVE-STOP
    update_contract_status(app_id, "INACTIVE-STOP")

    # Pause for user to check
    input("Press Enter to continue to contract deletion...")

    # Step 4: Delete the contract
    try:
        delete_contract(app_id)
        logger.info("Contract deleted successfully!")
    except ValueError as e:
        logger.error(f"Cannot delete contract: {e}")
        proceed = input("Do you want to force delete the contract anyway? (y/n): ")
        if proceed.lower() == "y":
            delete_contract(app_id, force=True)
            logger.info("Contract force deleted successfully!")
        else:
            logger.info("Contract deletion aborted")

    logger.info("Test sequence completed!")


def main():
    """Command-line interface for admin operations."""
    parser = argparse.ArgumentParser(
        description="Admin operations for the trader contract"
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # Test sequence command
    test_parser = subparsers.add_parser(
        "test", help="Run a test sequence of operations"
    )
    test_parser.add_argument("contract_file", help="Contract information JSON file")

    # Status command
    status_parser = subparsers.add_parser("status", help="Update contract status")
    status_parser.add_argument("app_id", type=int, help="Application ID")
    status_parser.add_argument(
        "new_status",
        choices=["ACTIVE", "INACTIVE-STOP", "INACTIVE-SOLD"],
        help="New status value",
    )

    # Global update command
    global_parser = subparsers.add_parser(
        "update-global", help="Update global parameters"
    )
    global_parser.add_argument("app_id", type=int, help="Application ID")
    global_parser.add_argument("--user-id", required=True, help="New user ID")
    global_parser.add_argument("--book-id", required=True, help="New book ID")
    global_parser.add_argument("--user-address", required=True, help="New user address")
    global_parser.add_argument(
        "--parameters", required=True, help="New parameters string"
    )

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete the contract")
    delete_parser.add_argument("app_id", type=int, help="Application ID")
    delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Force deletion even if user is still opted in",
    )

    # State command
    state_parser = subparsers.add_parser("state", help="Get contract state")
    state_parser.add_argument("app_id", type=int, help="Application ID")

    # Check opt-in status command
    optin_parser = subparsers.add_parser(
        "check-optin", help="Check if the user is opted into the contract"
    )
    optin_parser.add_argument("app_id", type=int, help="Application ID")

    args = parser.parse_args()

    try:
        if not ADMIN_MNEMONIC:
            raise ValueError(
                "ADMIN_MNEMONIC environment variable not set. Please check your .env file."
            )

        if args.command == "test":
            # Load contract information
            with open(args.contract_file, "r") as f:
                contract_info = json.load(f)

            app_id = contract_info["app_id"]
            run_test_sequence(app_id, contract_info)

        elif args.command == "status":
            update_contract_status(args.app_id, args.new_status)

        elif args.command == "update-global":
            update_contract_global(
                args.app_id,
                args.user_id,
                args.book_id,
                args.user_address,
                args.parameters,
            )

        elif args.command == "delete":
            delete_contract(args.app_id, args.force)

        elif args.command == "state":
            state, _ = get_contract_state(args.app_id)
            print(json.dumps(state, indent=2))

        elif args.command == "check-optin":
            is_opted_in, user_address = check_if_user_opted_in(args.app_id)
            if is_opted_in:
                print(f"User {user_address} is currently opted in to app {args.app_id}")
            else:
                print(f"User {user_address} is not opted in to app {args.app_id}")

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)


if __name__ == "__main__":
    main()

# python3.12 4_admin_ops.py test contract_1096_info.json
