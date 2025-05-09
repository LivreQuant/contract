# utils/algorand.py - Common Algorand utility functions

import base64
import logging
import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union

from algosdk import account, mnemonic, encoding, logic
from algosdk.v2client import algod, indexer
from algosdk import transaction
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("algorand_utils")

# Load environment variables
load_dotenv()

# Algorand node connection parameters
ALGOD_TOKEN = os.getenv(
    "ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")

# Indexer connection parameters
INDEXER_TOKEN = os.getenv(
    "INDEXER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
INDEXER_SERVER = os.getenv("INDEXER_SERVER", "http://localhost")
INDEXER_PORT = os.getenv("INDEXER_PORT", "8980")

# Wallet mnemonics
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")
USER_MNEMONIC = os.getenv("USER_MNEMONIC")

# Contract configuration
DEFAULT_FUNDING_AMOUNT = 1_000_000  # 1 Algo in microAlgos


def get_algod_client() -> algod.AlgodClient:
    """Create and return an algod client."""
    algod_address = f"{ALGOD_SERVER}:{ALGOD_PORT}"
    return algod.AlgodClient(ALGOD_TOKEN, algod_address)


def get_indexer_client() -> indexer.IndexerClient:
    """Create and return an indexer client."""
    indexer_address = f"{INDEXER_SERVER}:{INDEXER_PORT}"
    return indexer.IndexerClient(INDEXER_TOKEN, indexer_address)


def get_account_from_mnemonic(mnemonic_phrase: str) -> Tuple[str, str]:
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


def wait_for_confirmation(client: algod.AlgodClient, txid: str) -> Dict[str, Any]:
    """
    Wait for a transaction to be confirmed.

    Args:
        client: The algod client
        txid: The transaction ID

    Returns:
        The transaction information
    """
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


def compile_program(client: algod.AlgodClient, source_code: str) -> bytes:
    """
    Compile TEAL source code to binary.

    Args:
        client: The algod client
        source_code: The TEAL source code

    Returns:
        The compiled program bytes
    """
    compile_response = client.compile(source_code)
    return base64.b64decode(compile_response["result"])


def create_method_signature(method_signature: str) -> bytes:
    """
    Create a method signature for ARC-4 compatible smart contracts.
    This creates the first 4 bytes of the SHA-512/256 hash of the method signature.

    Args:
        method_signature: The method signature string (e.g., "initialize(bytes,bytes,bytes)uint64")

    Returns:
        The first 4 bytes of the hash
    """
    return encoding.checksum(method_signature.encode())[:4]


def fund_account(
    client: algod.AlgodClient,
    sender_private_key: str,
    sender_address: str,
    receiver_address: str,
    amount_in_algos: float,
) -> Optional[str]:
    """
    Fund an account by sending Algos from sender to receiver.

    Args:
        client: The algod client instance
        sender_private_key: Private key of the sender
        sender_address: Address of the sender
        receiver_address: Address of the receiver
        amount_in_algos: Amount to send in Algos (not microAlgos)

    Returns:
        The transaction ID or None if error
    """
    # Get suggested parameters from the algod
    params = client.suggested_params()

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
    txid = client.send_transaction(signed_txn)
    logger.info(f"Transaction ID: {txid}")

    # Wait for confirmation
    try:
        confirmed_txn = wait_for_confirmation(client, txid)
        logger.info(
            f"Transaction confirmed in round: {confirmed_txn['confirmed-round']}"
        )
        logger.info(f"Funded {receiver_address} with {amount_in_algos} Algos")
        return txid
    except Exception as e:
        logger.error(f"Error confirming transaction: {e}")
        return None


def check_balance(client: algod.AlgodClient, address: str) -> float:
    """
    Check the balance of an account.

    Args:
        client: The algod client instance
        address: The address to check

    Returns:
        The balance in Algos
    """
    account_info = client.account_info(address)
    balance_in_microalgos = account_info.get("amount")
    balance_in_algos = balance_in_microalgos / 1_000_000
    logger.info(f"Account {address} has {balance_in_algos} Algos")
    return balance_in_algos


def format_global_state(global_state: list) -> Dict[str, str]:
    """
    Format global state for better readability.

    Args:
        global_state: The global state from an application

    Returns:
        Dictionary with formatted state values
    """
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


def format_local_state(local_state: list) -> Dict[str, str]:
    """
    Format local state for better readability.

    Args:
        local_state: The local state for an account in an application

    Returns:
        Dictionary with formatted state values
    """
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


def encode_params(params_dict: Dict[str, Any]) -> bytes:
    """
    Encode parameters into the format expected by the contract.
    Format: "key1:value1|key2:value2|..."

    Args:
        params_dict: Dictionary of parameters

    Returns:
        Encoded parameters as bytes
    """
    params_str = "|".join([f"{k}:{v}" for k, v in params_dict.items()])
    return params_str.encode("utf-8")


def decode_params(params_bytes: bytes) -> Dict[str, str]:
    """
    Decode parameters from the format used by the contract.
    Format: "key1:value1|key2:value2|..."

    Args:
        params_bytes: Encoded parameters

    Returns:
        Dictionary of parameters
    """
    params_str = params_bytes.decode("utf-8")
    if params_str == "NAN":
        return {}

    result = {}
    for item in params_str.split("|"):
        if ":" in item:
            key, value = item.split(":", 1)
            result[key] = value
    return result


def check_application_exists(app_id: int) -> bool:
    """
    Check if an application exists.

    Args:
        app_id: The application ID

    Returns:
        True if the application exists, False otherwise
    """
    try:
        algod_client = get_algod_client()
        algod_client.application_info(app_id)
        return True
    except Exception as e:
        if "application does not exist" in str(e) or "not exist" in str(e):
            logger.error(f"Application {app_id} does not exist")
            return False
        raise


def extract_user_address_from_global_state(global_state: list) -> Optional[str]:
    """
    Extract the user address from the global state.

    Args:
        global_state: The global state of the contract

    Returns:
        The user address, or None if not found
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


def get_app_address(app_id: int) -> str:
    """
    Get the address associated with an application.

    Args:
        app_id: The application ID

    Returns:
        The application address
    """
    return logic.get_application_address(app_id)


def get_contract_state(app_id: int) -> Tuple[Dict[str, str], list]:
    """
    Get the current state of the contract.

    Args:
        app_id: The application ID

    Returns:
        Tuple of (formatted state, raw state)
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


def check_if_user_opted_in(app_id: int) -> Tuple[bool, Optional[str]]:
    """
    Check if the authorized user (stored in g_address) is opted into the contract.

    Args:
        app_id: The application ID

    Returns:
        Tuple of (is_opted_in, user_address)
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


def check_if_specific_user_opted_in(app_id: int, user_address: str) -> bool:
    """
    Check if a specific user is opted into the contract.

    Args:
        app_id: The application ID
        user_address: The user address to check

    Returns:
        True if the user is opted in, False otherwise
    """
    algod_client = get_algod_client()

    # Get account info
    account_info = algod_client.account_info(user_address)

    # Check if the account has opted in to this app
    for app_local_state in account_info.get("apps-local-state", []):
        if app_local_state.get("id") == app_id:
            return True

    return False


def get_user_local_state(app_id: int, user_address: str) -> Dict[str, str]:
    """
    Get the local state for a specific user.

    Args:
        app_id: The application ID
        user_address: The user address

    Returns:
        Dictionary with formatted local state
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


def get_latest_contract_id() -> int:
    """
    Get the latest contract ID from the most recent contract info file.

    Returns:
        The latest contract ID
    """
    contract_files = list(Path("..").glob("contract_*_info.json"))
    if not contract_files:
        raise FileNotFoundError("No contract info files found")

    # Sort by modification time (newest first)
    latest_file = max(contract_files, key=lambda f: f.stat().st_mtime)

    # Load the file
    import json

    with open(latest_file, "r") as f:
        contract_info = json.load(f)

    return contract_info["app_id"]
