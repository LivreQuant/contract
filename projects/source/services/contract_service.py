# services/contract_service.py
import json
import time
import logging
import base64
from typing import Dict, Any, Optional

import config
from utils.algorand import (
    get_algod_client,
    wait_for_confirmation,
    get_app_address,
    check_application_exists,
)
from utils.contract import (
    admin_update_contract_global,
    admin_update_contract_status,
    admin_delete_contract,
)
from services.wallet_service import (
    get_admin_wallet,
    get_or_create_user_wallet,
    get_wallet_credentials,
)

from algosdk import encoding, logic, transaction

logger = logging.getLogger(__name__)


def get_contract_for_user_book(user_id: str, book_id: str) -> Optional[Dict[str, Any]]:
    """
    Get contract info for a specific user and book ID if it exists.

    Args:
        user_id: User identifier
        book_id: Book identifier

    Returns:
        Contract info dictionary or None if not found
    """

    # If standard path doesn't exist or contract is no longer valid,
    # try to find any other contracts for this user/book
    pattern = f"{user_id}_{book_id}_*_contract.json"
    contract_files = list(config.CONTRACTS_DIR.glob(pattern))

    # Sort by modification time (newest first)
    if contract_files:
        contract_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        # Try each file until we find a valid contract
        for file_path in contract_files:
            try:
                with open(file_path, "r") as f:
                    contract_info = json.load(f)

                app_id = contract_info["app_id"]
                if check_application_exists(app_id):
                    logger.info(
                        f"Found existing contract for user {user_id} and book {book_id} with app ID {app_id}"
                    )

                    return contract_info
                else:
                    logger.warning(
                        f"Contract {app_id} no longer exists on blockchain, but preserving record"
                    )
                    # Mark as deleted instead of removing
                    contract_info["blockchain_status"] = "Deleted"
                    contract_info["deletion_note"] = (
                        "Contract no longer exists on blockchain"
                    )

                    # Save the updated contract info back to this file
                    with open(file_path, "w") as f:
                        json.dump(contract_info, f, indent=2)
            except Exception as e:
                logger.error(f"Error loading contract from {file_path}: {e}")

    return None


def create_method_signature(method_signature: str) -> bytes:
    """
    Create a method signature for ARC-4 compatible smart contracts.

    Args:
        method_signature: The method signature string

    Returns:
        The first 4 bytes of the hash
    """
    return encoding.checksum(method_signature.encode())[:4]


def deploy_contract_for_user_book(
    user_id: str, book_id: str, params_str: str = None
) -> Dict[str, Any]:
    """
    Deploy a new contract for a user and book.

    Args:
        user_id: User identifier
        book_id: Book identifier
        params_str: Optional parameters string

    Returns:
        Contract info dictionary
    """
    # Check if contract already exists
    existing_contract = get_contract_for_user_book(user_id, book_id)
    if existing_contract:
        return existing_contract

    # Use default params if none provided
    if params_str is None:
        params_str = config.DEFAULT_PARAMS_STR

    # Get user wallet info
    user_wallet = get_or_create_user_wallet(user_id)
    _, user_address = get_wallet_credentials(user_wallet)

    # Get admin credentials
    admin_private_key, admin_address = get_admin_wallet()

    # Initialize Algorand client
    algod_client = get_algod_client()

    # Load and compile the programs
    with open(config.CONTRACT_APPROVAL_PATH, "r") as f:
        approval_program_source = f.read()

    with open(config.CONTRACT_CLEAR_PATH, "r") as f:
        clear_program_source = f.read()

    approval_program = algod_client.compile(approval_program_source)["result"]
    clear_program = algod_client.compile(clear_program_source)["result"]

    # Define global schema and local schema
    global_schema = transaction.StateSchema(num_uints=0, num_byte_slices=5)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=3)

    # Define application parameters
    params = algod_client.suggested_params()

    # Create unsigned transaction
    txn = transaction.ApplicationCreateTxn(
        sender=admin_address,
        sp=params,
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=base64.b64decode(approval_program),
        clear_program=base64.b64decode(clear_program),
        global_schema=global_schema,
        local_schema=local_schema,
    )

    # Sign transaction
    signed_txn = txn.sign(admin_private_key)

    # Send transaction
    txid = algod_client.send_transaction(signed_txn)
    logger.info(f"Transaction sent with ID: {txid}")

    # Wait for confirmation
    tx_info = wait_for_confirmation(algod_client, txid)

    # Get the application ID
    app_id = tx_info.get("application-index")
    logger.info(f"Created application with ID: {app_id}")

    # Fund the contract account
    app_address = logic.get_application_address(app_id)
    logger.info(f"Application address: {app_address}")

    # Fund the application with specified amount
    params = algod_client.suggested_params()
    fund_txn = transaction.PaymentTxn(
        sender=admin_address,
        sp=params,
        receiver=app_address,
        amt=config.DEFAULT_FUNDING_AMOUNT,
    )

    signed_fund_txn = fund_txn.sign(admin_private_key)
    fund_txid = algod_client.send_transaction(signed_fund_txn)
    logger.info(f"Funding transaction sent with ID: {fund_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, fund_txid)
    logger.info(
        f"Funded contract with {config.DEFAULT_FUNDING_AMOUNT / 1_000_000} Algo"
    )

    # Convert strings to bytes with ABI encoding
    # Add a 2-byte length prefix to each string
    user_id_bytes = len(user_id).to_bytes(2, byteorder="big") + user_id.encode()
    book_id_bytes = len(book_id).to_bytes(2, byteorder="big") + book_id.encode()
    params_bytes = len(params_str).to_bytes(2, byteorder="big") + params_str.encode()

    # Create application call transaction to initialize contract
    params = algod_client.suggested_params()
    init_app_args = [
        create_method_signature("initialize(byte[],byte[],byte[])uint64"),
        user_id_bytes,
        book_id_bytes,
        params_bytes,
    ]

    initialize_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=init_app_args,
    )

    signed_initialize_txn = initialize_txn.sign(admin_private_key)
    initialize_txid = algod_client.send_transaction(signed_initialize_txn)
    logger.info(f"Initialization transaction sent with ID: {initialize_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, initialize_txid)
    logger.info(f"Contract initialized with initial values")

    # Now update the contract with the actual user address using update_global
    update_global_state(app_id, user_id, book_id, user_address, params_str)

    # Save contract information
    contract_info = {
        "app_id": app_id,
        "app_address": app_address,
        "user_id": user_id,
        "user_address": user_address,
        "book_id": book_id,
        "parameters": params_str,
        "creation_timestamp": time.time(),
        "status": "ACTIVE",
    }

    # App-specific path
    app_specific_path = (
        config.CONTRACTS_DIR / f"{user_id}_{book_id}_{app_id}_contract.json"
    )
    with open(app_specific_path, "w") as f:
        json.dump(contract_info, f, indent=2)

    logger.info(
        f"Contract information saved for user {user_id} and book {book_id} with app ID {app_id}"
    )

    return contract_info


def update_global_state(
    app_id: int, user_id: str, book_id: str, user_address: str, params_str: str
) -> bool:
    """
    Update the global state of a contract.

    Args:
        app_id: Application ID
        user_id: User identifier
        book_id: Book identifier
        user_address: User wallet address
        params_str: Parameters string

    Returns:
        True if successful, False otherwise
    """
    try:
        admin_update_contract_global(app_id, user_id, book_id, user_address, params_str)
        return True
    except Exception as e:
        logger.error(f"Error updating global state: {e}")
        return False


def set_contract_status(app_id: int, status: str) -> bool:
    """
    Set the status of a contract.

    Args:
        app_id: Application ID
        status: Status string ('ACTIVE', 'INACTIVE-STOP', or 'INACTIVE-SOLD')

    Returns:
        True if successful, False otherwise
    """
    try:
        admin_update_contract_status(app_id, status)
        return True
    except Exception as e:
        logger.error(f"Error updating contract status: {e}")
        return False


def remove_contract(user_id: str, book_id: str, force: bool = False) -> bool:
    """
    Remove a contract from the blockchain (but archive it locally).

    Args:
        user_id: User identifier
        book_id: Book identifier
        force: Force deletion even if user is still opted in

    Returns:
        True if successful, False otherwise
    """
    # Get contract info
    contract_info = get_contract_for_user_book(user_id, book_id)
    if not contract_info:
        logger.warning(f"No contract found for user {user_id} and book {book_id}")
        return False

    app_id = contract_info["app_id"]

    # Paths to explorer data (but we won't attempt to create it here)
    standard_explorer_path = (
        config.DB_DIR / "explorer" / f"{user_id}_{book_id}_explorer.json"
    )
    app_specific_explorer_path = (
        config.DB_DIR / "explorer" / f"{user_id}_{book_id}_{app_id}_explorer.json"
    )

    # Set contract to inactive first
    if not set_contract_status(app_id, "INACTIVE-STOP"):
        logger.error(f"Failed to set contract {app_id} to inactive status")
        if not force:
            return False

    # Delete contract from blockchain
    try:
        admin_delete_contract(app_id, force)
    except Exception as e:
        logger.error(f"Error deleting contract {app_id}: {e}")
        return False

    # Update contract info with deletion status
    contract_info["blockchain_status"] = "Deleted"
    contract_info["deletion_timestamp"] = time.time()

    # Save updated contract info (but don't remove from database) - to both paths
    app_specific_path = (
        config.CONTRACTS_DIR / f"{user_id}_{book_id}_{app_id}_contract.json"
    )

    with open(app_specific_path, "w") as f:
        json.dump(contract_info, f, indent=2)

    # Update the explorer data to mark as deleted but preserve data - if it exists
    explorer_paths = []
    if standard_explorer_path.exists():
        explorer_paths.append(standard_explorer_path)
    if app_specific_explorer_path.exists():
        explorer_paths.append(app_specific_explorer_path)

    for explorer_path in explorer_paths:
        try:
            with open(explorer_path, "r") as f:
                explorer_data = json.load(f)

            # Update deletion status but preserve the previously captured data
            explorer_data["blockchain_status"] = "Deleted"
            explorer_data["deletion_timestamp"] = time.time()
            explorer_data["contract_info"] = contract_info

            # Save updated explorer data
            with open(explorer_path, "w") as f:
                json.dump(explorer_data, f, indent=2)

            logger.info(
                f"Updated explorer data at {explorer_path} with deletion status"
            )
        except Exception as e:
            logger.error(f"Error updating explorer data at {explorer_path}: {e}")

    logger.info(
        f"Contract {app_id} successfully removed from blockchain but archived locally"
    )
    return True
