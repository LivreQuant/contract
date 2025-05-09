# utils/contract.py - Contract utility functions

import json
import time
import logging
from typing import Dict, Any, Tuple, List, Optional

import base64
from pathlib import Path

from utils.algorand import (
    get_algod_client,
    wait_for_confirmation,
    create_method_signature,
    get_account_from_mnemonic,
    check_if_user_opted_in,
    ADMIN_MNEMONIC,
    USER_MNEMONIC,
)

from algosdk import encoding, logic, transaction

# Configure logging
logger = logging.getLogger("contract_utils")


def deploy_contract(
    approval_program_path: Path,
    clear_program_path: Path,
    global_schema_uints: int = 0,
    global_schema_bytes: int = 5,
    local_schema_uints: int = 0,
    local_schema_bytes: int = 3,
    funding_amount: int = 1_000_000,  # 1 Algo in microAlgos
    user_id: str = "user123",
    book_id: str = "book456",
    params_str: str = "region:NA|asset_class:EQUITIES|instrument_class:STOCKS",
) -> Tuple[int, Dict[str, Any]]:
    """
    Deploy a contract to the Algorand network.

    Args:
        approval_program_path: Path to the approval program TEAL file
        clear_program_path: Path to the clear program TEAL file
        global_schema_uints: Number of global uint slots
        global_schema_bytes: Number of global byte slices
        local_schema_uints: Number of local uint slots
        local_schema_bytes: Number of local byte slices
        funding_amount: Amount to fund the contract with (in microAlgos)
        user_id: User ID for initialization
        book_id: Book ID for initialization
        params_str: Parameters string for initialization

    Returns:
        Tuple of (app_id, contract_info)
    """
    # Initialize Algorand client
    algod_client = get_algod_client()

    # Get account information
    admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    logger.info(f"Admin address: {admin_address}")
    logger.info(f"User address: {user_address}")

    # Check account balances
    admin_info = algod_client.account_info(admin_address)
    user_info = algod_client.account_info(user_address)

    admin_balance = admin_info.get("amount") / 1_000_000  # Convert microAlgos to Algos
    user_balance = user_info.get("amount") / 1_000_000

    logger.info(f"Admin balance: {admin_balance} Algos")
    logger.info(f"User balance: {user_balance} Algos")

    # Load and compile the programs
    with open(approval_program_path, "r") as f:
        approval_program_source = f.read()

    with open(clear_program_path, "r") as f:
        clear_program_source = f.read()

    approval_program = algod_client.compile(approval_program_source)["result"]
    clear_program = algod_client.compile(clear_program_source)["result"]

    # Define global schema and local schema
    global_schema = transaction.StateSchema(
        num_uints=global_schema_uints, num_byte_slices=global_schema_bytes
    )
    local_schema = transaction.StateSchema(
        num_uints=local_schema_uints, num_byte_slices=local_schema_bytes
    )

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

    # utils/contract.py (continued from previous part)

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
        sender=admin_address, sp=params, receiver=app_address, amt=funding_amount
    )

    signed_fund_txn = fund_txn.sign(admin_private_key)
    fund_txid = algod_client.send_transaction(signed_fund_txn)
    logger.info(f"Funding transaction sent with ID: {fund_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, fund_txid)
    logger.info(f"Funded contract with {funding_amount / 1_000_000} Algo")

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
    params = algod_client.suggested_params()

    # For the update_global method
    update_app_args = [
        create_method_signature("update_global(byte[],byte[],account,byte[])uint64"),
        user_id_bytes,
        book_id_bytes,
        (0).to_bytes(8, "big"),  # Index 0 in accounts array
        params_bytes,
    ]

    update_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
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
    logger.info(f"Contract global parameters updated with real user address")

    # Save contract information
    contract_info = {
        "app_id": app_id,
        "app_address": app_address,
        "user_address": user_address,
        "admin_address": admin_address,
        "user_id": user_id,
        "book_id": book_id,
        "parameters": params_str,
        "creation_timestamp": time.time(),
    }

    # Save to file
    contract_info_file = f"contract_{app_id}_info.json"
    with open(contract_info_file, "w") as f:
        json.dump(contract_info, f, indent=2)

    logger.info(f"Contract information saved to {contract_info_file}")

    return app_id, contract_info


# User operations


def user_opt_in(app_id: int) -> None:
    """
    Opt in to a contract as the user.

    Args:
        app_id: The application ID
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if already opted in
    if check_if_user_opted_in(app_id, user_address):
        logger.info(
            f"User {user_address} is already opted in to app {app_id}, skipping opt-in step"
        )
        return

    # Check balance before opt-in
    balance_before = algod_client.account_info(user_address).get("amount") / 1_000_000

    logger.info(f"Opting into contract with app ID: {app_id}")

    # Create the method selector for opt_in
    opt_in_selector = create_method_signature("opt_in()uint64")

    # Create the transaction
    params = algod_client.suggested_params()
    opt_in_txn = transaction.ApplicationOptInTxn(
        sender=user_address, sp=params, index=app_id, app_args=[opt_in_selector]
    )

    signed_opt_in_txn = opt_in_txn.sign(user_private_key)
    opt_in_txid = algod_client.send_transaction(signed_opt_in_txn)

    logger.info(f"Opt-in transaction sent with ID: {opt_in_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, opt_in_txid)
    logger.info(f"User successfully opted in to contract: {app_id}")

    # Check balance after opt-in
    balance_after = algod_client.account_info(user_address).get("amount") / 1_000_000

    # Show the difference (should be negative due to minimum balance requirement)
    difference = balance_after - balance_before
    logger.info(f"Account balance changed by {difference} Algos after opt-in")


def user_update_local_state(
    app_id: int, book_hash: str, research_hash: str, params_str: str
) -> None:
    """
    Update the local state of a contract as the user.

    Args:
        app_id: The application ID
        book_hash: The book hash value
        research_hash: The research hash value
        params_str: Parameters string
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if opted in
    if not check_if_user_opted_in(app_id, user_address):
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
    update_txn = transaction.ApplicationNoOpTxn(
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


def user_close_out(app_id: int) -> None:
    """
    Close out from a contract as the user.

    Args:
        app_id: The application ID
    """
    if not USER_MNEMONIC:
        raise ValueError(
            "USER_MNEMONIC environment variable not set. Please check your .env file."
        )

    algod_client = get_algod_client()
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Check if opted in
    if not check_if_user_opted_in(app_id, user_address):
        logger.info(
            f"User {user_address} is not opted in to app {app_id}, nothing to close out from"
        )
        return

    # Check balance before close-out
    balance_before = algod_client.account_info(user_address).get("amount") / 1_000_000

    logger.info(f"Closing out from contract with app ID: {app_id}")

    # Create the method selector for close_out
    close_out_selector = create_method_signature("close_out()uint64")

    # Create the transaction
    params = algod_client.suggested_params()
    close_out_txn = transaction.ApplicationCloseOutTxn(
        sender=user_address, sp=params, index=app_id, app_args=[close_out_selector]
    )

    signed_close_out_txn = close_out_txn.sign(user_private_key)
    close_out_txid = algod_client.send_transaction(signed_close_out_txn)

    logger.info(f"Close-out transaction sent with ID: {close_out_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, close_out_txid)
    logger.info(f"User successfully closed out from contract: {app_id}")

    # Check balance after close-out
    balance_after = algod_client.account_info(user_address).get("amount") / 1_000_000

    # Show the difference (should be positive due to released minimum balance requirement)
    difference = balance_after - balance_before
    logger.info(f"Account balance changed by {difference} Algos after close-out")


# Admin operations


def admin_update_contract_status(app_id: int, new_status: str) -> None:
    """
    Update the status of a contract as the admin.

    Args:
        app_id: The application ID
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

    update_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=app_args,
    )

    signed_update_txn = update_txn.sign(admin_private_key)
    update_txid = algod_client.send_transaction(signed_update_txn)
    logger.info(f"Update status transaction sent with ID: {update_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, update_txid)
    logger.info(f"Contract status updated to {new_status}")


def admin_update_contract_global(
    app_id: int, user_id: str, book_id: str, user_address: str, parameters: str
) -> None:
    """
    Update the global parameters of a contract as the admin.

    Args:
        app_id: The application ID
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

    update_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
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


def admin_delete_contract(app_id: int, force: bool = False) -> None:
    """
    Delete a contract as the admin.

    Args:
        app_id: The application ID
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

    delete_txn = transaction.ApplicationDeleteTxn(
        sender=admin_address, sp=params, index=app_id, app_args=app_args
    )

    signed_delete_txn = delete_txn.sign(admin_private_key)
    delete_txid = algod_client.send_transaction(signed_delete_txn)
    logger.info(f"Delete transaction sent with ID: {delete_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, delete_txid)
    logger.info(f"Contract deleted successfully")
