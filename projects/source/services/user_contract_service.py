# services/user_contract_service.py
import logging
from typing import Dict, Any, Optional, Tuple

import config
from utils.algorand import (
    get_algod_client,
    check_if_specific_user_opted_in,
    wait_for_confirmation,
)
from services.wallet_service import get_or_create_user_wallet, get_wallet_credentials
from services.contract_service import (
    create_method_signature,
    get_contract_for_user_book,
)

from algosdk import transaction

logger = logging.getLogger(__name__)


def user_opt_in_to_contract(user_id: str, book_id: str) -> bool:
    """
    Opt user into a contract.

    Args:
        user_id: User identifier
        book_id: Book identifier

    Returns:
        True if successful, False otherwise
    """
    # Get contract info
    contract_info = get_contract_for_user_book(user_id, book_id)
    if not contract_info:
        logger.error(f"No contract found for user {user_id} and book {book_id}")
        return False

    app_id = contract_info["app_id"]
    user_wallet = get_or_create_user_wallet(user_id)
    user_private_key, user_address = get_wallet_credentials(user_wallet)

    # Check if already opted in
    algod_client = get_algod_client()
    if check_if_specific_user_opted_in(app_id, user_address):
        logger.info(
            f"User {user_id} is already opted in to contract for book {book_id}"
        )
        return True

    logger.info(f"Opting user {user_id} into contract {app_id} for book {book_id}")

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
    try:
        wait_for_confirmation(algod_client, opt_in_txid)
        logger.info(
            f"User {user_id} successfully opted in to contract for book {book_id}"
        )
        return True
    except Exception as e:
        logger.error(f"Error opting in to contract: {e}")
        return False


def update_user_local_state(
    user_id: str, book_id: str, book_hash: str, research_hash: str, params_str: str
) -> bool:
    """
    Update the local state for a user in a contract.

    Args:
        user_id: User identifier
        book_id: Book identifier
        book_hash: Book hash value
        research_hash: Research hash value
        params_str: Parameters string

    Returns:
        True if successful, False otherwise
    """
    # Get contract info
    contract_info = get_contract_for_user_book(user_id, book_id)
    if not contract_info:
        logger.error(f"No contract found for user {user_id} and book {book_id}")
        return False

    app_id = contract_info["app_id"]
    user_wallet = get_or_create_user_wallet(user_id)
    user_private_key, user_address = get_wallet_credentials(user_wallet)

    # Check if opted in
    algod_client = get_algod_client()
    if not check_if_specific_user_opted_in(app_id, user_address):
        logger.error(f"User {user_id} is not opted in to contract for book {book_id}")
        return False

    logger.info(f"Updating local state for user {user_id} in contract {app_id}")

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
    try:
        wait_for_confirmation(algod_client, update_txid)
        logger.info(
            f"Local state updated successfully for user {user_id} in contract for book {book_id}"
        )
        return True
    except Exception as e:
        logger.error(f"Error updating local state: {e}")
        return False


def user_close_out_from_contract(user_id: str, book_id: str) -> bool:
    """
    Close out a user from a contract.

    Args:
        user_id: User identifier
        book_id: Book identifier

    Returns:
        True if successful, False otherwise
    """
    # Get contract info
    contract_info = get_contract_for_user_book(user_id, book_id)
    if not contract_info:
        logger.error(f"No contract found for user {user_id} and book {book_id}")
        return False

    app_id = contract_info["app_id"]
    user_wallet = get_or_create_user_wallet(user_id)
    user_private_key, user_address = get_wallet_credentials(user_wallet)

    # Check if opted in
    algod_client = get_algod_client()
    if not check_if_specific_user_opted_in(app_id, user_address):
        logger.info(
            f"User {user_id} is not opted in to contract for book {book_id}, nothing to close out from"
        )
        return True

    logger.info(f"Closing out user {user_id} from contract {app_id} for book {book_id}")

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
    try:
        wait_for_confirmation(algod_client, close_out_txid)
        logger.info(
            f"User {user_id} successfully closed out from contract for book {book_id}"
        )
        return True
    except Exception as e:
        logger.error(f"Error closing out from contract: {e}")
        return False
