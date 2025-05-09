# services/explorer_service.py
import csv
import json
import logging
import time
import base64
from typing import Dict, Any, List

import config
from utils.algorand import (
    get_algod_client,
    get_indexer_client,
    get_contract_state,
    check_application_exists,
    format_global_state,
    decode_params,
)

logger = logging.getLogger(__name__)

# Ensure explorer directory exists
EXPLORER_DIR = config.DB_DIR / "explorer"
EXPLORER_DIR.mkdir(exist_ok=True)


def decode_base64_values(values_list):
    """Decode base64 values in a list."""
    decoded_values = []
    for value in values_list:
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            decoded_values.append(decoded)
        except:
            decoded_values.append(value)
    return decoded_values


def explore_contract(
    user_id: str,
    book_id: str,
    app_id: str,
    include_csv: bool = True,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Explore a contract and store detailed information.

    Args:
        user_id: User identifier
        book_id: Book identifier
        app_id: App identifier
        include_csv: Whether to generate CSV exports
        force: Whether to force a fresh exploration even if data already exists

    Returns:
        Dictionary with detailed contract information
    """
    # Look for the contract in the contracts directory
    contract_path = config.CONTRACTS_DIR / f"{user_id}_{book_id}_{app_id}_contract.json"

    if not contract_path.exists():
        logger.error(
            f"No contract found for user {user_id} and book {book_id} and app {app_id}"
        )
        return {}

    # Load the contract info
    with open(contract_path, "r") as f:
        contract_info = json.load(f)

    # Define both standard and app-specific paths
    app_specific_explorer_path = (
        EXPLORER_DIR / f"{user_id}_{book_id}_{app_id}_explorer.json"
    )

    # Check if we should skip exploration
    if not force and app_specific_explorer_path.exists():
        logger.info(
            f"Explorer data for app ID {app_id} already exists, loading from {app_specific_explorer_path}"
        )
        with open(app_specific_explorer_path, "r") as f:
            return json.load(f)

    # Prepare the explorer info
    explorer_info = {
        "user_id": user_id,
        "book_id": book_id,
        "app_id": app_id,
        "creation_timestamp": contract_info.get("creation_timestamp"),
        "exploration_timestamp": time.time(),
        "blockchain_status": "Unknown",
        "contract_info": contract_info,
        "global_state": {},
        "transaction_history": [],
        "participants": [],
    }

    # Get transaction history, regardless of whether contract still exists
    try:
        # Initialize indexer client
        indexer_client = get_indexer_client()

        # Log the attempt to get transactions
        logger.info(f"Querying indexer for transactions related to app ID {app_id}...")

        # Wait a moment to ensure indexer has caught up
        time.sleep(2)

        # Try multiple methods to get transactions
        transactions = []

        # Method 1: Try using application_id parameter
        try:
            logger.info("Method 1: Using application_id parameter...")
            response = indexer_client.transactions(application_id=app_id, limit=100)
            method1_count = len(response.get("transactions", []))
            logger.info(f"Method 1 found {method1_count} transactions")

            # Process these transactions
            for tx in response.get("transactions", []):
                if process_transaction(tx, transactions):
                    logger.info(f"Processed transaction {tx.get('id')}")
        except AttributeError:
            # Fall back to search_transactions if transactions method doesn't exist
            try:
                logger.info("Method 1 fallback: Using search_transactions...")
                response = indexer_client.search_transactions(
                    application_id=app_id, limit=100
                )
                method1fb_count = len(response.get("transactions", []))
                logger.info(f"Method 1 fallback found {method1fb_count} transactions")

                # Process these transactions
                for tx in response.get("transactions", []):
                    if process_transaction(tx, transactions):
                        logger.info(f"Processed transaction {tx.get('id')}")
            except Exception as e1fb:
                logger.error(f"Method 1 fallback error: {e1fb}")
        except Exception as e1:
            logger.error(f"Method 1 error: {e1}")

        # Method 2: Try using the app address
        if not transactions and "app_address" in contract_info:
            try:
                app_address = contract_info["app_address"]
                logger.info(f"Method 2: Using app address {app_address}...")
                response = indexer_client.transactions(address=app_address, limit=100)
                method2_count = len(response.get("transactions", []))
                logger.info(f"Method 2 found {method2_count} transactions")

                # Process these transactions
                for tx in response.get("transactions", []):
                    if process_transaction(tx, transactions):
                        logger.info(f"Processed transaction {tx.get('id')}")
            except AttributeError:
                # Fall back to search_transactions
                try:
                    logger.info(
                        f"Method 2 fallback: Using search_transactions with address..."
                    )
                    response = indexer_client.search_transactions(
                        address=app_address, limit=100
                    )
                    method2fb_count = len(response.get("transactions", []))
                    logger.info(
                        f"Method 2 fallback found {method2fb_count} transactions"
                    )

                    # Process these transactions
                    for tx in response.get("transactions", []):
                        if process_transaction(tx, transactions):
                            logger.info(f"Processed transaction {tx.get('id')}")
                except Exception as e2fb:
                    logger.error(f"Method 2 fallback error: {e2fb}")
            except Exception as e2:
                logger.error(f"Method 2 error: {e2}")

        # Method 3: Try searching by rounds if we know them
        if not transactions:
            try:
                # Get a rough range of rounds from creation timestamp
                creation_time = contract_info.get(
                    "creation_timestamp", time.time() - 3600
                )
                # Rough estimate - 10 rounds per second, look back 10 minutes
                current_time = time.time()
                time_diff = current_time - creation_time
                min_round = max(
                    1, int(200 - time_diff * 0.1)
                )  # Approximate starting round
                max_round = min_round + 500  # Look ahead 500 rounds

                logger.info(f"Method 3: Using round range {min_round}-{max_round}...")
                response = indexer_client.transactions(
                    min_round=min_round, max_round=max_round, limit=100
                )
                method3_count = len(response.get("transactions", []))
                logger.info(f"Method 3 found {method3_count} transactions")

                # Filter for relevant transactions (involving our app_id)
                for tx in response.get("transactions", []):
                    if (
                        tx.get("tx-type") == "appl"
                        and tx.get("application-transaction", {}).get("application-id")
                        == app_id
                    ):
                        if process_transaction(tx, transactions):
                            logger.info(f"Processed transaction {tx.get('id')}")
                    elif (
                        "app_address" in contract_info
                        and tx.get("sender") == contract_info["app_address"]
                    ):
                        if process_transaction(tx, transactions):
                            logger.info(f"Processed transaction {tx.get('id')}")
            except Exception as e3:
                logger.error(f"Method 3 error: {e3}")

        # Sort transactions by timestamp
        transactions.sort(key=lambda x: x.get("timestamp", 0) or 0)

        # Log the final count
        explorer_info["transaction_history"] = transactions
        logger.info(f"Found {len(transactions)} total transactions for app ID {app_id}")

        # Export transactions to CSV if requested
        if include_csv and transactions:
            # Define both standard and app-specific CSV paths
            app_specific_csv_path = (
                EXPLORER_DIR / f"{user_id}_{book_id}_{app_id}_transactions.csv"
            )

            # First, ensure all transactions have state tracking
            enhance_transactions_with_state(transactions)

            # Export to both paths
            for csv_path in [app_specific_csv_path]:
                with open(csv_path, "w", newline="") as csvfile:
                    # Use new columns based on state fields
                    fieldnames = [
                        "transaction_id",
                        "date",
                        "sender",
                        "action",
                        "g_user_id",
                        "g_book_id",
                        "g_address",
                        "g_status",
                        "g_params",
                        "l_book_hash",
                        "l_research_hash",
                        "l_params",
                    ]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()

                    for tx in transactions:
                        # Get the tracked state from the transaction
                        state = tx.get("tracked_state", {})
                        global_state = state.get("global_state", {})
                        local_state = state.get("local_state", {})

                        writer.writerow(
                            {
                                "transaction_id": tx.get("id"),
                                "date": tx.get("date"),
                                "sender": tx.get("sender"),
                                "action": tx.get("on_completion", "noop"),
                                "g_user_id": global_state.get("user_id", ""),
                                "g_book_id": global_state.get("book_id", ""),
                                "g_address": global_state.get("address", ""),
                                "g_status": global_state.get("status", ""),
                                "g_params": global_state.get("params", ""),
                                "l_book_hash": local_state.get("book_hash", ""),
                                "l_research_hash": local_state.get("research_hash", ""),
                                "l_params": local_state.get("params", ""),
                            }
                        )

            logger.info(f"Exported {len(transactions)} transactions to CSV files")
            explorer_info["csv_export_path"] = str(app_specific_csv_path)

    except Exception as e:
        logger.error(f"Error getting transaction history: {e}")

    # Check if the contract still exists on the blockchain
    contract_exists = check_application_exists(app_id)

    if contract_exists:
        explorer_info["blockchain_status"] = "Active"

        # Get global state
        try:
            global_state, raw_state = get_contract_state(app_id)
            explorer_info["global_state"] = global_state
            explorer_info["raw_global_state"] = raw_state
        except Exception as e:
            logger.error(f"Error getting global state: {e}")

        # Get participants
        try:
            indexer_client = get_indexer_client()

            # Try different methods to get participants
            participants = []

            try:
                # Try with the updated method name if available
                logger.info(f"Attempting to get participants with accounts method...")
                response = indexer_client.accounts(application_id=app_id, limit=10)
                accts_count = len(response.get("accounts", []))
                logger.info(f"Found {accts_count} participants with accounts method")
            except AttributeError:
                # Fall back to the old method name if the new one isn't available
                try:
                    logger.info(
                        f"Attempting to get participants with search_accounts method..."
                    )
                    response = indexer_client.search_accounts(
                        application_id=app_id, limit=10
                    )
                    accts_count = len(response.get("accounts", []))
                    logger.info(
                        f"Found {accts_count} participants with search_accounts method"
                    )
                except AttributeError:
                    logger.error(
                        "Error getting participants: 'IndexerClient' object has no attribute 'search_accounts' or 'accounts'"
                    )
                    response = {"accounts": []}

            for account in response.get("accounts", []):
                # Find this application's local state
                local_state = None
                for app_local_state in account.get("apps-local-state", []):
                    if app_local_state.get("id") == app_id:
                        # Format the local state
                        local_state_formatted = {}
                        for kv in app_local_state.get("key-value", []):
                            try:
                                key = base64.b64decode(kv["key"]).decode("utf-8")
                                value = kv["value"]

                                if value["type"] == 1:  # bytes
                                    value_bytes = base64.b64decode(value["bytes"])
                                    try:
                                        local_state_formatted[key] = value_bytes.decode(
                                            "utf-8"
                                        )
                                    except:
                                        try:
                                            local_state_formatted[key] = decode_params(
                                                value_bytes
                                            )
                                        except:
                                            local_state_formatted[key] = (
                                                value_bytes.hex()
                                            )
                                else:  # uint
                                    local_state_formatted[key] = value["uint"]
                            except Exception as e:
                                logger.warning(f"Error decoding local state: {e}")

                        local_state = {
                            "formatted": local_state_formatted,
                            "raw": app_local_state.get("key-value", []),
                        }
                        break

                participant = {
                    "address": account.get("address"),
                    "opted_in": local_state is not None,
                    "local_state": local_state,
                    "amount": account.get("amount"),
                }

                participants.append(participant)

            explorer_info["participants"] = participants
        except Exception as e:
            logger.error(f"Error getting participants: {e}")
    else:
        explorer_info["blockchain_status"] = "Deleted"
        explorer_info["deletion_note"] = "Contract no longer exists on the blockchain"

        # Check if we had previously recorded the global state
        if app_specific_explorer_path.exists():
            try:
                with open(app_specific_explorer_path, "r") as f:
                    previous_data = json.load(f)

                # Preserve global state from previous exploration
                if previous_data.get("global_state"):
                    explorer_info["global_state"] = previous_data["global_state"]
                    explorer_info["preserved_global_state_note"] = (
                        "Retrieved from previous exploration before deletion"
                    )

                if previous_data.get("raw_global_state"):
                    explorer_info["raw_global_state"] = previous_data[
                        "raw_global_state"
                    ]
            except Exception as e:
                logger.error(f"Error retrieving previous explorer data: {e}")

    # Save the explorer info to both paths
    with open(app_specific_explorer_path, "w") as f:
        json.dump(explorer_info, f, indent=2)

    logger.info(f"Saved explorer information to {app_specific_explorer_path}")
    return explorer_info


def process_transaction(tx: Dict[str, Any], transactions: List[Dict[str, Any]]) -> bool:
    """Process a transaction and add it to the transactions list if it's an application transaction.

    Args:
        tx: The transaction to process
        transactions: The list to add the processed transaction to

    Returns:
        True if the transaction was processed and added, False otherwise
    """
    try:
        tx_type = tx.get("tx-type")
        if tx_type == "appl":  # Application transaction
            # Extract application arguments
            app_args = []
            for arg in tx.get("application-transaction", {}).get(
                "application-args", []
            ):
                try:
                    decoded_arg = base64.b64decode(arg).decode("utf-8")
                    app_args.append(decoded_arg)
                except:
                    try:
                        # Just show the first few bytes as hex
                        decoded_hex = base64.b64decode(arg).hex()[:20] + "..."
                        app_args.append(decoded_hex)
                    except:
                        app_args.append(arg)

            # Get on-completion action
            on_completion = tx.get("application-transaction", {}).get("on-completion")

            # Process global state delta
            global_delta = {}
            for delta in tx.get("global-state-delta", []):
                try:
                    key = base64.b64decode(delta.get("key")).decode("utf-8")
                    if delta.get("value", {}).get("type") == 1:  # Bytes
                        try:
                            value = base64.b64decode(
                                delta.get("value", {}).get("bytes")
                            ).decode("utf-8")
                        except:
                            value = base64.b64decode(
                                delta.get("value", {}).get("bytes")
                            ).hex()
                    else:  # UInt
                        value = str(delta.get("value", {}).get("uint", 0))
                    global_delta[key] = value
                except Exception as e:
                    logger.error(f"Error processing global delta: {e}")

            # Process local state delta
            local_delta = {}
            for account_delta in tx.get("local-state-delta", []):
                addr = account_delta.get("address")
                delta_values = {}
                for delta in account_delta.get("delta", []):
                    try:
                        key = base64.b64decode(delta.get("key")).decode("utf-8")
                        if delta.get("value", {}).get("type") == 1:  # Bytes
                            try:
                                value = base64.b64decode(
                                    delta.get("value", {}).get("bytes")
                                ).decode("utf-8")
                            except:
                                value = base64.b64decode(
                                    delta.get("value", {}).get("bytes")
                                ).hex()
                        else:  # UInt
                            value = str(delta.get("value", {}).get("uint", 0))
                        delta_values[key] = value
                    except Exception as e:
                        logger.error(f"Error processing local delta: {e}")
                local_delta[addr] = delta_values

            transaction = {
                "id": tx.get("id"),
                "sender": tx.get("sender"),
                "timestamp": tx.get("round-time"),
                "date": (
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(tx.get("round-time"))
                    )
                    if tx.get("round-time")
                    else None
                ),
                "round": tx.get("confirmed-round"),
                "app_args": app_args,
                "on_completion": on_completion,
                "global_delta": global_delta,
                "local_delta": local_delta,
                "accounts": tx.get("application-transaction", {}).get("accounts", []),
                "raw_tx": tx,  # Keep the raw transaction for complete information
            }

            # Check if we already have this transaction
            if not any(existing.get("id") == tx.get("id") for existing in transactions):
                transactions.append(transaction)
                return True
    except Exception as e:
        logger.error(f"Error processing transaction: {e}")

    return False


def enhance_transactions_with_state(transactions: List[Dict[str, Any]]) -> None:
    """
    Enhance transactions with cumulative state tracking using deltas.
    """
    logger.info(f"Starting state tracking for {len(transactions)} transactions")

    # Initialize state tracking
    current_global_state = {
        "user_id": "",
        "book_id": "",
        "address": "",
        "status": "",
        "params": "",
    }

    # Local state tracking per address
    current_local_states = {}  # address -> {key: value}

    # Process transactions in chronological order
    for tx_idx, tx in enumerate(transactions):
        logger.debug(
            f"Processing transaction {tx_idx+1}/{len(transactions)}: {tx.get('id', 'unknown')}"
        )

        # Process global state delta
        if "raw_tx" in tx and "global-state-delta" in tx["raw_tx"]:
            logger.debug(
                f"Transaction has global state delta with {len(tx['raw_tx']['global-state-delta'])} items"
            )
            for delta in tx["raw_tx"]["global-state-delta"]:
                try:
                    # Decode the key
                    key_b64 = delta["key"]
                    key = base64.b64decode(key_b64).decode("utf-8")

                    logger.debug(f"Processing global state key: {key}")

                    # Skip keys not in our tracking
                    if key not in current_global_state:
                        logger.debug(
                            f"Key {key} not in global state tracking, skipping"
                        )
                        continue

                    # Process the value based on action
                    value_obj = delta["value"]
                    if "action" not in value_obj:
                        logger.warning(f"Missing 'action' in value object: {value_obj}")
                        continue

                    if value_obj["action"] == 1:  # Update
                        # Check if it has bytes (it's a string/bytes value)
                        if "bytes" in value_obj:
                            # Use the decode_base64_values function
                            decoded_values = decode_base64_values([value_obj["bytes"]])
                            decoded_value = decoded_values[0] if decoded_values else ""

                            # Special handling for address
                            if key == "address" and len(decoded_value) != len(
                                base64.b64decode(value_obj["bytes"]).decode(
                                    "utf-8", errors="ignore"
                                )
                            ):
                                try:
                                    addr_bytes = base64.b64decode(value_obj["bytes"])
                                    if len(addr_bytes) == 32:
                                        from algosdk import encoding

                                        decoded_value = encoding.encode_address(
                                            addr_bytes
                                        )
                                        logger.debug(
                                            f"Decoded address: {decoded_value}"
                                        )
                                except Exception as e:
                                    logger.warning(f"Failed to decode address: {e}")

                            logger.debug(f"Decoded {key} value: {decoded_value}")
                            current_global_state[key] = decoded_value
                        # Check if it has uint (it's an integer value)
                        elif "uint" in value_obj:
                            uint_value = str(value_obj["uint"])
                            logger.debug(f"Using uint value for {key}: {uint_value}")
                            current_global_state[key] = uint_value
                        else:
                            logger.warning(
                                f"Value object has neither bytes nor uint: {value_obj}"
                            )
                    elif value_obj["action"] == 2:  # Delete
                        logger.debug(f"Deleting value for key {key}")
                        current_global_state[key] = ""
                except Exception as e:
                    logger.error(
                        f"Error processing global state delta: {e}", exc_info=True
                    )

        # Process local state delta
        if "raw_tx" in tx and "local-state-delta" in tx["raw_tx"]:
            logger.debug(
                f"Transaction has local state delta with {len(tx['raw_tx']['local-state-delta'])} accounts"
            )
            try:
                for account_delta in tx["raw_tx"]["local-state-delta"]:
                    addr = account_delta["address"]
                    logger.debug(f"Processing local state for address: {addr}")

                    # Initialize local state for this address if not exists
                    if addr not in current_local_states:
                        logger.debug(f"Initializing local state for address: {addr}")
                        current_local_states[addr] = {
                            "book_hash": "",
                            "research_hash": "",
                            "params": "",
                        }

                    # Update local state based on deltas
                    for delta in account_delta.get("delta", []):
                        try:
                            key_b64 = delta["key"]
                            key = base64.b64decode(key_b64).decode("utf-8")

                            logger.debug(f"Processing local state key: {key}")

                            # Skip keys not in our tracking
                            if key not in current_local_states[addr]:
                                logger.debug(
                                    f"Key {key} not in local state tracking for {addr}, skipping"
                                )
                                continue

                            # Process value based on action
                            value_obj = delta["value"]
                            if "action" not in value_obj:
                                logger.warning(
                                    f"Missing 'action' in local value object: {value_obj}"
                                )
                                continue

                            if value_obj["action"] == 1:  # Update
                                # Check for bytes value
                                if "bytes" in value_obj:
                                    # Use the decode_base64_values function
                                    decoded_values = decode_base64_values(
                                        [value_obj["bytes"]]
                                    )
                                    decoded_value = (
                                        decoded_values[0] if decoded_values else ""
                                    )

                                    logger.debug(
                                        f"Decoded local {key} value: {decoded_value}"
                                    )
                                    current_local_states[addr][key] = decoded_value
                                # Check for uint value
                                elif "uint" in value_obj:
                                    uint_value = str(value_obj["uint"])
                                    logger.debug(
                                        f"Using local uint value for {key}: {uint_value}"
                                    )
                                    current_local_states[addr][key] = uint_value
                                else:
                                    logger.warning(
                                        f"Local value object has neither bytes nor uint: {value_obj}"
                                    )
                            elif value_obj["action"] == 2:  # Delete
                                logger.debug(f"Deleting local value for key {key}")
                                current_local_states[addr][key] = ""
                        except Exception as e:
                            logger.error(
                                f"Error processing local state delta item: {e}",
                                exc_info=True,
                            )
            except Exception as e:
                logger.error(f"Error processing local state delta: {e}", exc_info=True)

        # Handle OptIn and CloseOut cases from on_completion
        on_completion = tx.get("on_completion")
        sender = tx.get("sender")

        if on_completion == "optin" and sender not in current_local_states:
            logger.debug(f"OptIn operation for {sender}, initializing local state")
            current_local_states[sender] = {
                "book_hash": "NAN",
                "research_hash": "NAN",
                "params": "NAN",
            }
        elif on_completion == "closeout" and sender in current_local_states:
            logger.debug(f"CloseOut operation for {sender}, clearing local state")
            current_local_states[sender] = {
                "book_hash": "",
                "research_hash": "",
                "params": "",
            }

        # Save the current state to the transaction
        tx["tracked_state"] = {
            "global_state": current_global_state.copy(),
            "local_state": current_local_states.get(sender, {}).copy(),
        }
        logger.debug(f"Updated tracked state for transaction {tx.get('id', 'unknown')}")

    logger.info(f"Completed state tracking for {len(transactions)} transactions")
