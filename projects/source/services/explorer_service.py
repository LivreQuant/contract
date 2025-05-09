# services/explorer_service.py
import csv
import json
import logging
import time
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional

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
    user_id: str, book_id: str, include_csv: bool = True
) -> Dict[str, Any]:
    """
    Explore a contract and store detailed information.

    Args:
        user_id: User identifier
        book_id: Book identifier
        include_csv: Whether to generate CSV exports

    Returns:
        Dictionary with detailed contract information
    """
    # Look for the contract in the contracts directory
    contract_path = config.CONTRACTS_DIR / f"{user_id}_{book_id}_contract.json"

    if not contract_path.exists():
        logger.error(f"No contract found for user {user_id} and book {book_id}")
        return {}

    # Load the contract info
    with open(contract_path, "r") as f:
        contract_info = json.load(f)

    app_id = contract_info.get("app_id")
    if not app_id:
        logger.error(
            f"Invalid contract info for user {user_id} and book {book_id}: missing app_id"
        )
        return {}

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
        "participants": [],
    }

    # Export paths
    csv_path = EXPLORER_DIR / f"{user_id}_{book_id}_transactions.csv"
    detailed_csv_path = EXPLORER_DIR / f"{user_id}_{book_id}_detailed_transactions.csv"
    explorer_info["transactions_csv_path"] = str(csv_path)
    explorer_info["detailed_transactions_csv_path"] = str(detailed_csv_path)

    # Get transaction history, regardless of whether contract still exists
    try:
        indexer_client = get_indexer_client()
        response = indexer_client.search_transactions(application_id=app_id, limit=100)

        # Initialize state tracking
        cumulative_global_state = {}
        cumulative_local_states = {}  # address -> state

        # First, try to get the current state if the contract exists
        # This will help us interpret the deltas correctly
        current_contract_exists = check_application_exists(app_id)
        if current_contract_exists:
            try:
                current_state, raw_state = get_contract_state(app_id)

                # Initialize our cumulative state with properly formatted values from real state
                for key, value in current_state.items():
                    # Extract the actual value part (after the type prefix)
                    if isinstance(value, str):
                        if ": " in value:
                            actual_value = value.split(": ", 1)[1]
                            cumulative_global_state[key] = actual_value
                        else:
                            cumulative_global_state[key] = value
                    else:
                        cumulative_global_state[key] = value

                logger.info(
                    f"Initialized global state from current state: {cumulative_global_state}"
                )
            except Exception as e:
                logger.error(f"Error getting current state: {e}")

        # Initialize CSV writers if needed
        if include_csv:
            # Create directories if needed
            EXPLORER_DIR.mkdir(exist_ok=True)

            # Standard CSV
            standard_csv_file = open(csv_path, "w", newline="")
            standard_csv_writer = csv.DictWriter(
                standard_csv_file,
                fieldnames=[
                    "transaction_id",
                    "date",
                    "round",
                    "sender",
                    "action",
                    "global_delta",
                    "local_delta",
                    "app_args",
                    "current_global_state",
                    "current_local_state",
                ],
            )
            standard_csv_writer.writeheader()

            # Detailed CSV
            detailed_csv_file = open(detailed_csv_path, "w", newline="")
            detailed_csv_writer = csv.writer(detailed_csv_file)
            detailed_csv_writer.writerow(
                [
                    "Transaction ID",
                    "Date",
                    "Round",
                    "Sender",
                    "Action",
                    "Global State After Transaction",
                    "All Local States After Transaction",
                ]
            )

        tx_count = 0

        # Sort transactions by confirmed round
        transactions = response.get("transactions", [])
        sorted_txs = sorted(
            transactions,
            key=lambda x: (x.get("confirmed-round", 0), x.get("intra-round-offset", 0)),
        )

        # If the contract was created recently and we're not seeing the full history,
        # start with baseline state from the contract info
        if not current_contract_exists or len(sorted_txs) == 0:
            # Initialize with contract info as a fallback
            if not cumulative_global_state.get("user_id"):
                cumulative_global_state["user_id"] = contract_info.get("user_id", "")
            if not cumulative_global_state.get("book_id"):
                cumulative_global_state["book_id"] = contract_info.get("book_id", "")
            if not cumulative_global_state.get("params"):
                cumulative_global_state["params"] = contract_info.get("parameters", "")
            if not cumulative_global_state.get("address"):
                cumulative_global_state["address"] = contract_info.get(
                    "user_address", ""
                )
            if not cumulative_global_state.get("status"):
                cumulative_global_state["status"] = contract_info.get(
                    "status", "ACTIVE"
                )

        # Process transactions
        for tx in sorted_txs:
            tx_type = tx.get("tx-type")
            if tx_type == "appl":  # Application transaction
                tx_count += 1

                # Extract application arguments
                app_args = []
                for arg in tx.get("application-transaction", {}).get(
                    "application-args", []
                ):
                    try:
                        # Try to decode as UTF-8 first
                        decoded_arg = base64.b64decode(arg).decode("utf-8")
                        app_args.append(decoded_arg)
                    except:
                        try:
                            # Show as hex if UTF-8 fails
                            decoded_hex = base64.b64decode(arg).hex()[:20] + "..."
                            app_args.append(decoded_hex)
                        except:
                            app_args.append(arg)

                # Get on-completion action
                on_completion = tx.get("application-transaction", {}).get(
                    "on-completion"
                )

                # Process global state delta
                global_delta = {}
                for delta in tx.get("global-state-delta", []):
                    try:
                        key = base64.b64decode(delta.get("key")).decode("utf-8")

                        # Handle different delta actions
                        action = delta.get(
                            "action", 1
                        )  # Default to update if not specified

                        if action == 2:  # Delete
                            if key in cumulative_global_state:
                                del cumulative_global_state[key]
                            global_delta[key] = "DELETED"
                        else:  # Update or insert
                            value_obj = delta.get("value", {})
                            if value_obj.get("type") == 1:  # Bytes
                                try:
                                    raw_bytes = base64.b64decode(
                                        value_obj.get("bytes", "")
                                    )
                                    value = raw_bytes.decode("utf-8")
                                except:
                                    # If decoding fails, try to show as hex
                                    value = base64.b64decode(
                                        value_obj.get("bytes", "")
                                    ).hex()
                            else:  # UInt
                                value = str(value_obj.get("uint", 0))

                            # Update global delta and cumulative state
                            global_delta[key] = value
                            cumulative_global_state[key] = value
                    except Exception as e:
                        logger.error(f"Error processing global delta: {e}")

                # Process local state delta
                local_delta = {}
                for account_delta in tx.get("local-state-delta", []):
                    addr = account_delta.get("address")

                    # Initialize address in cumulative state if not present
                    if addr not in cumulative_local_states:
                        cumulative_local_states[addr] = {}

                    delta_values = {}
                    for delta in account_delta.get("delta", []):
                        try:
                            key = base64.b64decode(delta.get("key")).decode("utf-8")

                            # Handle different delta actions
                            action = delta.get(
                                "action", 1
                            )  # Default to update if not specified

                            if action == 2:  # Delete
                                if key in cumulative_local_states[addr]:
                                    del cumulative_local_states[addr][key]
                                delta_values[key] = "DELETED"
                            else:  # Update or insert
                                value_obj = delta.get("value", {})
                                if value_obj.get("type") == 1:  # Bytes
                                    try:
                                        raw_bytes = base64.b64decode(
                                            value_obj.get("bytes", "")
                                        )
                                        value = raw_bytes.decode("utf-8")
                                    except:
                                        # If decoding fails, try to show as hex
                                        value = base64.b64decode(
                                            value_obj.get("bytes", "")
                                        ).hex()
                                else:  # UInt
                                    value = str(value_obj.get("uint", 0))

                                # Update local delta and cumulative state
                                delta_values[key] = value
                                cumulative_local_states[addr][key] = value
                        except Exception as e:
                            logger.error(f"Error processing local delta: {e}")

                    local_delta[addr] = delta_values

                # If this is a closeout or clear state transaction, remove the address
                if (
                    on_completion in ["CloseOut", "ClearState"]
                    and tx.get("sender") in cumulative_local_states
                ):
                    del cumulative_local_states[tx.get("sender")]

                # Make copies of current cumulative state for this transaction
                current_global_state = copy.deepcopy(cumulative_global_state)
                current_local_states = copy.deepcopy(cumulative_local_states)

                # Get current local state for the sender
                sender = tx.get("sender")
                current_local_state = current_local_states.get(sender, {})

                # Format date
                tx_date = (
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(tx.get("round-time"))
                    )
                    if tx.get("round-time")
                    else "Unknown"
                )

                # Write to CSVs if requested
                if include_csv:
                    # Standard CSV
                    standard_csv_writer.writerow(
                        {
                            "transaction_id": tx.get("id"),
                            "date": tx_date,
                            "round": tx.get("confirmed-round"),
                            "sender": sender,
                            "action": on_completion or "NoOp",
                            "global_delta": json.dumps(global_delta),
                            "local_delta": json.dumps(local_delta),
                            "app_args": json.dumps(app_args),
                            "current_global_state": json.dumps(current_global_state),
                            "current_local_state": json.dumps(current_local_state),
                        }
                    )

                    # Detailed CSV
                    detailed_csv_writer.writerow(
                        [
                            tx.get("id"),
                            tx_date,
                            tx.get("confirmed-round"),
                            sender,
                            on_completion or "NoOp",
                            json.dumps(current_global_state, indent=2),
                            json.dumps(current_local_states, indent=2),
                        ]
                    )

                    # Log the state after specific operations to help with debugging
                    if (
                        tx_count <= 5
                    ):  # Only log first few transactions to avoid verbosity
                        logger.info(
                            f"Transaction {tx.get('id')} (round {tx.get('confirmed-round')}): action={on_completion or 'NoOp'}"
                        )
                        logger.info(
                            f"Global state after transaction: {current_global_state}"
                        )
                        if sender in current_local_states:
                            logger.info(
                                f"Local state for {sender}: {current_local_states[sender]}"
                            )

        # Close CSV files if they were opened
        if include_csv:
            standard_csv_file.close()
            detailed_csv_file.close()

        # Add transaction count and final states to explorer info
        explorer_info["transaction_count"] = tx_count
        explorer_info["final_global_state"] = cumulative_global_state
        explorer_info["final_local_states"] = cumulative_local_states

        logger.info(f"Processed {tx_count} transactions for contract {app_id}")
        logger.info(f"Final global state: {cumulative_global_state}")

    except Exception as e:
        logger.error(f"Error getting transaction history: {e}")
        logger.exception(e)

    # Check if the contract still exists on the blockchain
    contract_exists = check_application_exists(app_id)

    if contract_exists:
        explorer_info["blockchain_status"] = "Active"

        # Get current global state
        try:
            global_state, raw_state = get_contract_state(app_id)
            explorer_info["global_state"] = global_state
            explorer_info["raw_global_state"] = raw_state
        except Exception as e:
            logger.error(f"Error getting global state: {e}")

        # Get participants
        try:
            indexer_client = get_indexer_client()

            # Check if the search_accounts method exists
            if hasattr(indexer_client, "search_accounts"):
                response = indexer_client.search_accounts(
                    application_id=app_id, limit=10
                )

                participants = []
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
                                            local_state_formatted[key] = (
                                                value_bytes.decode("utf-8")
                                            )
                                        except:
                                            try:
                                                local_state_formatted[key] = (
                                                    decode_params(value_bytes)
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
            else:
                logger.warning(
                    "Indexer client does not have search_accounts method, skipping participants retrieval"
                )
                explorer_info["participants_error"] = (
                    "Indexer client does not support search_accounts method"
                )
        except Exception as e:
            logger.error(f"Error getting participants: {e}")
    else:
        explorer_info["blockchain_status"] = "Deleted"
        explorer_info["deletion_note"] = "Contract no longer exists on the blockchain"

        # Check if we had previously recorded the global state
        explorer_path = EXPLORER_DIR / f"{user_id}_{book_id}_explorer.json"
        if explorer_path.exists():
            try:
                with open(explorer_path, "r") as f:
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

    # If we couldn't get state from blockchain but have a final state from tx history
    if not explorer_info.get("global_state") and explorer_info.get(
        "final_global_state"
    ):
        explorer_info["global_state"] = explorer_info["final_global_state"]
        explorer_info["state_source"] = "transaction_history"

    # Save the explorer info
    explorer_path = EXPLORER_DIR / f"{user_id}_{book_id}_explorer.json"
    with open(explorer_path, "w") as f:
        json.dump(explorer_info, f, indent=2)

    logger.info(f"Saved explorer information to {explorer_path}")

    # Add transaction history file references
    explorer_info["transactions_csv_exists"] = csv_path.exists()
    explorer_info["detailed_transactions_csv_exists"] = detailed_csv_path.exists()

    return explorer_info
