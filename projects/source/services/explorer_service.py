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
        "transaction_history": [],
        "participants": [],
    }

    # Get transaction history, regardless of whether contract still exists
    try:
        indexer_client = get_indexer_client()
        response = indexer_client.search_transactions(application_id=app_id, limit=100)

        # Process transactions
        transactions = []
        for tx in response.get("transactions", []):
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
                on_completion = tx.get("application-transaction", {}).get(
                    "on-completion"
                )

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
                    "accounts": tx.get("application-transaction", {}).get(
                        "accounts", []
                    ),
                    "raw_tx": tx,  # Keep the raw transaction for complete information
                }
                transactions.append(transaction)

        explorer_info["transaction_history"] = transactions

        # Export transactions to CSV if requested
        if include_csv and transactions:
            csv_path = EXPLORER_DIR / f"{user_id}_{book_id}_transactions.csv"

            with open(csv_path, "w", newline="") as csvfile:
                fieldnames = [
                    "transaction_id",
                    "date",
                    "sender",
                    "action",
                    "global_delta",
                    "local_delta",
                    "app_args",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for tx in transactions:
                    writer.writerow(
                        {
                            "transaction_id": tx.get("id"),
                            "date": tx.get("date"),
                            "sender": tx.get("sender"),
                            "action": tx.get("on_completion", "NoOp"),
                            "global_delta": json.dumps(tx.get("global_delta", {})),
                            "local_delta": json.dumps(tx.get("local_delta", {})),
                            "app_args": json.dumps(tx.get("app_args", [])),
                        }
                    )

            logger.info(f"Exported {len(transactions)} transactions to {csv_path}")
            explorer_info["csv_export_path"] = str(csv_path)

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
            response = indexer_client.search_accounts(application_id=app_id, limit=10)

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

    # Save the explorer info
    explorer_path = EXPLORER_DIR / f"{user_id}_{book_id}_explorer.json"
    with open(explorer_path, "w") as f:
        json.dump(explorer_info, f, indent=2)

    logger.info(f"Saved explorer information to {explorer_path}")
    return explorer_info
