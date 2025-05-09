# utils/explorer.py - Contract explorer utility functions

import base64
import logging
import datetime
import json
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate

from utils.algorand import (
    get_algod_client,
    get_indexer_client,
    decode_params,
    format_global_state,
)

# Configure logging
logger = logging.getLogger("explorer_utils")


def get_transaction_history(app_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get transaction history for a contract.

    Args:
        app_id: Application ID
        limit: Maximum number of transactions to retrieve

    Returns:
        List of transaction dictionaries
    """
    # Initialize indexer client
    indexer_client = get_indexer_client()

    try:
        # Search for transactions involving the application
        response = indexer_client.search_transactions(
            application_id=app_id, limit=limit
        )

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
                        app_args.append(base64.b64decode(arg).hex())

                # Create transaction record
                transaction = {
                    "id": tx["id"],
                    "sender": tx["sender"],
                    "timestamp": tx.get("round-time"),
                    "date": (
                        datetime.datetime.fromtimestamp(tx.get("round-time")).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        if tx.get("round-time")
                        else None
                    ),
                    "type": tx_type,
                    "application_id": tx.get("application-transaction", {}).get(
                        "application-id"
                    ),
                    "on_completion": tx.get("application-transaction", {}).get(
                        "on-completion"
                    ),
                    "app_args": app_args,
                    "global_state_delta": tx.get("global-state-delta"),
                    "local_state_delta": tx.get("local-state-delta"),
                    "confirmed_round": tx.get("confirmed-round"),
                }

                transactions.append(transaction)

        # Sort transactions by timestamp
        transactions.sort(key=lambda x: x.get("timestamp", 0) or 0)

        return transactions

    except Exception as e:
        logger.error(f"Error getting transaction history: {e}")
        return []


def get_participants(app_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get participants (accounts that have opted in) for a contract.

    Args:
        app_id: Application ID
        limit: Maximum number of accounts to retrieve

    Returns:
        List of participants
    """
    # Initialize indexer client
    indexer_client = get_indexer_client()

    try:
        # Search for accounts that have opted in to the application
        response = indexer_client.accounts(application_id=app_id, limit=limit)

        # Process accounts
        participants = []
        for account in response.get("accounts", []):
            # Find this application's local state
            local_state = None
            for app_local_state in account.get("apps-local-state", []):
                if app_local_state.get("id") == app_id:
                    local_state = {}
                    for kv in app_local_state.get("key-value", []):
                        try:
                            key = base64.b64decode(kv["key"]).decode("utf-8")

                            # Decode the value
                            value = kv["value"]
                            if value["type"] == 1:  # bytes
                                value_bytes = base64.b64decode(value["bytes"])
                                try:
                                    local_state[key] = value_bytes.decode("utf-8")
                                except:
                                    # Try to decode as parameters
                                    try:
                                        local_state[key] = decode_params(value_bytes)
                                    except:
                                        local_state[key] = value_bytes.hex()
                            else:  # uint
                                local_state[key] = value["uint"]

                        except Exception as e:
                            logger.warning(
                                f"Error decoding participant local state: {e}"
                            )
                    break

            # Create participant record
            participant = {
                "address": account["address"],
                "opted_in_at_round": None,  # Would need to search transactions to find this
                "opted_out": local_state is None,
                "local_state": local_state or {},
            }

            participants.append(participant)

        return participants

    except Exception as e:
        logger.error(f"Error getting participants: {e}")
        return []


def get_contract_info(app_id: int) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a contract.

    Args:
        app_id: Application ID

    Returns:
        Contract information dictionary
    """
    # Initialize Algorand client
    algod_client = get_algod_client()

    try:
        # Get application information
        app_info = algod_client.application_info(app_id)

        # Prepare contract information dictionary
        contract_info = {
            "app_id": app_id,
            "creator": app_info["params"]["creator"],
            "app_address": algosdk.logic.get_application_address(app_id),
            "approval_program": base64.b64decode(
                app_info["params"]["approval-program"]
            ).hex(),
            "clear_program": base64.b64decode(
                app_info["params"]["clear-state-program"]
            ).hex(),
            "global_state_schema": {
                "num_byte_slices": app_info["params"]["global-state-schema"][
                    "num-byte-slice"
                ],
                "num_uints": app_info["params"]["global-state-schema"]["num-uint"],
            },
            "local_state_schema": {
                "num_byte_slices": app_info["params"]["local-state-schema"][
                    "num-byte-slice"
                ],
                "num_uints": app_info["params"]["local-state-schema"]["num-uint"],
            },
            "created_at_round": app_info["created-at-round"],
            "deleted": app_info.get("deleted", False),
            "global_state": {},
        }

        # Process global state
        global_state = app_info["params"].get("global-state", [])
        contract_info["global_state"] = format_global_state(global_state)

        return contract_info

    except Exception as e:
        logger.error(f"Error getting contract info: {e}")
        return None


def analyze_parameter_changes(
    transactions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Analyze changes to contract parameters over time.

    Args:
        transactions: Transaction history

    Returns:
        List of parameter change records
    """
    param_changes = []

    for tx in transactions:
        # Check if this is an update_params or update_global transaction
        if (
            tx.get("app_args")
            and len(tx.get("app_args", [])) > 0
            and (
                tx.get("app_args")[0] == "update_params"
                or "update_global" in tx.get("app_args")[0]
            )
        ):
            # For global state delta, look for params changes
            if tx.get("global_state_delta"):
                for change in tx.get("global_state_delta"):
                    try:
                        key_bytes = base64.b64decode(change["key"])
                        key = key_bytes.decode("utf-8")

                        if key == "params" and "value" in change:
                            value = change["value"]
                            if value["type"] == 1:  # bytes
                                params_bytes = base64.b64decode(value["bytes"])
                                try:
                                    params_str = params_bytes.decode("utf-8")

                                    # Create parameter change record
                                    change_record = {
                                        "timestamp": tx.get("timestamp"),
                                        "date": tx.get("date"),
                                        "sender": tx.get("sender"),
                                        "raw_params": params_str,
                                        "transaction_id": tx.get("id"),
                                    }

                                    # Try to parse parameters
                                    if "|" in params_str and ":" in params_str:
                                        params_dict = {}
                                        for pair in params_str.split("|"):
                                            if ":" in pair:
                                                k, v = pair.split(":", 1)
                                                params_dict[k] = v
                                        change_record["parsed_params"] = params_dict

                                    param_changes.append(change_record)
                                except:
                                    pass
                    except:
                        pass

    return param_changes


def generate_activity_chart(
    transactions: List[Dict[str, Any]], output_file: Optional[str] = None
) -> None:
    """
    Generate a chart showing contract activity over time.

    Args:
        transactions: Transaction history
        output_file: Optional file to save the chart to
    """
    # Extract timestamps
    timestamps = [tx.get("timestamp") for tx in transactions if tx.get("timestamp")]

    if not timestamps:
        logger.warning("No timestamp data available for chart generation")
        return

    # Convert timestamps to dates
    dates = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]

    # Group by day
    date_counts = {}
    for date in dates:
        date_str = date.strftime("%Y-%m-%d")
        date_counts[date_str] = date_counts.get(date_str, 0) + 1

    # Create dataframe for plotting
    df = pd.DataFrame(list(date_counts.items()), columns=["Date", "Transactions"])
    df["Date"] = pd.to_datetime(df["Date"])
    df = df.sort_values("Date")

    # Create plot
    plt.figure(figsize=(12, 6))
    plt.bar(df["Date"], df["Transactions"], width=0.8)
    plt.title(
        f"Contract Activity Over Time (App ID: {transactions[0].get('application_id')})"
    )
    plt.xlabel("Date")
    plt.ylabel("Number of Transactions")
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()

    if output_file:
        plt.savefig(output_file)
        logger.info(f"Chart saved to {output_file}")
    else:
        plt.show()


def search_contracts_by_address(address: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Search for contracts created by a specific address.

    Args:
        address: Creator address
        limit: Maximum number of contracts to retrieve

    Returns:
        List of contracts
    """
    # Initialize indexer client
    indexer_client = get_indexer_client()

    try:
        # Search for applications created by the address
        response = indexer_client.search_applications(creator=address, limit=limit)

        # Process applications
        contracts = []
        for app in response.get("applications", []):
            contract = {
                "app_id": app["id"],
                "created_at_round": app.get("created-at-round"),
                "deleted": app.get("deleted", False),
                "global_state": {},
            }

            # Add global state if available
            global_state = app.get("params", {}).get("global-state", [])
            contract["global_state"] = format_global_state(global_state)

            contracts.append(contract)

        return contracts

    except Exception as e:
        logger.error(f"Error searching contracts: {e}")
        return []


def export_transaction_state_changes_to_csv(
    app_id: int, output_file: Optional[str] = None
) -> Optional[str]:
    """
    Export all transactions with their global and local state changes to a CSV file.

    Args:
        app_id: Application ID
        output_file: Output CSV file path (default: app_{app_id}_state_changes.csv)

    Returns:
        Path to the CSV file or None if error
    """
    if output_file is None:
        output_file = f"app_{app_id}_state_changes.csv"

    # Initialize clients
    algod_client = get_algod_client()
    indexer_client = get_indexer_client()

    # Get transaction history
    transactions = get_transaction_history(
        app_id, limit=1000
    )  # Get up to 1000 transactions

    # Initialize a list to store all rows
    rows = []

    # Get initial global state to identify schema
    try:
        app_info = algod_client.application_info(app_id)
        initial_global_state = {}
        global_state_keys = []

        for item in app_info["params"].get("global-state", []):
            try:
                key = base64.b64decode(item["key"]).decode("utf-8")

                # Decode the value
                value = item["value"]
                if value["type"] == 1:  # bytes
                    value_bytes = base64.b64decode(value["bytes"])
                    try:
                        initial_global_state[key] = value_bytes.decode("utf-8")
                    except:
                        # Try to decode as parameters
                        try:
                            initial_global_state[key] = decode_params(value_bytes)
                        except:
                            initial_global_state[key] = value_bytes.hex()
                else:  # uint
                    initial_global_state[key] = value["uint"]

                global_state_keys.append(key)
            except Exception as e:
                logger.warning(f"Error decoding initial global state key: {e}")
    except Exception as e:
        logger.warning(f"Error getting initial app info: {e}")
        # App might be deleted
        initial_global_state = {}
        global_state_keys = []

    # Get local state keys from participants
    try:
        response = indexer_client.accounts(application_id=app_id, limit=1)
        local_state_keys = []

        for account in response.get("accounts", []):
            for app_local_state in account.get("apps-local-state", []):
                if app_local_state.get("id") == app_id:
                    for kv in app_local_state.get("key-value", []):
                        try:
                            key = base64.b64decode(kv["key"]).decode("utf-8")
                            if key not in local_state_keys:
                                local_state_keys.append(key)
                        except Exception as e:
                            logger.warning(f"Error decoding local state key: {e}")
                    break
    except Exception as e:
        logger.warning(f"Error getting local state keys: {e}")
        local_state_keys = []

    # If we couldn't get keys from current state, let's try to infer from transactions
    if not global_state_keys or not local_state_keys:
        for tx in transactions:
            # Try to infer global state keys
            if tx.get("global_state_delta"):
                for change in tx.get("global_state_delta"):
                    try:
                        key = base64.b64decode(change["key"]).decode("utf-8")
                        if key not in global_state_keys:
                            global_state_keys.append(key)
                    except Exception as e:
                        logger.warning(f"Error inferring global state key: {e}")

            # Try to infer local state keys
            if tx.get("local_state_delta"):
                for addr_delta in tx.get("local_state_delta"):
                    for change in addr_delta.get("delta", []):
                        try:
                            key = base64.b64decode(change["key"]).decode("utf-8")
                            if key not in local_state_keys:
                                local_state_keys.append(key)
                        except Exception as e:
                            logger.warning(f"Error inferring local state key: {e}")

    # Add fallback keys if still empty
    if not global_state_keys:
        global_state_keys = ["user_id", "book_id", "address", "params", "status"]
    if not local_state_keys:
        local_state_keys = ["book_hash", "research_hash", "params"]

    # Prepare CSV headers
    base_headers = ["txid", "timestamp", "date", "sender", "method", "on_completion"]
    global_headers = [f"g_{key}" for key in global_state_keys]
    local_headers = [f"l_{key}" for key in local_state_keys]

    headers = base_headers + global_headers + local_headers

    # Track current global state
    current_global_state = initial_global_state.copy()

    # Track current local states for all accounts
    current_local_states = {}  # address -> {key: value}

    for tx in transactions:
        # Extract basic transaction info
        txid = tx.get("id")
        timestamp = tx.get("timestamp")
        date = tx.get("date")
        sender = tx.get("sender")
        method = (
            tx.get("app_args")[0]
            if tx.get("app_args") and len(tx.get("app_args")) > 0
            else "Unknown"
        )
        on_completion = tx.get("on_completion")

        # Extract global state changes
        if tx.get("global_state_delta"):
            for change in tx.get("global_state_delta"):
                try:
                    key = base64.b64decode(change["key"]).decode("utf-8")

                    # Add key to global_state_keys if it's new
                    if key not in global_state_keys:
                        global_state_keys.append(key)
                        global_headers.append(f"g_{key}")
                        headers = base_headers + global_headers + local_headers

                    # Process value based on action
                    if "value" in change:
                        value = change["value"]
                        if value["type"] == 1:  # bytes
                            value_bytes = base64.b64decode(value["bytes"])
                            try:
                                decoded_value = value_bytes.decode("utf-8")
                            except:
                                # Try to decode as parameters
                                try:
                                    decoded_value = decode_params(value_bytes)
                                except:
                                    decoded_value = value_bytes.hex()
                            current_global_state[key] = decoded_value
                        else:  # uint
                            current_global_state[key] = value["uint"]
                    else:  # Value was deleted
                        if key in current_global_state:
                            del current_global_state[key]
                except Exception as e:
                    logger.warning(f"Error processing global state delta: {e}")

        # Extract local state changes
        sender_local_state = {}
        if tx.get("local_state_delta"):
            for addr_delta in tx.get("local_state_delta"):
                addr = addr_delta["address"]
                if addr not in current_local_states:
                    current_local_states[addr] = {}

                # Process each key-value change
                for change in addr_delta.get("delta", []):
                    try:
                        key = base64.b64decode(change["key"]).decode("utf-8")

                        # Add key to local_state_keys if it's new
                        if key not in local_state_keys:
                            local_state_keys.append(key)
                            local_headers.append(f"l_{key}")
                            headers = base_headers + global_headers + local_headers

                        # Process value based on action
                        if "value" in change:
                            value = change["value"]
                            if value["type"] == 1:  # bytes
                                value_bytes = base64.b64decode(value["bytes"])
                                try:
                                    decoded_value = value_bytes.decode("utf-8")
                                except:
                                    # Try to decode as parameters
                                    try:
                                        decoded_value = decode_params(value_bytes)
                                    except:
                                        decoded_value = value_bytes.hex()
                                current_local_states[addr][key] = decoded_value
                            else:  # uint
                                current_local_states[addr][key] = value["uint"]
                        else:  # Value was deleted
                            if key in current_local_states[addr]:
                                del current_local_states[addr][key]
                    except Exception as e:
                        logger.warning(f"Error processing local state delta: {e}")

                # If this transaction's sender matches the address with local state changes,
                # capture those changes for this row
                if addr == sender:
                    sender_local_state = current_local_states[addr]

        # If OptIn or CloseOut operation, check if sender local state exists
        if (
            on_completion in ["OptIn", "CloseOut", "ClearState"]
            and sender not in current_local_states
        ):
            # For OptIn, initialize empty local state
            if on_completion == "OptIn":
                current_local_states[sender] = {}
                sender_local_state = current_local_states[sender]
            # For CloseOut/ClearState, mark as closed out
            elif (
                on_completion in ["CloseOut", "ClearState"]
                and sender in current_local_states
            ):
                del current_local_states[sender]
                sender_local_state = {}

        # Create a row with current state values
        row = {
            "txid": txid,
            "timestamp": timestamp,
            "date": date,
            "sender": sender,
            "method": method,
            "on_completion": on_completion,
        }

        # Add global state values
        for key in global_state_keys:
            value = current_global_state.get(key, "")
            row[f"g_{key}"] = (
                json.dumps(value) if isinstance(value, (dict, list)) else value
            )

        # Add local state values
        for key in local_state_keys:
            value = sender_local_state.get(key, "")
            row[f"l_{key}"] = (
                json.dumps(value) if isinstance(value, (dict, list)) else value
            )

        # Add to rows
        rows.append(row)

    # Sort rows by timestamp
    rows.sort(key=lambda x: x.get("timestamp", 0) or 0)

    # Write to CSV
    try:
        import csv

        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

        logger.info(f"Transaction state changes exported to {output_file}")
        print(f"Transaction state changes exported to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error writing CSV file: {e}")
        print(f"Error writing CSV file: {e}")
        return None
