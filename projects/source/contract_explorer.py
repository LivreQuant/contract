# contract_explorer.py
import argparse
import json
import logging
import time
import os
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional
from tabulate import tabulate

import config
from services.explorer_service import explore_contract, get_all_contracts

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler("explorer.log"), logging.StreamHandler()],
)
logger = logging.getLogger("contract_explorer")


def print_contract_summary(contract_info: Dict[str, Any]):
    """Print a summary of contract information."""
    if not contract_info:
        print("No contract information available")
        return

    print("\n=== CONTRACT SUMMARY ===")
    print(f"User ID: {contract_info.get('user_id')}")
    print(f"Book ID: {contract_info.get('book_id')}")
    print(f"App ID: {contract_info.get('app_id')}")
    print(f"Status: {contract_info.get('blockchain_status', 'Unknown')}")
    print(
        f"Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(contract_info.get('creation_timestamp', 0)))}"
    )

    if "global_state" in contract_info and contract_info["global_state"]:
        print("\nGlobal State:")
        for key, value in contract_info["global_state"].items():
            print(f"  {key}: {value}")

    if "participants" in contract_info and contract_info["participants"]:
        print("\nParticipants:")
        for participant in contract_info["participants"]:
            status = "Opted In" if participant.get("opted_in") else "Opted Out"
            print(f"  {participant.get('address')}: {status}")

    tx_count = len(contract_info.get("transaction_history", []))
    print(f"\nTransaction History: {tx_count} transactions")
    if tx_count > 0:
        print("  Most recent transactions:")
        for tx in sorted(
            contract_info.get("transaction_history", []),
            key=lambda x: x.get("timestamp", 0),
            reverse=True,
        )[:3]:
            date = tx.get("date", "Unknown")
            sender = tx.get("sender", "Unknown")
            action = tx.get("on_completion", "NoOp")
            print(f"  {date}: {sender[:10]}... - {action}")

    if "csv_export_path" in contract_info:
        print(f"\nTransaction CSV export: {contract_info['csv_export_path']}")


def export_transactions_to_csv(
    explorer_info: Dict[str, Any], output_path: str = None
) -> str:
    """Export transactions from explorer info to CSV."""
    transactions = explorer_info.get("transaction_history", [])
    if not transactions:
        print("No transactions to export")
        return None

    if not output_path:
        user_id = explorer_info.get("user_id", "unknown")
        book_id = explorer_info.get("book_id", "unknown")
        output_path = (
            config.DB_DIR / "explorer" / f"{user_id}_{book_id}_transactions.csv"
        )

    # Create a DataFrame
    rows = []
    for tx in transactions:
        row = {
            "transaction_id": tx.get("id"),
            "date": tx.get("date"),
            "sender": tx.get("sender"),
            "action": tx.get("on_completion", "NoOp"),
            "global_delta": json.dumps(tx.get("global_delta", {})),
            "local_delta": json.dumps(tx.get("local_delta", {})),
            "app_args": json.dumps(tx.get("app_args", [])),
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
    print(f"Exported {len(transactions)} transactions to {output_path}")
    return str(output_path)


def list_all_contracts():
    """List all contracts in the system."""
    contracts = get_all_contracts()

    if not contracts:
        print("No contracts found")
        return

    print(f"\nFound {len(contracts)} contracts:")
    print(
        "\n{:<15} {:<15} {:<10} {:<15} {:<20}".format(
            "USER ID", "BOOK ID", "APP ID", "STATUS", "CREATED"
        )
    )
    print("-" * 80)

    for contract in contracts:
        created = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(contract.get("creation_timestamp", 0))
        )
        print(
            "{:<15} {:<15} {:<10} {:<15} {:<20}".format(
                contract.get("user_id", "Unknown"),
                contract.get("book_id", "Unknown"),
                contract.get("app_id", "Unknown"),
                contract.get("blockchain_status", "Unknown"),
                created,
            )
        )


def main():
    parser = argparse.ArgumentParser(description="Algorand Contract Explorer")

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List all contracts")

    # Explore command
    explore_parser = subparsers.add_parser(
        "explore", help="Explore a specific contract"
    )
    explore_parser.add_argument("--user-id", required=True, help="User ID")
    explore_parser.add_argument("--book-id", required=True, help="Book ID")

    # View command
    view_parser = subparsers.add_parser(
        "view", help="View explorer data for a contract"
    )
    view_parser.add_argument("--user-id", required=True, help="User ID")
    view_parser.add_argument("--book-id", required=True, help="Book ID")

    # Export transactions command
    export_parser = subparsers.add_parser("export", help="Export transactions to CSV")
    export_parser.add_argument("--user-id", required=True, help="User ID")
    export_parser.add_argument("--book-id", required=True, help="Book ID")
    export_parser.add_argument("--output", help="Output CSV file path")

    args = parser.parse_args()

    try:
        if args.command == "list":
            list_all_contracts()

        elif args.command == "explore":
            print(
                f"Exploring contract for user {args.user_id} and book {args.book_id}..."
            )
            contract_info = explore_contract(
                args.user_id, args.book_id, include_csv=True
            )

            if contract_info:
                print(
                    f"Successfully explored contract for user {args.user_id} and book {args.book_id}"
                )
                print_contract_summary(contract_info)
                explorer_path = (
                    config.DB_DIR
                    / "explorer"
                    / f"{args.user_id}_{args.book_id}_explorer.json"
                )
                print(f"Full explorer data saved to {explorer_path}")
            else:
                print(
                    f"Failed to explore contract for user {args.user_id} and book {args.book_id}"
                )

        elif args.command == "view":
            explorer_path = (
                config.DB_DIR
                / "explorer"
                / f"{args.user_id}_{args.book_id}_explorer.json"
            )

            if not explorer_path.exists():
                print(
                    f"No explorer data found for user {args.user_id} and book {args.book_id}"
                )
                print(
                    f"Run 'python contract_explorer.py explore --user-id {args.user_id} --book-id {args.book_id}' first"
                )
                return

            with open(explorer_path, "r") as f:
                explorer_info = json.load(f)

            print_contract_summary(explorer_info)

        elif args.command == "export":
            explorer_path = (
                config.DB_DIR
                / "explorer"
                / f"{args.user_id}_{args.book_id}_explorer.json"
            )

            if not explorer_path.exists():
                print(
                    f"No explorer data found for user {args.user_id} and book {args.book_id}"
                )
                print(
                    f"Run 'python contract_explorer.py explore --user-id {args.user_id} --book-id {args.book_id}' first"
                )
                return

            with open(explorer_path, "r") as f:
                explorer_info = json.load(f)

            export_transactions_to_csv(explorer_info, args.output)

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
