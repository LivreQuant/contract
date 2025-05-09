# contract_explorer.py - Explorer for Algorand contracts

import argparse
import logging
import json
from tabulate import tabulate

from utils.explorer import (
    get_contract_info,
    get_transaction_history,
    get_participants,
    analyze_parameter_changes,
    generate_activity_chart,
    search_contracts_by_address,
    export_transaction_state_changes_to_csv,
)
from utils.algorand import get_user_local_state

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("contract_explorer")


def print_contract_summary(contract_info):
    """Print a summary of contract information."""
    if not contract_info:
        print("Contract not found or error retrieving information.")
        return

    print("\n=== CONTRACT SUMMARY ===")
    print(f"App ID: {contract_info['app_id']}")
    print(f"Creator: {contract_info['creator']}")
    print(f"App Address: {contract_info['app_address']}")
    print(f"Created at Round: {contract_info['created_at_round']}")
    print(f"Status: {'Deleted' if contract_info['deleted'] else 'Active'}")

    print("\nGlobal State Schema:")
    print(f"  Byte Slices: {contract_info['global_state_schema']['num_byte_slices']}")
    print(f"  Integers: {contract_info['global_state_schema']['num_uints']}")

    print("Local State Schema:")
    print(f"  Byte Slices: {contract_info['local_state_schema']['num_byte_slices']}")
    print(f"  Integers: {contract_info['local_state_schema']['num_uints']}")

    print("\nGlobal State:")
    for key, value in contract_info["global_state"].items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")


def print_transaction_history(transactions):
    """Print transaction history in a tabular format."""
    if not transactions:
        print("No transactions found for this contract.")
        return

    table_data = []
    for tx in transactions:
        # Extract method name if available
        method = "Unknown"
        if tx.get("app_args") and len(tx.get("app_args")) > 0:
            method = tx.get("app_args")[0]

        # Add row to table
        table_data.append(
            [
                tx.get("date") or "Unknown",
                tx.get("sender")[:12] + "..." if tx.get("sender") else "Unknown",
                tx.get("on_completion") or "NoOp",
                method,
                tx.get("id")[:12] + "..." if tx.get("id") else "Unknown",
            ]
        )

    print("\n=== TRANSACTION HISTORY ===")
    print(
        tabulate(
            table_data,
            headers=["Date", "Sender", "Operation", "Method", "Transaction ID"],
            tablefmt="grid",
        )
    )


# contract_explorer.py (continued from previous part)


def print_participants(participants):
    """Print contract participants in a tabular format."""
    if not participants:
        print("No participants found for this contract.")
        return

    table_data = []
    for p in participants:
        # Count number of local state variables
        state_count = len(p["local_state"])

        # Add row to table
        table_data.append(
            [
                p["address"][:12] + "..." if p["address"] else "Unknown",
                "No" if p["opted_out"] else "Yes",
                state_count,
            ]
        )

    print("\n=== CONTRACT PARTICIPANTS ===")
    print(
        tabulate(
            table_data,
            headers=["Address", "Opted In", "# Local State Variables"],
            tablefmt="grid",
        )
    )

    # Information about viewing participant details
    print(
        "\nTo view details for a specific participant, use the participant-detail command."
    )


def print_parameter_changes(param_changes):
    """Print parameter change history."""
    if not param_changes:
        print("No parameter changes found for this contract.")
        return

    table_data = []
    for change in param_changes:
        # Format parameters
        params_str = "Error parsing parameters"
        if change.get("parsed_params"):
            params_str = ", ".join(
                [f"{k}={v}" for k, v in change["parsed_params"].items()]
            )
        else:
            params_str = change.get("raw_params", "Unknown")

        # Add row to table
        table_data.append(
            [
                change.get("date") or "Unknown",
                (
                    change.get("sender")[:12] + "..."
                    if change.get("sender")
                    else "Unknown"
                ),
                params_str,
            ]
        )

    print("\n=== PARAMETER CHANGE HISTORY ===")
    print(
        tabulate(
            table_data, headers=["Date", "Sender", "New Parameters"], tablefmt="grid"
        )
    )


def print_participant_detail(app_id, address):
    """Print detailed information for a specific participant."""
    # Get local state for this participant
    local_state = get_user_local_state(app_id, address)

    print(f"\n=== PARTICIPANT DETAILS: {address} ===")
    print(f"Opted In: {'No' if not local_state else 'Yes'}")

    if local_state:
        print("\nLocal State:")
        for key, value in local_state.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            else:
                print(f"  {key}: {value}")

    # Get transaction history for this participant with this contract
    transactions = get_transaction_history(app_id, limit=100)

    # Filter transactions for this sender
    participant_txs = [tx for tx in transactions if tx.get("sender") == address]

    if participant_txs:
        table_data = []
        for tx in participant_txs:
            # Extract method name if available
            method = "Unknown"
            if tx.get("app_args") and len(tx.get("app_args")) > 0:
                method = tx.get("app_args")[0]

            # Add row to table
            table_data.append(
                [
                    tx.get("date") or "Unknown",
                    tx.get("on_completion") or "NoOp",
                    method,
                    tx.get("id")[:12] + "..." if tx.get("id") else "Unknown",
                ]
            )

        print("\nTransaction History:")
        print(
            tabulate(
                table_data,
                headers=["Date", "Operation", "Method", "Transaction ID"],
                tablefmt="grid",
            )
        )
    else:
        print("\nNo transactions found for this participant with this contract.")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Algorand Contract Explorer")

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # Info command
    info_parser = subparsers.add_parser(
        "info", help="Get detailed information about a contract"
    )
    info_parser.add_argument("app_id", type=int, help="Application ID")

    # History command
    history_parser = subparsers.add_parser(
        "history", help="Get transaction history for a contract"
    )
    history_parser.add_argument("app_id", type=int, help="Application ID")
    history_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of transactions to retrieve",
    )

    # Participants command
    participants_parser = subparsers.add_parser(
        "participants", help="Get participants for a contract"
    )
    participants_parser.add_argument("app_id", type=int, help="Application ID")
    participants_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of participants to retrieve",
    )

    # Participant detail command
    participant_detail_parser = subparsers.add_parser(
        "participant-detail", help="Get detailed information for a specific participant"
    )
    participant_detail_parser.add_argument("app_id", type=int, help="Application ID")
    participant_detail_parser.add_argument("address", help="Participant address")

    # Parameters command
    parameters_parser = subparsers.add_parser(
        "parameters", help="Analyze parameter changes for a contract"
    )
    parameters_parser.add_argument("app_id", type=int, help="Application ID")

    # Activity command
    activity_parser = subparsers.add_parser(
        "activity", help="Generate activity chart for a contract"
    )
    activity_parser.add_argument("app_id", type=int, help="Application ID")
    activity_parser.add_argument("--output", help="Output file to save the chart")

    # Search command
    search_parser = subparsers.add_parser(
        "search", help="Search for contracts by creator address"
    )
    search_parser.add_argument("address", help="Creator address")
    search_parser.add_argument(
        "--limit", type=int, default=20, help="Maximum number of contracts to retrieve"
    )

    # Summary command - combines several views into one
    summary_parser = subparsers.add_parser(
        "summary", help="Get a comprehensive summary of a contract"
    )
    summary_parser.add_argument("app_id", type=int, help="Application ID")

    # Export to CSV command
    export_parser = subparsers.add_parser(
        "export-csv", help="Export all transaction state changes to CSV"
    )
    export_parser.add_argument("app_id", type=int, help="Application ID")
    export_parser.add_argument("--output", help="Output CSV file path")

    args = parser.parse_args()

    try:
        if args.command == "info":
            contract_info = get_contract_info(args.app_id)
            print_contract_summary(contract_info)

        elif args.command == "history":
            transactions = get_transaction_history(args.app_id, args.limit)
            print_transaction_history(transactions)

        elif args.command == "participants":
            participants = get_participants(args.app_id, args.limit)
            print_participants(participants)

        elif args.command == "participant-detail":
            print_participant_detail(args.app_id, args.address)

        elif args.command == "parameters":
            transactions = get_transaction_history(args.app_id)
            param_changes = analyze_parameter_changes(transactions)
            print_parameter_changes(param_changes)

        elif args.command == "activity":
            transactions = get_transaction_history(args.app_id)
            generate_activity_chart(transactions, args.output)

        elif args.command == "search":
            contracts = search_contracts_by_address(args.address, args.limit)
            if contracts:
                table_data = []
                for c in contracts:
                    status = "Deleted" if c.get("deleted") else "Active"
                    name = "Unknown"
                    # Try to extract name or ID from global state
                    for key in ["user_id", "book_id", "name", "title", "id"]:
                        if key in c.get("global_state", {}):
                            name = c["global_state"][key]
                            break

                    table_data.append([c["app_id"], status, name])

                print("\n=== CONTRACTS CREATED BY ADDRESS ===")
                print(f"Creator: {args.address}")
                print(
                    tabulate(
                        table_data,
                        headers=["App ID", "Status", "Identifier"],
                        tablefmt="grid",
                    )
                )
            else:
                print(f"No contracts found for creator {args.address}")

        elif args.command == "export-csv":
            export_transaction_state_changes_to_csv(args.app_id, args.output)

        elif args.command == "summary":
            # Get contract info
            contract_info = get_contract_info(args.app_id)
            print_contract_summary(contract_info)

            # Get transaction history
            transactions = get_transaction_history(
                args.app_id, 20
            )  # Limit to 20 for summary
            print_transaction_history(transactions)

            # Get participants
            participants = get_participants(args.app_id, 10)  # Limit to 10 for summary
            print_participants(participants)

            # Get parameter changes
            param_changes = analyze_parameter_changes(transactions)
            print_parameter_changes(param_changes)

            # Generate activity chart
            if len(transactions) > 0:
                print("\nTo generate an activity chart, use the activity command.")

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
