# user_ops.py - User operations for the contract

import argparse
import json
import logging
from pathlib import Path

from utils.contract import user_opt_in, user_update_local_state, user_close_out
from utils.algorand import (
    get_algod_client,
    get_account_from_mnemonic,
    get_user_local_state,
    get_latest_contract_id,
    USER_MNEMONIC,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("user_ops")


def run_test_sequence(app_id: int):
    """
    Run a test sequence of user operations on a contract.

    Args:
        app_id: The application ID
    """
    logger.info(f"Starting user test sequence for app ID: {app_id}")

    # Get user address
    _, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    # Step 1: Opt in to the contract (or skip if already opted in)
    user_opt_in(app_id)

    # Pause for user to check
    input("Press Enter to update local state for the first time...")

    # Step 2: Update local state
    user_update_local_state(
        app_id,
        "book_hash_123",
        "research_hash_456",
        "local_param1:value1|local_param2:value2",
    )

    # Pause for user to check
    input("Press Enter to update local state for the second time...")

    # Step 3: Update local state again with different values
    user_update_local_state(
        app_id,
        "book_hash_updated",
        "research_hash_updated",
        "local_param1:new_value1|local_param2:new_value2|local_param3:value3",
    )

    # Pause for user to check
    input("Press Enter to close out from the contract...")

    # Step 4: Close out from the contract
    user_close_out(app_id)

    logger.info("User test sequence completed successfully!")


def main():
    """Command-line interface for user operations."""
    parser = argparse.ArgumentParser(description="User operations for the contract")

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # Test sequence command
    test_parser = subparsers.add_parser(
        "test", help="Run a test sequence of operations"
    )
    test_parser.add_argument(
        "app_id", type=int, help="Application ID (use 0 for latest)"
    )

    # Opt-in command
    opt_in_parser = subparsers.add_parser("opt-in", help="Opt in to a contract")
    opt_in_parser.add_argument("app_id", type=int, help="Application ID")

    # Update local state command
    update_parser = subparsers.add_parser("update-local", help="Update local state")
    update_parser.add_argument("app_id", type=int, help="Application ID")
    update_parser.add_argument("--book-hash", required=True, help="Book hash value")
    update_parser.add_argument(
        "--research-hash", required=True, help="Research hash value"
    )
    update_parser.add_argument("--parameters", required=True, help="Parameters string")

    # Close-out command
    close_out_parser = subparsers.add_parser(
        "close-out", help="Close out from a contract"
    )
    close_out_parser.add_argument("app_id", type=int, help="Application ID")

    # Get local state command
    state_parser = subparsers.add_parser("local-state", help="Get local state")
    state_parser.add_argument("app_id", type=int, help="Application ID")
    state_parser.add_argument(
        "--address", help="User address (defaults to address from USER_MNEMONIC)"
    )

    # Get latest contract command
    latest_parser = subparsers.add_parser("latest", help="Get the latest contract ID")

    args = parser.parse_args()

    try:
        # Special case for app_id = 0 (use latest)
        if hasattr(args, "app_id") and args.app_id == 0:
            args.app_id = get_latest_contract_id()
            logger.info(f"Using latest contract ID: {args.app_id}")

        # For local-state command, parse the address argument
        if args.command == "local-state" and not args.address and USER_MNEMONIC:
            _, user_address = get_account_from_mnemonic(USER_MNEMONIC)
            args.address = user_address

        if args.command == "test":
            run_test_sequence(args.app_id)

        elif args.command == "opt-in":
            user_opt_in(args.app_id)

        elif args.command == "update-local":
            user_update_local_state(
                args.app_id, args.book_hash, args.research_hash, args.parameters
            )

        elif args.command == "close-out":
            user_close_out(args.app_id)

        elif args.command == "local-state":
            if not args.address:
                parser.error(
                    "User address is required for local-state command when USER_MNEMONIC is not set"
                )

            state = get_user_local_state(args.app_id, args.address)
            if state:
                print(json.dumps(state, indent=2))
            else:
                print(
                    f"No local state found for app ID {args.app_id} and address {args.address}"
                )

        elif args.command == "latest":
            latest_id = get_latest_contract_id()
            print(f"Latest contract ID: {latest_id}")

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)


if __name__ == "__main__":
    main()
