# admin_ops.py - Admin operations for the contract

import argparse
import json
import logging

from utils.contract import (
    admin_update_contract_status,
    admin_update_contract_global,
    admin_delete_contract,
)
from utils.algorand import get_contract_state, check_if_user_opted_in

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("admin_ops")


def run_test_sequence(app_id: int, contract_info: dict):
    """
    Run a test sequence of admin operations on a contract.

    Args:
        app_id: The application ID
        contract_info: Contract information dictionary
    """
    logger.info(f"Starting test sequence for app ID: {app_id}")

    # Step 1: Display current state
    current_state, _ = get_contract_state(app_id)
    logger.info("Current contract state:")
    for key, value in current_state.items():
        logger.info(f"  {key}: {value}")

    # Check if user is opted in
    is_opted_in, user_address = check_if_user_opted_in(app_id)
    if is_opted_in:
        logger.info(f"User {user_address} is opted in to the contract")
    else:
        logger.info(f"User {user_address} is not opted in to the contract")

    # Step 2: Update global parameters
    input("Press Enter to update global parameters...")

    # Make a small change to the parameters
    new_user_id = "user123_updated"
    new_book_id = "book456_updated"
    new_parameters = "region:EMEA|asset_class:FOREX|instrument_class:OPTIONS"
    user_address = contract_info["user_address"]

    admin_update_contract_global(
        app_id, new_user_id, new_book_id, user_address, new_parameters
    )

    # Pause for user to check
    input("Press Enter to continue to status update...")

    # Step 3: Update status to INACTIVE-STOP
    admin_update_contract_status(app_id, "INACTIVE-STOP")

    # Pause for user to check
    input("Press Enter to continue to contract deletion...")

    # Step 4: Delete the contract
    try:
        admin_delete_contract(app_id)
        logger.info("Contract deleted successfully!")
    except ValueError as e:
        logger.error(f"Cannot delete contract: {e}")
        proceed = input("Do you want to force delete the contract anyway? (y/n): ")
        if proceed.lower() == "y":
            admin_delete_contract(app_id, force=True)
            logger.info("Contract force deleted successfully!")
        else:
            logger.info("Contract deletion aborted")

    logger.info("Test sequence completed!")


def main():
    """Command-line interface for admin operations."""
    parser = argparse.ArgumentParser(description="Admin operations for the contract")

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )
    # admin_ops.py (continued from previous part)

    # Test sequence command
    test_parser = subparsers.add_parser(
        "test", help="Run a test sequence of operations"
    )
    test_parser.add_argument("contract_file", help="Contract information JSON file")

    # Status command
    status_parser = subparsers.add_parser("status", help="Update contract status")
    status_parser.add_argument("app_id", type=int, help="Application ID")
    status_parser.add_argument(
        "new_status",
        choices=["ACTIVE", "INACTIVE-STOP", "INACTIVE-SOLD"],
        help="New status value",
    )

    # Global update command
    global_parser = subparsers.add_parser(
        "update-global", help="Update global parameters"
    )
    global_parser.add_argument("app_id", type=int, help="Application ID")
    global_parser.add_argument("--user-id", required=True, help="New user ID")
    global_parser.add_argument("--book-id", required=True, help="New book ID")
    global_parser.add_argument("--user-address", required=True, help="New user address")
    global_parser.add_argument(
        "--parameters", required=True, help="New parameters string"
    )

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete the contract")
    delete_parser.add_argument("app_id", type=int, help="Application ID")
    delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Force deletion even if user is still opted in",
    )

    # State command
    state_parser = subparsers.add_parser("state", help="Get contract state")
    state_parser.add_argument("app_id", type=int, help="Application ID")

    # Check opt-in status command
    optin_parser = subparsers.add_parser(
        "check-optin", help="Check if the user is opted into the contract"
    )
    optin_parser.add_argument("app_id", type=int, help="Application ID")

    args = parser.parse_args()

    try:
        if args.command == "test":
            # Load contract information
            with open(args.contract_file, "r") as f:
                contract_info = json.load(f)

            app_id = contract_info["app_id"]
            run_test_sequence(app_id, contract_info)

        elif args.command == "status":
            admin_update_contract_status(args.app_id, args.new_status)

            # Display the updated state
            updated_state, _ = get_contract_state(args.app_id)
            logger.info("Updated contract state:")
            for key, value in updated_state.items():
                logger.info(f"  {key}: {value}")

        elif args.command == "update-global":
            admin_update_contract_global(
                args.app_id,
                args.user_id,
                args.book_id,
                args.user_address,
                args.parameters,
            )

            # Display the updated state
            updated_state, _ = get_contract_state(args.app_id)
            logger.info("Updated contract state:")
            for key, value in updated_state.items():
                logger.info(f"  {key}: {value}")

        elif args.command == "delete":
            admin_delete_contract(args.app_id, args.force)

        elif args.command == "state":
            state, _ = get_contract_state(args.app_id)
            print(json.dumps(state, indent=2))

        elif args.command == "check-optin":
            is_opted_in, user_address = check_if_user_opted_in(args.app_id)
            if is_opted_in:
                print(f"User {user_address} is currently opted in to app {args.app_id}")
            else:
                print(f"User {user_address} is not opted in to app {args.app_id}")

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)


if __name__ == "__main__":
    main()
