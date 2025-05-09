import argparse
import json
import logging
import sys
from typing import Dict, Any

from projects.old.services.config import USER_MNEMONIC
from projects.old.services.utils import (
    get_algod_client,
    get_account_from_mnemonic,
    get_app_client,
    encode_params,
    decode_params,
    log_transaction_result,
)

# Configure logging
logger = logging.getLogger("assets_contract.user")


class ContractUser:
    """User class for interacting with Assets Contract."""

    def __init__(self, user_mnemonic: str = USER_MNEMONIC):
        """Initialize the user with mnemonic."""
        if not user_mnemonic:
            raise ValueError("User mnemonic is required")

        self.algorand = get_algod_client()
        self.user_account = get_account_from_mnemonic(user_mnemonic)
        logger.info(f"User initialized with address: {self.user_account.address}")

    def opt_in_to_contract(self, app_id: int) -> None:
        """
        Opt in to an assets contract.

        Args:
            app_id: The ID of the application to opt in to
        """
        app_client = get_app_client(app_id, USER_MNEMONIC)

        # Call the opt_in method
        response = app_client.send.opt_in()

        log_transaction_result(response, "Contract opt-in")
        logger.info(f"Successfully opted in to contract: {app_id}")

    def update_local_state(
        self, app_id: int, file_hash: str, research_hash: str, params: Dict[str, Any]
    ) -> None:
        """
        Update the local state in a contract.

        Args:
            app_id: The ID of the application
            file_hash: Hash of the asset file
            research_hash: Hash of the research
            params: Dictionary of local parameters
        """
        app_client = get_app_client(app_id, USER_MNEMONIC)

        # Encode the parameters
        encoded_file_hash = file_hash.encode("utf-8")
        encoded_research_hash = research_hash.encode("utf-8")
        encoded_params = encode_params(params)

        # Call the update_local method
        response = app_client.send.update_local(
            args=(encoded_file_hash, encoded_research_hash, encoded_params)
        )

        log_transaction_result(response, "Local state update")
        logger.info(f"Successfully updated local state in contract: {app_id}")

    def close_out_from_contract(self, app_id: int) -> None:
        """
        Close out from a contract (opt out).

        Args:
            app_id: The ID of the application to close out from
        """
        app_client = get_app_client(app_id, USER_MNEMONIC)

        # Call the close_out method
        response = app_client.send.close_out()

        log_transaction_result(response, "Contract close-out")
        logger.info(f"Successfully closed out from contract: {app_id}")

    def get_local_state(self, app_id: int) -> Dict[str, Any]:
        """
        Get the local state for this user in a contract.

        Args:
            app_id: The ID of the application

        Returns:
            Dictionary with local state information
        """
        # Check if the user is opted in
        account_info = self.algorand.algod.account_info(self.user_account.address)

        # Find the app in the account's apps_local_state
        local_state = None
        for app_state in account_info.get("apps-local-states", []):
            if app_state["id"] == app_id:
                local_state = app_state.get("key-value", [])
                break

        if local_state is None:
            logger.warning(f"User is not opted in to app ID: {app_id}")
            return {}

        # Process and return state
        processed_state = {}

        for item in local_state:
            key = base64.b64decode(item["key"]).decode("utf-8")
            value = item["value"]

            if value["type"] == 1:  # bytes
                processed_value = base64.b64decode(value["bytes"])
                if key == "local_params":
                    try:
                        processed_value = decode_params(processed_value)
                    except:
                        processed_value = processed_value.hex()
                else:
                    try:
                        processed_value = processed_value.decode("utf-8")
                    except:
                        processed_value = processed_value.hex()
            else:  # uint
                processed_value = value["uint"]

            processed_state[key] = processed_value

        return processed_state


def main():
    """Command-line interface for user operations."""
    parser = argparse.ArgumentParser(description="Assets Contract User Tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Opt in command
    opt_in_parser = subparsers.add_parser("opt-in", help="Opt in to a contract")
    opt_in_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )

    # Update local state command
    update_parser = subparsers.add_parser("update-local", help="Update local state")
    update_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )
    update_parser.add_argument("--file-hash", required=True, help="File hash")
    update_parser.add_argument("--research-hash", required=True, help="Research hash")
    update_parser.add_argument(
        "--parameters", required=True, help="JSON string of parameters"
    )

    # Close out command
    close_parser = subparsers.add_parser("close-out", help="Close out from a contract")
    close_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )

    # Get local state command
    state_parser = subparsers.add_parser("local-state", help="Get local state")
    state_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )

    args = parser.parse_args()

    try:
        user = ContractUser()

        if args.command == "opt-in":
            user.opt_in_to_contract(args.app_id)
            print(f"Successfully opted in to contract: {args.app_id}")

        elif args.command == "update-local":
            parameters = json.loads(args.parameters)
            user.update_local_state(
                args.app_id, args.file_hash, args.research_hash, parameters
            )
            print(f"Successfully updated local state in contract: {args.app_id}")

        elif args.command == "close-out":
            user.close_out_from_contract(args.app_id)
            print(f"Successfully closed out from contract: {args.app_id}")

        elif args.command == "local-state":
            state = user.get_local_state(args.app_id)
            print(json.dumps(state, indent=2))

        else:
            parser.print_help()

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
