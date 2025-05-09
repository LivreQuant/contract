import argparse
import json
import logging
import sys
import time
from typing import Dict, Any

from projects.old.services.config import ADMIN_MNEMONIC, DEFAULT_FUNDING_AMOUNT
from projects.old.services.utils import (
    get_algod_client,
    get_account_from_mnemonic,
    get_app_client,
    get_app_factory,
    encode_params,
    decode_params,
    log_transaction_result,
)

# Configure logging
logger = logging.getLogger("assets_contract.admin")


class ContractAdmin:
    """Admin class for managing Assets Contract lifecycle."""

    def __init__(self, admin_mnemonic: str = ADMIN_MNEMONIC):
        """Initialize the admin with mnemonic."""
        if not admin_mnemonic:
            raise ValueError("Admin mnemonic is required")

        self.algorand = get_algod_client()
        self.admin_account = get_account_from_mnemonic(admin_mnemonic)
        logger.info(f"Admin initialized with address: {self.admin_account.address}")

    def create_contract(
        self, user_address: str, user_id: str, asset_id: str, parameters: Dict[str, Any]
    ) -> int:
        """
        Create a new assets contract.

        Args:
            user_address: The address of the user who can interact with the contract
            user_id: Identifier for the user
            asset_id: Identifier for the asset
            parameters: Dictionary of contract parameters

        Returns:
            The app ID of the created contract
        """
        factory = get_app_factory(ADMIN_MNEMONIC)

        # Deploy the contract
        app_client, result = factory.deploy(
            on_update=algokit_utils.OnUpdate.AppendApp,
            on_schema_break=algokit_utils.OnSchemaBreak.AppendApp,
            create_params={
                "on_complete": algokit_utils.OnCompleteAction.NoOp,
                "app_args": [
                    user_address.encode("utf-8"),  # Pass user_address to constructor
                ],
            },
        )

        logger.info(f"Contract deployed with app ID: {app_client.app_id}")
        logger.info(f"Contract address: {app_client.app_address}")

        # Fund the contract with min balance
        funding_amount = algokit_utils.AlgoAmount(microalgos=DEFAULT_FUNDING_AMOUNT)
        self.algorand.send.payment(
            algokit_utils.PaymentParams(
                amount=funding_amount,
                sender=self.admin_account.address,
                receiver=app_client.app_address,
                signer=self.admin_account,
            )
        )
        logger.info(f"Funded contract with {funding_amount.algos} Algos")

        # Initialize the contract
        encoded_user_id = user_id.encode("utf-8")
        encoded_asset_id = asset_id.encode("utf-8")
        encoded_parameters = encode_params(parameters)

        response = app_client.send.initialize(
            args=(encoded_user_id, encoded_asset_id, encoded_parameters),
        )

        log_transaction_result(response, "Contract initialization")
        logger.info(
            f"Contract successfully created and initialized with app ID: {app_client.app_id}"
        )

        # Save contract info to a file for reference
        contract_info = {
            "app_id": app_client.app_id,
            "app_address": app_client.app_address,
            "user_address": user_address,
            "user_id": user_id,
            "asset_id": asset_id,
            "parameters": parameters,
            "creation_timestamp": time.time(),
        }

        with open(f"contract_{app_client.app_id}_info.json", "w") as f:
            json.dump(contract_info, f, indent=2)

        return app_client.app_id

    def update_contract_params(
        self, app_id: int, new_parameters: Dict[str, Any]
    ) -> None:
        """
        Update the parameters of an existing contract.

        Args:
            app_id: The ID of the application to update
            new_parameters: New parameters dictionary
        """
        app_client = get_app_client(app_id, ADMIN_MNEMONIC)

        # Encode the parameters
        encoded_parameters = encode_params(new_parameters)

        # Call the update_params method
        response = app_client.send.update_params(args=(encoded_parameters,))

        log_transaction_result(response, "Contract parameter update")
        logger.info(f"Contract parameters updated for app ID: {app_id}")

    def update_contract_status(self, app_id: int, new_status: str) -> None:
        """
        Update the status of an existing contract.

        Args:
            app_id: The ID of the application to update
            new_status: New status ("ACTIVE" or "INACTIVE")
        """
        if new_status not in ["ACTIVE", "INACTIVE"]:
            raise ValueError("Status must be either 'ACTIVE' or 'INACTIVE'")

        app_client = get_app_client(app_id, ADMIN_MNEMONIC)

        # Call the update_status method
        response = app_client.send.update_status(args=(new_status,))

        log_transaction_result(response, "Contract status update")
        logger.info(f"Contract status updated to {new_status} for app ID: {app_id}")

    def delete_contract(self, app_id: int) -> None:
        """
        Delete a contract (must be INACTIVE first).

        Args:
            app_id: The ID of the application to delete
        """
        app_client = get_app_client(app_id, ADMIN_MNEMONIC)

        # Call the delete_application method
        try:
            response = app_client.send.delete_application()
            log_transaction_result(response, "Contract deletion")
            logger.info(f"Contract deleted: {app_id}")
        except Exception as e:
            logger.error(f"Failed to delete contract: {e}")
            logger.info(
                "Make sure the contract status is set to INACTIVE before deletion"
            )
            raise

    def get_contract_state(self, app_id: int) -> Dict[str, Any]:
        """
        Get the current state of a contract.

        Args:
            app_id: The ID of the application

        Returns:
            Dictionary with contract state information
        """
        app_client = get_app_client(app_id, ADMIN_MNEMONIC)

        # Get global state
        global_state = self.algorand.algod.application_info(app_id)["params"][
            "global-state"
        ]

        # Process and return state
        processed_state = {}

        for item in global_state:
            key = base64.b64decode(item["key"]).decode("utf-8")
            value = item["value"]

            if value["type"] == 1:  # bytes
                processed_value = base64.b64decode(value["bytes"])
                if key == "global_status":
                    processed_value = processed_value.decode("utf-8")
                elif key in ["global_params"]:
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
    """Command-line interface for admin operations."""
    parser = argparse.ArgumentParser(description="Assets Contract Admin Tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create contract command
    create_parser = subparsers.add_parser("create", help="Create a new contract")
    create_parser.add_argument("--user-address", required=True, help="User address")
    create_parser.add_argument("--user-id", required=True, help="User ID")
    create_parser.add_argument("--asset-id", required=True, help="Asset ID")
    create_parser.add_argument(
        "--parameters", required=True, help="JSON string of parameters"
    )

    # Update params command
    update_params_parser = subparsers.add_parser(
        "update-params", help="Update contract parameters"
    )
    update_params_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )
    update_params_parser.add_argument(
        "--parameters", required=True, help="JSON string of parameters"
    )

    # Update status command
    update_status_parser = subparsers.add_parser(
        "update-status", help="Update contract status"
    )
    update_status_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )
    update_status_parser.add_argument(
        "--status", required=True, choices=["ACTIVE", "INACTIVE"], help="New status"
    )

    # Delete contract command
    delete_parser = subparsers.add_parser("delete", help="Delete a contract")
    delete_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )

    # Get state command
    state_parser = subparsers.add_parser("state", help="Get contract state")
    state_parser.add_argument(
        "--app-id", required=True, type=int, help="Application ID"
    )

    args = parser.parse_args()

    try:
        admin = ContractAdmin()

        if args.command == "create":
            parameters = json.loads(args.parameters)
            app_id = admin.create_contract(
                args.user_address, args.user_id, args.asset_id, parameters
            )
            print(f"Contract created with app ID: {app_id}")

        elif args.command == "update-params":
            parameters = json.loads(args.parameters)
            admin.update_contract_params(args.app_id, parameters)
            print(f"Contract parameters updated for app ID: {args.app_id}")

        elif args.command == "update-status":
            admin.update_contract_status(args.app_id, args.status)
            print(f"Contract status updated to {args.status} for app ID: {args.app_id}")

        elif args.command == "delete":
            admin.delete_contract(args.app_id)
            print(f"Contract deleted: {args.app_id}")

        elif args.command == "state":
            state = admin.get_contract_state(args.app_id)
            print(json.dumps(state, indent=2))

        else:
            parser.print_help()

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
