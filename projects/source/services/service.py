import logging
import json
import time
from typing import Dict, Any, Optional

from projects.source.services.admin import ContractAdmin
from projects.source.services.user import ContractUser
from projects.source.services.config import ADMIN_MNEMONIC, USER_MNEMONIC

# Configure logging
logger = logging.getLogger("assets_contract.service")


class AssetsContractService:
    """Service for managing the full lifecycle of Assets Contracts."""

    def __init__(
        self,
        admin_mnemonic: str = ADMIN_MNEMONIC,
        user_mnemonic: str = USER_MNEMONIC
    ):
        """Initialize the service with admin and user components."""
        self.admin = ContractAdmin(admin_mnemonic)
        self.user = ContractUser(user_mnemonic)
        logger.info("Assets Contract Service initialized")

    def create_contract_and_opt_in(
        self,
        user_id: str,
        asset_id: str,
        parameters: Dict[str, Any]
    ) -> int:
        """
        Create a contract and opt in the user.

        Args:
            user_id: Identifier for the user
            asset_id: Identifier for the asset
            parameters: Dictionary of contract parameters

        Returns:
            The app ID of the created contract
        """
        # Create the contract with the admin
        app_id = self.admin.create_contract(
            self.user.user_account.address,
            user_id,
            asset_id,
            parameters
        )

        # Give the transaction time to confirm
        time.sleep(5)

        # Opt in with the user
        try:
            self.user.opt_in_to_contract(app_id)
            logger.info(f"User successfully opted in to contract: {app_id}")
        except Exception as e:
            logger.error(f"User opt-in failed: {e}")
            logger.warning(f"Contract created but user not opted in: {app_id}")

        return app_id

    def update_contract_and_local_state(
        self,
        app_id: int,
        global_parameters: Dict[str, Any],
        file_hash: str,
        research_hash: str,
        local_parameters: Dict[str, Any]
    ) -> None:
        """
        Update both global and local state in a single operation.

        Args:
            app_id: The ID of the application
            global_parameters: Dictionary of global parameters to update
            file_hash: Hash of the asset file
            research_hash: Hash of the research
            local_parameters: Dictionary of local parameters
        """
        # Update global parameters first
        try:
            self.admin.update_contract_params(app_id, global_parameters)
            logger.info(f"Global parameters updated for app ID: {app_id}")
        except Exception as e:
            logger.error(f"Failed to update global parameters: {e}")
            raise

        # Give the transaction time to confirm
        time.sleep(5)

        # Update local state
        try:
            self.user.update_local_state(
                app_id,
                file_hash,
                research_hash,
                local_parameters
            )
            logger.info(f"Local state updated for app ID: {app_id}")
        except Exception as e:
            logger.error(f"Failed to update local state: {e}")
            raise

    def close_contract(self, app_id: int, delete_contract: bool = True) -> None:
        """
        Close out the user and optionally delete the contract.

        Args:
            app_id: The ID of the application
            delete_contract: Whether to delete the contract after close-out
        """
        # Close out with the user
        try:
            self.user.close_out_from_contract(app_id)
            logger.info(f"User closed out from contract: {app_id}")
        except Exception as e:
            logger.error(f"User close-out failed: {e}")
            raise

        # Give the transaction time to confirm
        time.sleep(5)

        if delete_contract:
            # Set contract to inactive
            try:
                self.admin.update_contract_status(app_id, "INACTIVE")
                logger.info(f"Contract status set to INACTIVE: {app_id}")

                # Give the transaction time to confirm
                time.sleep(5)

                # Delete the contract
                self.admin.delete_contract(app_id)
                logger.info(f"Contract deleted: {app_id}")
            except Exception as e:
                logger.error(f"Contract deletion failed: {e}")
                raise

    def get_contract_complete_state(self, app_id: int) -> Dict[str, Any]:
        """
        Get both global and local state for a contract.

        Args:
            app_id: The ID of the application

        Returns:
            Dictionary with complete state information
        """
        global_state = self.admin.get_contract_state(app_id)
        local_state = self.user.get_local_state(app_id)

        return {
            "app_id": app_id,
            "global_state": global_state,
            "local_state": local_state,
            "timestamp": time.time()
        }

    def export_contract_state(self, app_id: int, filename: Optional[str] = None) -> str:
        """
        Export the complete state of a contract to a JSON file.

        Args:
            app_id: The ID of the application
            filename: Optional filename to use

        Returns:
            Path to the exported file
        """
        state = self.get_contract_complete_state(app_id)

        if filename is None:
            filename = f"contract_{app_id}_state_{int(time.time())}.json"

        with open(filename, "w") as f:
            json.dump(state, f, indent=2)

        logger.info(f"Contract state exported to: {filename}")
        return filename

    def check_contract_status(self, app_id: int) -> str:
        """
        Check the status of a contract.

        Args:
            app_id: The ID of the application

        Returns:
            The status of the contract (ACTIVE/INACTIVE)
        """
        state = self.admin.get_contract_state(app_id)
        return state.get("global_status", "UNKNOWN")

    def is_user_opted_in(self, app_id: int) -> bool:
        """
        Check if the user is opted in to a contract.

        Args:
            app_id: The ID of the application

        Returns:
            True if the user is opted in, False otherwise
        """
        local_state = self.user.get_local_state(app_id)
        return len(local_state) > 0

    def get_contract_by_user_and_asset(self, user_id: str, asset_id: str) -> Optional[int]:
        """
        Find a contract matching the given user and asset IDs.

        Args:
            user_id: Identifier for the user
            asset_id: Identifier for the asset

        Returns:
            The app ID if found, None otherwise
        """
        # This would typically involve indexer search in a production environment
        # For this example, we'll just search through a list of created contracts
        # that would be stored somewhere

        # Placeholder implementation
        # In reality, you would use the indexer to search for contracts with matching global state
        logger.warning("get_contract_by_user_and_asset is not fully implemented")
        return None


# Example usage for testing
def main():
    """Test the AssetsContractService class."""
    service = AssetsContractService()

    # Create a contract and opt in
    app_id = service.create_contract_and_opt_in(
        user_id="user123",
        asset_id="asset456",
        parameters={"param1": "value1", "param2": "value2"}
    )

    print(f"Contract created with app ID: {app_id}")

    # Wait a bit
    time.sleep(5)

    # Update the contract
    service.update_contract_and_local_state(
        app_id=app_id,
        global_parameters={"param1": "new_value1", "param2": "new_value2", "param3": "value3"},
        file_hash="file_hash_123",
        research_hash="research_hash_456",
        local_parameters={"local_param1": "local_value1"}
    )

    # Check and export the state
    state_file = service.export_contract_state(app_id)
    print(f"Contract state exported to: {state_file}")

    # Check status
    status = service.check_contract_status(app_id)
    print(f"Contract status: {status}")

    # Check if user is opted in
    opted_in = service.is_user_opted_in(app_id)
    print(f"User opted in: {opted_in}")

    # Close the contract after a bit
    time.sleep(5)
    close_contract = input("Close and delete the contract? (y/n): ")
    if close_contract.lower() == 'y':
        service.close_contract(app_id, delete_contract=True)
        print(f"Contract {app_id} closed and deleted")


if __name__ == "__main__":
    main()
