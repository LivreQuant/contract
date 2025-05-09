# contract_deploy.py - Deploy a contract to the Algorand network

import argparse
import logging
from pathlib import Path

from utils.contract import deploy_contract
from utils.algorand import check_application_exists, get_contract_state

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("contract_deploy")


def main():
    """Deploy a contract to the Algorand network."""
    parser = argparse.ArgumentParser(
        description="Deploy a contract to the Algorand network"
    )

    parser.add_argument(
        "--approval",
        help="Path to approval program TEAL file",
        default="artifacts/BookContract.approval.teal",
    )
    parser.add_argument(
        "--clear",
        help="Path to clear program TEAL file",
        default="artifacts/BookContract.clear.teal",
    )
    parser.add_argument(
        "--user-id", help="User ID for initialization", default="user123"
    )
    parser.add_argument(
        "--book-id", help="Book ID for initialization", default="book456"
    )
    parser.add_argument(
        "--params",
        help="Parameters string for initialization",
        default="region:NA|asset_class:EQUITIES|instrument_class:STOCKS",
    )

    args = parser.parse_args()

    # Validate paths
    approval_path = Path(args.approval)
    clear_path = Path(args.clear)

    if not approval_path.exists():
        logger.error(f"Approval program file not found: {approval_path}")
        return

    if not clear_path.exists():
        logger.error(f"Clear program file not found: {clear_path}")
        return

    # Deploy the contract
    app_id, contract_info = deploy_contract(
        approval_program_path=approval_path,
        clear_program_path=clear_path,
        user_id=args.user_id,
        book_id=args.book_id,
        params_str=args.params,
    )

    # Verify the contract exists
    if check_application_exists(app_id):
        state, _ = get_contract_state(app_id)
        logger.info("\nContract State:")
        for key, value in state.items():
            logger.info(f"  {key}: {value}")

        print(f"\nContract deployed with app ID: {app_id}")
        print(f"Contract address: {contract_info['app_address']}")
        print(f"User address: {contract_info['user_address']}")
        print(f"Contract information saved to contract_{app_id}_info.json")
    else:
        logger.error(f"Failed to verify contract with app ID: {app_id}")


if __name__ == "__main__":
    main()
