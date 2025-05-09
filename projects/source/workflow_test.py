# workflow_test.py
import logging
import argparse
import json
import time
import base64
from pathlib import Path

# Import our config module
import config
from services.wallet_service import (
    get_or_create_user_wallet,
    ensure_user_wallet_funded,
    get_wallet_credentials,
)
from services.contract_service import (
    get_contract_for_user_book,
    deploy_contract_for_user_book,
    remove_contract,
)
from services.user_contract_service import (
    user_opt_in_to_contract,
    update_user_local_state,
    user_close_out_from_contract,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler("workflow.log"), logging.StreamHandler()],
)
logger = logging.getLogger("workflow_test")


def run_full_workflow(
    user_id: str, book_id: str, funding_amount: float = 1.0, interactive: bool = True
):
    """Run the complete workflow from wallet creation to contract deletion.

    Args:
        user_id: User identifier
        book_id: Book identifier
        funding_amount: Amount to fund the user wallet with (in Algos)
        interactive: Whether to pause between steps
    """

    logger.info("-" * 80)
    logger.info(f"STARTING WORKFLOW: user_id={user_id}, book_id={book_id}")
    logger.info("-" * 80)

    start_time = time.time()

    # Step 1: Get or create user wallet
    logger.info("STEP 1: Get or create user wallet")
    step1_start = time.time()
    user_wallet = get_or_create_user_wallet(user_id)
    logger.info(f"User wallet address: {user_wallet['address']}")
    logger.info(f"Step 1 completed in {time.time() - step1_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 2: Ensure user wallet is funded...")

    # Step 2: Ensure user wallet is funded
    logger.info("STEP 2: Ensure user wallet is funded")
    step2_start = time.time()
    if ensure_user_wallet_funded(user_id, funding_amount):
        logger.info("User wallet funding successful or already sufficient")
    else:
        logger.error(
            f"Failed to fund user wallet with {funding_amount} Algos, aborting workflow"
        )
        logger.info(
            "You may need to manually fund the admin account or reduce the funding amount"
        )
        logger.info(
            f"Try running: 'goal clerk send -a {int(funding_amount * 1000000)} -f ADMIN_ADDRESS -t {user_wallet['address']}'"
        )
        return
    logger.info(f"Step 2 completed in {time.time() - step2_start:.2f} seconds")

    if interactive:
        input(
            "Press Enter to continue to Step 3: Deploy contract or get existing contract..."
        )

    # Step 3: Deploy contract or get existing contract
    logger.info("STEP 3: Deploy contract or get existing contract")
    step3_start = time.time()
    contract_info = get_contract_for_user_book(user_id, book_id)
    if contract_info:
        app_id = contract_info["app_id"]
        logger.info(f"Using existing contract: {app_id}")
    else:
        logger.info("Deploying new contract")
        contract_info = deploy_contract_for_user_book(user_id, book_id)
        if contract_info:
            app_id = contract_info["app_id"]
            logger.info(f"Contract deployed with app ID: {app_id}")
        else:
            logger.error("Contract deployment failed, aborting workflow")
            return
    logger.info(f"Step 3 completed in {time.time() - step3_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 4: User opt-in to contract...")

    # Step 4: User opt-in to contract
    logger.info("STEP 4: User opt-in to contract")
    step4_start = time.time()
    if user_opt_in_to_contract(user_id, book_id):
        logger.info("User opt-in successful")
    else:
        logger.error("User opt-in failed, aborting workflow")
        return
    logger.info(f"Step 4 completed in {time.time() - step4_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 5: Update local state...")

    # Step 5: Update local state
    logger.info("STEP 5: Update local state")
    step5_start = time.time()
    book_hash = f"book_hash_{user_id}_{book_id}"
    research_hash = f"research_hash_{user_id}_{book_id}"
    local_params = f"param1:value1|param2:value2|user:{user_id}|book:{book_id}"

    if update_user_local_state(
        user_id, book_id, book_hash, research_hash, local_params
    ):
        logger.info("Local state update successful")
    else:
        logger.error("Local state update failed, continuing workflow")
    logger.info(f"Step 5 completed in {time.time() - step5_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 6: Update local state again...")

    # Step 6: Update local state again with different values
    logger.info("STEP 6: Update local state again")
    step6_start = time.time()
    book_hash = f"book_hash_{user_id}_{book_id}_updated"
    research_hash = f"research_hash_{user_id}_{book_id}_updated"
    local_params = f"param1:new_value1|param2:new_value2|user:{user_id}|book:{book_id}|timestamp:{time.time()}"

    if update_user_local_state(
        user_id, book_id, book_hash, research_hash, local_params
    ):
        logger.info("Second local state update successful")
    else:
        logger.error("Second local state update failed, continuing workflow")
    logger.info(f"Step 6 completed in {time.time() - step6_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 7: User closes out from contract...")

    # Step 7: User closes out from contract
    logger.info("STEP 7: User closes out from contract")
    step7_start = time.time()
    if user_close_out_from_contract(user_id, book_id):
        logger.info("User close-out successful")
    else:
        logger.error(
            "User close-out failed, admin may need to force-delete the contract"
        )
    logger.info(f"Step 7 completed in {time.time() - step7_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 8: Explore contract...")

    # Step 8: Explore contract and save detailed information
    logger.info("STEP 8: Explore contract and save detailed information")
    step8_start = time.time()

    # Wait for indexer to catch up
    wait_seconds = 15
    logger.info(
        f"Waiting {wait_seconds} seconds for the indexer to catch up before exploring..."
    )
    time.sleep(wait_seconds)
    logger.info(f"Waited {wait_seconds} seconds. Now exploring contract...")

    try:
        from services.explorer_service import (
            explore_contract,
            export_transactions_to_csv,
        )

        # First get the JSON data without CSV generation
        explorer_info = explore_contract(
            user_id, book_id, app_id, include_csv=True, force=True
        )

        if explorer_info:
            logger.info(
                f"Contract exploration complete, information saved to db/explorer/{user_id}_{book_id}_explorer.json"
            )

            # Check if any transactions were found
            tx_count = len(explorer_info.get("transaction_history", []))
            logger.info(f"Found {tx_count} transactions in the explorer")
        else:
            logger.error("Contract exploration failed")
    except Exception as e:
        logger.error(f"Error exploring contract: {e}")
    logger.info(f"Step 8 completed in {time.time() - step8_start:.2f} seconds")

    if interactive:
        input("Press Enter to continue to Step 9: Delete contract...")

    # Step 9: Admin deletes contract
    logger.info("STEP 9: Admin deletes contract")
    step9_start = time.time()
    if remove_contract(user_id, book_id, force=True):
        logger.info("Contract deletion successful")
    else:
        logger.error("Contract deletion failed")
    logger.info(f"Step 9 completed in {time.time() - step9_start:.2f} seconds")

    total_time = time.time() - start_time
    logger.info("-" * 80)
    logger.info(f"WORKFLOW COMPLETED in {total_time:.2f} seconds")
    logger.info("-" * 80)


def main():
    parser = argparse.ArgumentParser(description="Test the complete workflow")
    parser.add_argument(
        "--user-id", default="test_user_001", help="User ID for the test"
    )
    parser.add_argument(
        "--book-id", default="test_book_002", help="Book ID for the test"
    )
    parser.add_argument(
        "--funding",
        type=float,
        default=0.1,
        help="Amount to fund the user wallet with (in Algos)",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run without pauses between steps",
    )

    args = parser.parse_args()

    # Run the workflow
    run_full_workflow(
        args.user_id,
        args.book_id,
        funding_amount=args.funding,
        interactive=not args.non_interactive,
    )


if __name__ == "__main__":
    main()
