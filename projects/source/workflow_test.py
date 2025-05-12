# workflow_test.py
import logging
import argparse
import time
import json
from pathlib import Path
import hashlib

import config
from services.wallet_service import (
    get_or_create_user_wallet,
    ensure_user_wallet_funded,
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
from services.file_integrity_service import FileIntegrityService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("workflow_test")


def wait_for_prompt(message):
    """Wait a moment for logs to flush, then display a prompt."""
    # Give time for any pending logs to be processed
    time.sleep(0.5)

    # Force flush of all log handlers
    for handler in logging.getLogger().handlers:
        handler.flush()

    # Now show the prompt
    return input(f"\n{message}\n")


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file for debugging."""
    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def save_debug_info(file_path, hash_value):
    """Save debugging information about a file."""
    debug_info = {
        "file_path": str(file_path),
        "file_name": file_path.name,
        "file_size": file_path.stat().st_size,
        "hash_value": hash_value,
        "timestamp": time.time(),
    }

    # Save to debug file
    debug_path = Path(f"file_debug_{file_path.name}.json")
    with open(debug_path, "w") as f:
        json.dump(debug_info, f, indent=2)

    logger.info(f"Debug information saved to {debug_path}")


def run_full_workflow(
    user_id: str,
    book_id: str,
    funding_amount: float = 1.0,
    interactive: bool = True,
    use_encrypt: bool = True,
):
    """Run the complete workflow from wallet creation to contract deletion.

    Args:
        user_id: User identifier
        book_id: Book identifier
        funding_amount: Amount to fund the user wallet with (in Algos)
        interactive: Whether to pause between steps
        use_encrypt: Encrypt file hashes
    """

    logger.info("-" * 80)
    logger.info(f"STARTING WORKFLOW: user_id={user_id}, book_id={book_id}")
    if use_encrypt:
        logger.info("USING SECURE CRYPTOGRAPHIC VERIFICATION")
    logger.info("-" * 80)

    start_time = time.time()

    # Step 1: Get or create user wallet
    logger.info("STEP 1: Get or create user wallet")
    step1_start = time.time()
    user_wallet = get_or_create_user_wallet(user_id)
    logger.info(f"User wallet address: {user_wallet['address']}")
    logger.info(f"Step 1 completed in {time.time() - step1_start:.2f} seconds")

    if interactive:
        wait_for_prompt(
            "Press Enter to continue to Step 2: Ensure user wallet is funded..."
        )

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
        wait_for_prompt(
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
        wait_for_prompt("Press Enter to continue to Step 4: User opt-in to contract...")

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
        wait_for_prompt("Press Enter to continue to Step 5: Update local state...")

    # Step 5: Update local state with only book hash
    logger.info("STEP 5: Update local state with book hash only")
    step5_start = time.time()

    # Initialize the file integrity service
    file_service = FileIntegrityService()

    # Define path to your book file
    book_file = Path("files/market_stream_20250505T195600.csv")

    # Check if file exists
    if book_file.exists():
        # Calculate and log hash for debugging
        file_hash = calculate_file_hash(book_file)
        logger.info(f"WORKFLOW DEBUG - Book file hash: {file_hash}")
        logger.info(
            f"WORKFLOW DEBUG - Book file size: {book_file.stat().st_size} bytes"
        )

        # Choose the appropriate update method based on use_encrypt flag
        if use_encrypt:
            # Use secure cryptographic signing
            logger.info("Using secure cryptographic signing for book file")

            success = file_service.update_contract_with_signed_hashes(
                user_id=user_id,
                book_id=book_id,
                book_file_path=book_file,
                private_key_path=Path(config.PRIVATE_KEY_PATH),
                passphrase=(
                    config.SECRET_PASS_PHRASE if config.ENCRYPT_PRIVATE_KEYS else None
                ),  # Pass passphrase if key is encrypted
            )

        else:
            # Update contract with book file hash only (no research file, no params)
            logger.info("Using regular hash for book file")

            success = file_service.update_contract_with_file_hashes(
                user_id=user_id,
                book_id=book_id,
                book_file_path=book_file,
            )

            # Save debug info
            save_debug_info(book_file, file_hash)

        if success:
            logger.info("Local state update with book hash successful")
        else:
            logger.error("Local state update with book hash failed")
    else:
        # Fallback to dummy values if files don't exist
        logger.warning("Book file not found, using dummy hash")
        book_hash = f"book_hash_{user_id}_{book_id}"

        if update_user_local_state(user_id, book_id, book_hash, "", ""):
            logger.info("Local state update with dummy book hash successful")
        else:
            logger.error("Local state update with dummy book hash failed")

    logger.info(f"Step 5 completed in {time.time() - step5_start:.2f} seconds")

    if interactive:
        wait_for_prompt(
            "Press Enter to continue to Step 6: Update local state with book and research hash..."
        )

    # Rest of function continues unchanged...

    # Step 6: Update local state with both book and research hash
    logger.info("STEP 6: Update local state with book and research hash")
    step6_start = time.time()

    # Define paths to both files
    second_book_file = Path("files/market_stream_20250505T195600_update.csv")
    research_file = Path("files/factsheet.jpg")

    # Check if files exist
    if second_book_file.exists():
        # Calculate and log hash for debugging
        second_file_hash = calculate_file_hash(second_book_file)
        logger.info(f"WORKFLOW DEBUG - Second book file hash: {second_file_hash}")
        logger.info(
            f"WORKFLOW DEBUG - Second book file size: {second_book_file.stat().st_size} bytes"
        )

        if research_file.exists():
            research_file_hash = calculate_file_hash(research_file)
            logger.info(f"WORKFLOW DEBUG - Research file hash: {research_file_hash}")
            logger.info(
                f"WORKFLOW DEBUG - Research file size: {research_file.stat().st_size} bytes"
            )

        # Choose the appropriate update method based on use_encrypt flag
        if use_encrypt:
            # Use secure cryptographic signing
            success = file_service.update_contract_with_signed_hashes(
                user_id=user_id,
                book_id=book_id,
                book_file_path=second_book_file,
                private_key_path=Path(config.PRIVATE_KEY_PATH),  # Use path from config
                research_file_path=research_file if research_file.exists() else None,
                additional_params={
                    "version": "2.0",
                    "description": "Updated submission",
                },
                passphrase=(
                    config.SECRET_PASS_PHRASE if config.ENCRYPT_PRIVATE_KEYS else None
                ),
            )

        else:
            # Update contract with book file hash and optional research file
            success = file_service.update_contract_with_file_hashes(
                user_id=user_id,
                book_id=book_id,
                book_file_path=second_book_file,
                research_file_path=research_file if research_file.exists() else None,
                additional_params={
                    "version": "2.0",
                    "description": "Updated submission",
                },
            )

            # Save debug info
            save_debug_info(second_book_file, second_file_hash)
            if research_file.exists():
                save_debug_info(research_file, research_file_hash)

        if success:
            if research_file.exists():
                logger.info(
                    "Second local state update with book and research hash successful"
                )
            else:
                logger.info(
                    "Second local state update with book hash successful (no research file)"
                )
        else:
            logger.error("Second local state update failed")
    else:
        # Fallback to dummy values if files don't exist
        logger.warning("Second book file not found, using dummy hashes")
        book_hash = f"book_hash_{user_id}_{book_id}_updated"
        research_hash = (
            f"research_hash_{user_id}_{book_id}_updated"
            if research_file.exists()
            else ""
        )
        local_params = f"param1:new_value1|param2:new_value2|user:{user_id}|book:{book_id}|timestamp:{time.time()}"

        if update_user_local_state(
            user_id, book_id, book_hash, research_hash, local_params
        ):
            logger.info("Second local state update with dummy values successful")
        else:
            logger.error("Second local state update with dummy values failed")

    logger.info(f"Step 6 completed in {time.time() - step6_start:.2f} seconds")

    # Continue with the rest of the steps as before...
    # Steps 7-9 remain unchanged

    if interactive:
        wait_for_prompt(
            "Press Enter to continue to Step 7: User closes out from contract..."
        )

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
        wait_for_prompt("Press Enter to continue to Step 8: Explore contract...")

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
        )

        # Generate explorer data and CSV
        explorer_info = explore_contract(
            user_id, book_id, app_id, include_csv=True, force=True
        )

        if explorer_info:
            # Get the CSV path for the transaction history
            csv_path = (
                Path("db/explorer") / f"{user_id}_{book_id}_{app_id}_transactions.csv"
            )

            if csv_path.exists():
                logger.info(f"Transaction history saved to {csv_path}")
                logger.info(f"To audit these files later, run:")
                logger.info(f"python audit_test.py")
            else:
                logger.warning(f"CSV file not generated at expected path: {csv_path}")

            # Check if any transactions were found
            tx_count = len(explorer_info.get("transaction_history", []))
            logger.info(f"Found {tx_count} transactions in the explorer")
        else:
            logger.error("Contract exploration failed")
    except Exception as e:
        logger.error(f"Error exploring contract: {e}")
    logger.info(f"Step 8 completed in {time.time() - step8_start:.2f} seconds")

    if interactive:
        wait_for_prompt("Press Enter to continue to Step 9: Delete contract...")

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
        use_encrypt=True,
    )


if __name__ == "__main__":
    main()
