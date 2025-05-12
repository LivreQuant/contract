# audit_test.py - Using deterministic signatures
import logging
import argparse
import json
import csv
from pathlib import Path

from services.audit_service import AuditService
from utils.hash_file_utils import calculate_file_hash
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("audit_test")

# Default paths
DEFAULT_CSV_PATH = "db/explorer/test_user_001_test_book_002_1577_transactions.csv"
DEFAULT_FILES_DIR = "files"
DEFAULT_OUTPUT_PATH = "audit_report.json"


def read_blockchain_hashes(csv_file):
    """Read hashes from the blockchain transaction CSV."""
    blockchain_hashes = {"book_hash": [], "research_hash": [], "params": []}
    transaction_count = 0

    try:
        with open(csv_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                transaction_count += 1

                # Extract hash values
                book_hash = row.get("l_book_hash", "")
                if (
                    book_hash
                    and book_hash != "NAN"
                    and book_hash not in blockchain_hashes["book_hash"]
                ):
                    blockchain_hashes["book_hash"].append(book_hash)

                research_hash = row.get("l_research_hash", "")
                if (
                    research_hash
                    and research_hash != "NAN"
                    and research_hash not in blockchain_hashes["research_hash"]
                ):
                    blockchain_hashes["research_hash"].append(research_hash)

                params_hash = row.get("l_params", "")
                if (
                    params_hash
                    and params_hash != "NAN"
                    and params_hash not in blockchain_hashes["params"]
                ):
                    blockchain_hashes["params"].append(params_hash)

        logger.info(f"Found {len(blockchain_hashes['book_hash'])} book hashes in CSV")
        logger.info(
            f"Found {len(blockchain_hashes['research_hash'])} research hashes in CSV"
        )
        logger.info(f"Found {len(blockchain_hashes['params'])} parameter hashes in CSV")
        logger.info(f"Total transactions: {transaction_count}")

    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        return {}, 0

    return blockchain_hashes, transaction_count


def run_audit(
    csv_file: Path = Path(DEFAULT_CSV_PATH),
    files_dir: Path = Path(DEFAULT_FILES_DIR),
    output_path: Path = Path(DEFAULT_OUTPUT_PATH),
):
    """
    Run an audit to verify files against blockchain records.
    """
    logger.info("-" * 80)
    logger.info(f"STARTING AUDIT: CSV={csv_file}")
    logger.info(f"Files directory: {files_dir}")
    logger.info("-" * 80)

    # Get blockchain hashes from CSV
    blockchain_hashes, transaction_count = read_blockchain_hashes(csv_file)

    # Initialize the audit service
    audit_service = AuditService()

    # List files to verify
    files_to_verify = [
        {"path": files_dir / "market_stream_20250505T195600.csv", "type": "book"},
        {
            "path": files_dir / "market_stream_20250505T195600_update.csv",
            "type": "book",
        },
        {"path": files_dir / "factsheet.jpg", "type": "research"},
    ]

    # Use the same passphrase for verification as was used for signing
    passphrase = config.SECRET_PASS_PHRASE

    # Parameters for verification
    params_dict = {
        "book": "test_book_002",
        "book_file": "market_stream_20250505T195600_update.csv",
        "description": "Updated submission",
        "research_file": "factsheet.jpg",
        "user": "test_user_001",
        "version": "2.0",
    }

    # Verify each file using deterministic signatures and generate report
    verification_results = []
    all_verified = True

    for file_info in files_to_verify:
        if not file_info["path"].exists():
            logger.warning(f"File not found: {file_info['path']}")
            verification = {
                "verified": False,
                "file": file_info["path"].name,
                "file_type": file_info["type"],
                "error": "File not found",
            }
        else:
            verification = audit_service.verify_file_against_blockchain(
                file_info["path"], file_info["type"], passphrase, blockchain_hashes
            )

        verification_results.append(verification)
        all_verified = all_verified and verification.get("verified", False)

    # Verify parameters
    params_verification = audit_service.verify_params_against_blockchain(
        params_dict, passphrase, blockchain_hashes
    )

    all_verified = all_verified and params_verification.get("verified", False)

    # Create report
    report = {
        "audit_date": "2025-05-12",
        "csv_file": str(csv_file),
        "transaction_count": transaction_count,
        "file_verifications": verification_results,
        "params_verification": params_verification,
        "all_verified": all_verified,
    }

    # Print the report
    audit_service.print_audit_report(report)

    # Save the report
    audit_service.save_audit_report(report, output_path)

    return all_verified


def main():
    parser = argparse.ArgumentParser(
        description="Verify files against blockchain records"
    )

    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV_PATH,
        help=f"Path to the CSV file (default: {DEFAULT_CSV_PATH})",
    )
    parser.add_argument(
        "--files-dir",
        default=DEFAULT_FILES_DIR,
        help=f"Directory containing the files to verify (default: {DEFAULT_FILES_DIR})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help=f"Path to save the audit report (default: {DEFAULT_OUTPUT_PATH})",
    )

    args = parser.parse_args()

    # Run the audit
    success = run_audit(
        csv_file=Path(args.csv),
        files_dir=Path(args.files_dir),
        output_path=Path(args.output),
    )

    # Exit with appropriate status code
    if success:
        logger.info("AUDIT SUCCESSFUL: All files verified!")
        return 0
    else:
        logger.error("AUDIT FAILED: Verification failures detected")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
