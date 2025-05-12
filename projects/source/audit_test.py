# audit_test.py - simplified to verify directly against transaction CSV
import logging
import argparse
import json
import hashlib
import csv
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("audit_test")

# Hardcoded paths
DEFAULT_CSV_PATH = "db/explorer/test_user_001_test_book_002_1527_transactions.csv"
DEFAULT_FILES_DIR = "files"
DEFAULT_OUTPUT_PATH = "audit_report.json"


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def run_audit(
    csv_file: Path = Path(DEFAULT_CSV_PATH),
    files_dir: Path = Path(DEFAULT_FILES_DIR),
    output_path: Path = Path(DEFAULT_OUTPUT_PATH),
):
    """
    Run an audit to verify files against blockchain records.

    Args:
        csv_file: Path to the CSV file with blockchain transactions
        files_dir: Directory containing the files to verify
        output_path: Path to save the audit report to
    """
    logger.info("-" * 80)
    logger.info(f"STARTING AUDIT: CSV={csv_file}")
    logger.info(f"Files directory: {files_dir}")
    logger.info("-" * 80)

    # Dictionary to hold hash values from CSV for each file type
    csv_hashes = {"book_hash": [], "research_hash": [], "params": []}

    # Read the transaction CSV
    try:
        with open(csv_file, "r") as f:
            reader = csv.DictReader(f)
            transaction_count = 0
            for row in reader:
                transaction_count += 1

                # Extract hash values, skipping empty or 'NAN' values
                book_hash = row.get("l_book_hash", "")
                if (
                    book_hash
                    and book_hash != "NAN"
                    and book_hash not in csv_hashes["book_hash"]
                ):
                    csv_hashes["book_hash"].append(book_hash)

                research_hash = row.get("l_research_hash", "")
                if (
                    research_hash
                    and research_hash != "NAN"
                    and research_hash not in csv_hashes["research_hash"]
                ):
                    csv_hashes["research_hash"].append(research_hash)

                params_hash = row.get("l_params", "")
                if (
                    params_hash
                    and params_hash != "NAN"
                    and params_hash not in csv_hashes["params"]
                ):
                    csv_hashes["params"].append(params_hash)

        logger.info(f"Found {len(csv_hashes['book_hash'])} book hashes in CSV")
        logger.info(f"Found {len(csv_hashes['research_hash'])} research hashes in CSV")
        logger.info(f"Found {len(csv_hashes['params'])} parameter hashes in CSV")
        logger.info(f"Total transactions: {transaction_count}")

    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        return False

    # List to store verification results
    verification_results = []

    # Find and verify files
    original_book_file = files_dir / "market_stream_20250505T195600.csv"
    if original_book_file.exists():
        file_hash = calculate_file_hash(original_book_file)
        logger.info(f"File: {original_book_file.name}, Hash: {file_hash}")

        # Check if hash is in blockchain records
        hash_match = file_hash in csv_hashes["book_hash"]
        verification_results.append(
            {
                "file": original_book_file.name,
                "file_type": "book",
                "calculated_hash": file_hash,
                "blockchain_match": hash_match,
                "verified": hash_match,
            }
        )

        if hash_match:
            logger.info(f"✅ {original_book_file.name}: Verified on blockchain")
        else:
            logger.error(f"❌ {original_book_file.name}: Hash not found on blockchain")

    updated_book_file = files_dir / "market_stream_20250505T195600_update.csv"
    if updated_book_file.exists():
        file_hash = calculate_file_hash(updated_book_file)
        logger.info(f"File: {updated_book_file.name}, Hash: {file_hash}")

        # Check if hash is in blockchain records
        hash_match = file_hash in csv_hashes["book_hash"]
        verification_results.append(
            {
                "file": updated_book_file.name,
                "file_type": "book",
                "calculated_hash": file_hash,
                "blockchain_match": hash_match,
                "verified": hash_match,
            }
        )

        if hash_match:
            logger.info(f"✅ {updated_book_file.name}: Verified on blockchain")
        else:
            logger.error(f"❌ {updated_book_file.name}: Hash not found on blockchain")

    research_file = files_dir / "factsheet.jpg"
    if research_file.exists():
        file_hash = calculate_file_hash(research_file)
        logger.info(f"File: {research_file.name}, Hash: {file_hash}")

        # Check if hash is in blockchain records
        hash_match = file_hash in csv_hashes["research_hash"]
        verification_results.append(
            {
                "file": research_file.name,
                "file_type": "research",
                "calculated_hash": file_hash,
                "blockchain_match": hash_match,
                "verified": hash_match,
            }
        )

        if hash_match:
            logger.info(f"✅ {research_file.name}: Verified on blockchain")
        else:
            logger.error(f"❌ {research_file.name}: Hash not found on blockchain")

    # Create the report
    import datetime

    report = {
        "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "csv_file": str(csv_file),
        "transaction_count": transaction_count,
        "file_verifications": verification_results,
        "all_verified": all(v.get("verified", False) for v in verification_results),
    }

    # Print the report
    print("\n" + "=" * 80)
    print("BLOCKCHAIN FILE INTEGRITY AUDIT REPORT")
    print("=" * 80)
    print(f"Audit Date: {report['audit_date']}")
    print(f"CSV Transaction Record: {report['csv_file']}")
    print(f"Transaction Count: {report['transaction_count']}")
    print("\nFILE VERIFICATION RESULTS:")

    for verification in report["file_verifications"]:
        print(f"\nFILE: {verification['file']} ({verification['file_type']})")
        if verification["verified"]:
            print("✅ VERIFICATION SUCCESSFUL")
            print(f"  Calculated Hash: {verification['calculated_hash']}")
            print("  Hash found in blockchain records")
        else:
            print("❌ VERIFICATION FAILED")
            print(f"  Calculated Hash: {verification['calculated_hash']}")
            print("  Hash NOT found in blockchain records")

    print("\n" + "=" * 80)
    print("AUDIT CONCLUSION:")
    if report["all_verified"]:
        print(
            "✅ All files have been verified successfully against blockchain records."
        )
        print("The data integrity is confirmed. No modifications detected.")
    else:
        print("❌ Some verifications failed. See the detailed report above.")
        print("Data integrity issues detected. Files may have been modified.")
    print("=" * 80)

    # Save the report
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Audit report saved to: {output_path}")

    # Return the overall verification result
    return report.get("all_verified", False)


def main():
    parser = argparse.ArgumentParser(
        description="Verify files against blockchain records"
    )

    # Make all arguments optional with sensible defaults
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

    # Run the audit with either the default paths or those specified
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
