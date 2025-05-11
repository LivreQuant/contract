# file_integrity_tool.py
import argparse
import logging
import sys
import json
from pathlib import Path

from services.file_integrity_service import FileIntegrityService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler("file_integrity.log"), logging.StreamHandler()],
)
logger = logging.getLogger("file_integrity_tool")


def main():
    parser = argparse.ArgumentParser(description="File Integrity Tool")

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # Calculate hashes command
    calc_parser = subparsers.add_parser("calc", help="Calculate file hashes")
    calc_parser.add_argument("--book", required=True, help="Path to book data file")
    calc_parser.add_argument("--research", required=True, help="Path to research file")

    # Update contract command
    update_parser = subparsers.add_parser(
        "update", help="Update contract with file hashes"
    )
    update_parser.add_argument("--user-id", required=True, help="User ID")
    update_parser.add_argument("--book-id", required=True, help="Book ID")
    update_parser.add_argument("--book", required=True, help="Path to book data file")
    update_parser.add_argument(
        "--research", required=True, help="Path to research file"
    )
    update_parser.add_argument(
        "--no-store", action="store_true", help="Don't store file copies"
    )

    # Verify command
    verify_parser = subparsers.add_parser(
        "verify", help="Verify file against blockchain hash"
    )
    verify_parser.add_argument("--user-id", required=True, help="User ID")
    verify_parser.add_argument("--book-id", required=True, help="Book ID")
    verify_parser.add_argument("--file", required=True, help="Path to file to verify")
    verify_parser.add_argument(
        "--type",
        required=True,
        choices=["book", "research"],
        help="Type of file (book or research)",
    )

    # History command
    history_parser = subparsers.add_parser("history", help="Get file hash history")
    history_parser.add_argument("--user-id", required=True, help="User ID")
    history_parser.add_argument("--book-id", required=True, help="Book ID")
    history_parser.add_argument("--output", help="Output JSON file path")

    args = parser.parse_args()

    service = FileIntegrityService()

    try:
        if args.command == "calc":
            book_path = Path(args.book)
            research_path = Path(args.research)

            if not book_path.exists() or not research_path.exists():
                logger.error("File(s) not found")
                return 1

            hashes = service.calculate_and_store_hashes(
                "test_user", "test_book", book_path, research_path, store_files=False
            )

            print(f"Book hash: {hashes['book_hash']}")
            print(f"Research hash: {hashes['research_hash']}")

        elif args.command == "update":
            book_path = Path(args.book)
            research_path = Path(args.research)

            if not book_path.exists() or not research_path.exists():
                logger.error("File(s) not found")
                return 1

            success = service.update_contract_with_file_hashes(
                args.user_id,
                args.book_id,
                book_path,
                research_path,
                store_files=not args.no_store,
            )

            if success:
                print(f"Successfully updated contract with file hashes")
            else:
                print(f"Failed to update contract with file hashes")
                return 1

        elif args.command == "verify":
            file_path = Path(args.file)

            if not file_path.exists():
                logger.error(f"File not found: {args.file}")
                return 1

            match = service.verify_file(
                args.user_id, args.book_id, file_path, args.type
            )

            if match:
                print(f"✅ File matches the hash stored on the blockchain")
            else:
                print(f"❌ File does NOT match the hash stored on the blockchain")
                return 1

        elif args.command == "history":
            history = service.get_file_history(args.user_id, args.book_id)

            if not history:
                print(f"No file hash history found for {args.user_id}/{args.book_id}")
                return 1

            print(f"Found {len(history)} file hash records:")
            for i, record in enumerate(history, 1):
                print(f"Record {i}:")
                print(f"  Date: {record.get('date')}")
                print(f"  Book Hash: {record.get('book_hash')}")
                print(f"  Research Hash: {record.get('research_hash')}")
                print(f"  Params: {record.get('params')}")
                print("")

            if args.output:
                with open(args.output, "w") as f:
                    json.dump(history, f, indent=2)
                print(f"Saved history to {args.output}")

    except Exception as e:
        logger.error(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
