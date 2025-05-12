# audit_verification_tool.py
import json
import sys
from pathlib import Path

from services.audit_verification_service import AuditVerificationService


def run_audit(config_dict, csv_path, output_file=None):
    """
    Run an audit using a configuration dictionary.

    Args:
        config_dict: Dictionary with files and parameters to verify
        csv_path: Path to the CSV file
        output_file: Optional path to save the report JSON
    """
    # Initialize the service
    service = AuditVerificationService(csv_path)

    # Clean up parameters - remove timestamp if present
    if "parameters" in config_dict and "timestamp" in config_dict["parameters"]:
        config_dict["parameters"] = config_dict["parameters"].copy()
        del config_dict["parameters"]["timestamp"]

    # Generate the audit report
    report = service.generate_audit_report(
        files_to_verify=config_dict.get("files", []),
        params_dict=config_dict.get("parameters"),
    )

    # Print the report
    service.print_audit_report(report)

    # Save the report if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nAudit report saved to {output_file}")

    return report


def main():
    # Define the base directory (where the script is located)
    base_dir = Path(__file__).parent.resolve()

    # CSV file path
    csv_path = (
        base_dir
        / "db"
        / "explorer"
        / "test_user_001_test_book_002_1405_transactions.csv"
    )

    # Example configuration with proper paths
    config = {
        "files": [
            {
                "path": base_dir / "files" / "market_stream_20250505T195600.csv",
                "type": "book",
            },
            {
                "path": base_dir / "files" / "market_stream_20250505T195600_update.csv",
                "type": "book",
            },
            {"path": base_dir / "files" / "factsheet.jpg", "type": "research"},
        ],
        "parameters": {
            "book_file": "market_stream_20250505T195600_update.csv",
            "user": "test_user_001",
            "book": "test_book_002",
            "research_file": "factsheet.jpg",
            "version": "2.0",
            "description": "Updated submission",
        },
    }

    # Convert Path objects to strings for the audit service
    for file_info in config["files"]:
        file_info["path"] = str(file_info["path"])

    # Run the audit
    run_audit(config, csv_path)


if __name__ == "__main__":
    main()
