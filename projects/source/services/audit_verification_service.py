# services/audit_verification_service.py
import csv
import hashlib
import datetime
import logging
from pathlib import Path
from typing import Dict, Any, List, Union, Optional, Tuple

logger = logging.getLogger(__name__)


class AuditVerificationService:
    """Service for verifying file and parameter integrity against blockchain CSV exports."""

    def __init__(self, csv_path: Union[str, Path]):
        """
        Initialize the service with a CSV path.

        Args:
            csv_path: Path to the CSV file containing blockchain transaction data
        """
        self.csv_path = Path(csv_path)
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        # Load the CSV data
        self.transactions = self._load_csv_data()
        logger.info(
            f"Loaded {len(self.transactions)} transactions from {self.csv_path}"
        )

    def _load_csv_data(self) -> List[Dict[str, str]]:
        """
        Load transaction data from the CSV file.

        Returns:
            List of transaction dictionaries
        """
        transactions = []
        with open(self.csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                transactions.append(row)
        return transactions

    def calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """
        Calculate the SHA-256 hash of a file.

        Args:
            file_path: Path to the file

        Returns:
            Hex digest of the hash
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        hash_obj = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def hash_params_string(self, params_str: str) -> str:
        """
        Create a hash of the parameters string.

        Args:
            params_str: The parameters string in format "key1:value1|key2:value2|..."

        Returns:
            Hash of the parameters string
        """
        return hashlib.sha256(params_str.encode()).hexdigest()

    def format_params_dict(self, params_dict: Dict[str, Any]) -> str:
        """
        Format a parameters dictionary to a standardized string.

        Args:
            params_dict: Dictionary of parameters

        Returns:
            Formatted string "key1:value1|key2:value2|..." sorted by key
        """
        # Create a copy to avoid modifying the original
        params_copy = params_dict.copy()

        # Remove timestamp if present (it causes verification issues)
        if "timestamp" in params_copy:
            del params_copy["timestamp"]

        # Sort by key and join with the format key:value|key:value...
        return "|".join([f"{k}:{v}" for k, v in sorted(params_copy.items())])

    def verify_file(
        self, file_path: Union[str, Path], file_type: str
    ) -> List[Dict[str, Any]]:
        """
        Verify if a file's hash matches any records in the transaction history.

        Args:
            file_path: Path to the file to verify
            file_type: Type of file ('book' or 'research')

        Returns:
            List of matching transaction records with verification details
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if file_type.lower() not in ["book", "research"]:
            raise ValueError(
                f"Invalid file type: {file_type}. Must be 'book' or 'research'"
            )

        # Calculate file hash
        current_hash = self.calculate_file_hash(file_path)
        logger.info(f"Calculated hash for {file_path.name}: {current_hash}")

        # Determine which column to check
        hash_column = f"l_{file_type.lower()}_hash"

        # Find matching transactions
        matches = []
        for tx in self.transactions:
            if hash_column not in tx:
                logger.warning(f"Column {hash_column} not found in CSV")
                return []

            stored_hash = tx[hash_column]

            # Skip empty hash values
            if not stored_hash or stored_hash == "NAN":
                continue

            # Compare hashes
            is_match = stored_hash == current_hash

            if is_match:
                match_info = {
                    "transaction_id": tx["transaction_id"],
                    "date": tx["date"],
                    "sender": tx["sender"],
                    "stored_hash": stored_hash,
                    "calculated_hash": current_hash,
                    "is_match": is_match,
                    "file_name": file_path.name,
                    "file_type": file_type,
                }
                matches.append(match_info)

        if matches:
            logger.info(
                f"File {file_path.name} matched {len(matches)} transaction records"
            )
        else:
            logger.warning(
                f"File {file_path.name} did not match any transaction records"
            )

        return matches

    def verify_params(self, params_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Verify if parameters match any records in the transaction history.

        Args:
            params_dict: Dictionary of parameters to verify

        Returns:
            List of matching transaction records with verification details
        """
        # Format parameters
        params_str = self.format_params_dict(params_dict)

        # Calculate hash
        current_hash = self.hash_params_string(params_str)
        logger.info(f"Calculated hash for parameters: {current_hash}")

        # Find matching transactions
        matches = []
        for tx in self.transactions:
            if "l_params" not in tx:
                logger.warning("Column l_params not found in CSV")
                return []

            stored_hash = tx["l_params"]

            # Skip empty hash values
            if not stored_hash or stored_hash == "NAN":
                continue

            # Compare hashes
            is_match = stored_hash == current_hash

            if is_match:
                match_info = {
                    "transaction_id": tx["transaction_id"],
                    "date": tx["date"],
                    "sender": tx["sender"],
                    "stored_hash": stored_hash,
                    "calculated_hash": current_hash,
                    "is_match": is_match,
                    "params_str": params_str,
                }
                matches.append(match_info)

        if matches:
            logger.info(f"Parameters matched {len(matches)} transaction records")
        else:
            logger.warning(f"Parameters did not match any transaction records")

        return matches

    def verify_file_at_time(
        self, file_path: Union[str, Path], file_type: str, timestamp: str
    ) -> Dict[str, Any]:
        """
        Verify if a file existed at a specific timestamp.

        Args:
            file_path: Path to the file to verify
            file_type: Type of file ('book' or 'research')
            timestamp: Timestamp to check (format: 'YYYY-MM-DD HH:MM:SS')

        Returns:
            Verification result dictionary
        """
        # Get all matches for the file
        matches = self.verify_file(file_path, file_type)

        # Parse the target timestamp
        try:
            target_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise ValueError(
                f"Invalid timestamp format: {timestamp}. Use 'YYYY-MM-DD HH:MM:SS'"
            )

        # Find the closest transaction before or at the target time
        closest_match = None
        min_time_diff = float("inf")

        for match in matches:
            try:
                tx_time = datetime.datetime.strptime(match["date"], "%Y-%m-%d %H:%M:%S")
                time_diff = (target_time - tx_time).total_seconds()

                # Only consider transactions before or at the target time
                if time_diff >= 0 and time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_match = match
            except ValueError:
                logger.warning(f"Could not parse date: {match['date']}")

        result = {
            "file_name": Path(file_path).name,
            "file_type": file_type,
            "target_timestamp": timestamp,
            "verification_result": False,
            "match_found": closest_match is not None,
            "time_difference_seconds": min_time_diff if closest_match else None,
            "match_details": closest_match,
        }

        if closest_match:
            result["verification_result"] = True
            logger.info(
                f"File {Path(file_path).name} verified at timestamp {timestamp}"
            )
        else:
            logger.warning(
                f"File {Path(file_path).name} could not be verified at timestamp {timestamp}"
            )

        return result

    def verify_params_at_time(
        self, params_dict: Dict[str, Any], timestamp: str
    ) -> Dict[str, Any]:
        """
        Verify if parameters existed at a specific timestamp.

        Args:
            params_dict: Dictionary of parameters to verify
            timestamp: Timestamp to check (format: 'YYYY-MM-DD HH:MM:SS')

        Returns:
            Verification result dictionary
        """
        # Get all matches for the parameters
        matches = self.verify_params(params_dict)

        # Parse the target timestamp
        try:
            target_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise ValueError(
                f"Invalid timestamp format: {timestamp}. Use 'YYYY-MM-DD HH:MM:SS'"
            )

        # Find the closest transaction before or at the target time
        closest_match = None
        min_time_diff = float("inf")

        for match in matches:
            try:
                tx_time = datetime.datetime.strptime(match["date"], "%Y-%m-%d %H:%M:%S")
                time_diff = (target_time - tx_time).total_seconds()

                # Only consider transactions before or at the target time
                if time_diff >= 0 and time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_match = match
            except ValueError:
                logger.warning(f"Could not parse date: {match['date']}")

        result = {
            "params_str": self.format_params_dict(params_dict),
            "target_timestamp": timestamp,
            "verification_result": False,
            "match_found": closest_match is not None,
            "time_difference_seconds": min_time_diff if closest_match else None,
            "match_details": closest_match,
        }

        if closest_match:
            result["verification_result"] = True
            logger.info(f"Parameters verified at timestamp {timestamp}")
        else:
            logger.warning(f"Parameters could not be verified at timestamp {timestamp}")

        return result

    def generate_audit_report(
        self,
        files_to_verify: List[Dict[str, str]],
        params_dict: Optional[Dict[str, Any]] = None,
        target_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive audit report for files and parameters.

        Args:
            files_to_verify: List of dictionaries with file paths and types
                             [{"path": "/path/to/file.csv", "type": "book"}, ...]
            params_dict: Optional dictionary of parameters to verify
            target_timestamp: Optional timestamp to verify existence at a specific time

        Returns:
            Audit report dictionary
        """
        report = {
            "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "csv_file": str(self.csv_path),
            "transaction_count": len(self.transactions),
            "target_timestamp": target_timestamp,
            "file_verifications": [],
            "params_verification": None,
            "all_verified": True,
        }

        # Verify each file
        for file_info in files_to_verify:
            file_path = file_info["path"]
            file_type = file_info["type"]

            if target_timestamp:
                verification = self.verify_file_at_time(
                    file_path, file_type, target_timestamp
                )
            else:
                matches = self.verify_file(file_path, file_type)
                verification = {
                    "file_name": Path(file_path).name,
                    "file_type": file_type,
                    "verification_result": len(matches) > 0,
                    "match_count": len(matches),
                    "matches": matches,
                }

            report["file_verifications"].append(verification)
            report["all_verified"] = (
                report["all_verified"] and verification["verification_result"]
            )

        # Verify parameters if provided
        if params_dict:
            if target_timestamp:
                params_verification = self.verify_params_at_time(
                    params_dict, target_timestamp
                )
            else:
                matches = self.verify_params(params_dict)
                params_verification = {
                    "params_str": self.format_params_dict(params_dict),
                    "verification_result": len(matches) > 0,
                    "match_count": len(matches),
                    "matches": matches,
                }

            report["params_verification"] = params_verification
            report["all_verified"] = (
                report["all_verified"] and params_verification["verification_result"]
            )

        return report

    def print_audit_report(self, report: Dict[str, Any]) -> None:
        """
        Print a formatted audit report to the console.

        Args:
            report: Audit report dictionary from generate_audit_report
        """
        print("=" * 80)
        print("BLOCKCHAIN FILE INTEGRITY AUDIT REPORT")
        print("=" * 80)
        print(f"Audit Date: {report['audit_date']}")
        print(f"CSV Transaction Record: {report['csv_file']}")
        print(f"Transaction Count: {report['transaction_count']}")

        if report.get("target_timestamp"):
            print(f"Target Timestamp: {report['target_timestamp']}")

        print("\n" + "-" * 80)
        print("FILE VERIFICATION RESULTS:")

        for verification in report["file_verifications"]:
            print(
                f"\n{verification['file_type'].upper()} FILE: {verification['file_name']}"
            )
            if verification["verification_result"]:
                print("✅ VERIFICATION SUCCESSFUL")

                if "match_count" in verification:
                    print(f"  Match Count: {verification['match_count']}")

                    # Show the most recent match
                    if verification["matches"]:
                        most_recent = verification["matches"][-1]
                        print(f"  Most Recent Match:")
                        print(f"    Transaction: {most_recent['transaction_id']}")
                        print(f"    Date: {most_recent['date']}")

                if (
                    "time_difference_seconds" in verification
                    and verification["time_difference_seconds"] is not None
                ):
                    time_diff = verification["time_difference_seconds"]
                    if time_diff < 60:
                        time_str = f"{time_diff:.1f} seconds"
                    elif time_diff < 3600:
                        time_str = f"{time_diff/60:.1f} minutes"
                    else:
                        time_str = f"{time_diff/3600:.1f} hours"

                    print(f"  Time Difference: {time_str} before target timestamp")
            else:
                print("❌ VERIFICATION FAILED")
                print("  No matching records found")

        if report.get("params_verification"):
            print("\n" + "-" * 80)
            print("PARAMETERS VERIFICATION RESULTS:")

            params_verification = report["params_verification"]
            if params_verification["verification_result"]:
                print("✅ VERIFICATION SUCCESSFUL")

                if "match_count" in params_verification:
                    print(f"  Match Count: {params_verification['match_count']}")

                    # Show the most recent match
                    if params_verification.get("matches"):
                        most_recent = params_verification["matches"][-1]
                        print(f"  Most Recent Match:")
                        print(f"    Transaction: {most_recent['transaction_id']}")
                        print(f"    Date: {most_recent['date']}")

                if (
                    "time_difference_seconds" in params_verification
                    and params_verification["time_difference_seconds"] is not None
                ):
                    time_diff = params_verification["time_difference_seconds"]
                    if time_diff < 60:
                        time_str = f"{time_diff:.1f} seconds"
                    elif time_diff < 3600:
                        time_str = f"{time_diff/60:.1f} minutes"
                    else:
                        time_str = f"{time_diff/3600:.1f} hours"

                    print(f"  Time Difference: {time_str} before target timestamp")
            else:
                print("❌ VERIFICATION FAILED")
                print("  No matching records found")

        # Overall conclusion
        print("\n" + "=" * 80)
        print("AUDIT CONCLUSION:")
        if report["all_verified"]:
            print("✅ All files and parameters have been verified successfully.")
            print("The data integrity is confirmed. No modifications detected.")
        else:
            print("❌ Some verifications failed. See the detailed report above.")
            print(
                "Data integrity issues detected. Files or parameters may have been modified."
            )
        print("=" * 80)
