# Modified audit_service.py - No metadata dependency
import logging
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from utils.hash_file_utils import calculate_file_hash
from services.crypto_service import verify_signature, sign_hash, load_private_key

logger = logging.getLogger(__name__)


class AuditService:
    """Service for auditing and verifying file and parameter integrity against blockchain records."""

    def __init__(self):
        """Initialize the audit service."""
        pass

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

    def verify_file_against_blockchain(
        self,
        file_path: Union[str, Path],
        file_type: str,
        passphrase: str,  # Just need the passphrase, not private key
        blockchain_hashes: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        Verify a file against blockchain hashes using deterministic signing.

        Args:
            file_path: Path to the file to verify
            file_type: Type of file ('book' or 'research')
            passphrase: The secret passphrase for signing
            blockchain_hashes: Dictionary containing hashes from blockchain

        Returns:
            Verification result dictionary
        """
        try:
            # Convert path to Path object if string
            file_path = Path(file_path)

            # Calculate current file hash
            current_hash = calculate_file_hash(file_path)
            logger.info(f"VERIFICATION TRACE - File: {file_path.name}")
            logger.info(f"VERIFICATION TRACE - Current File Hash: {current_hash}")

            # Sign the hash deterministically using the passphrase
            from services.crypto_service import sign_hash_deterministic

            signed_hash = sign_hash_deterministic(current_hash, passphrase)
            logger.info(f"VERIFICATION TRACE - Deterministic Signature: {signed_hash}")

            # Hash the signature to get what should be on the blockchain
            signature_hash = hashlib.sha256(signed_hash.encode()).hexdigest()
            logger.info(
                f"VERIFICATION TRACE - Signature Hash (for blockchain): {signature_hash}"
            )

            # Determine which hash collection to check
            hash_list = (
                blockchain_hashes["book_hash"]
                if file_type.lower() == "book"
                else blockchain_hashes["research_hash"]
            )
            logger.info(
                f"VERIFICATION TRACE - Available blockchain hashes: {hash_list}"
            )

            # Check if our signature hash exists in the blockchain data
            hash_match = signature_hash in hash_list
            logger.info(f"VERIFICATION TRACE - Hash Match: {hash_match}")

            # Return verification result
            return {
                "verified": hash_match,
                "file": file_path.name,
                "file_type": file_type,
                "original_hash": current_hash,
                "deterministic_signature": signed_hash,
                "signature_hash": signature_hash,
                "blockchain_match": hash_match,
            }

        except Exception as e:
            logger.error(f"Error verifying file: {e}")
            import traceback

            traceback.print_exc()
            return {"verified": False, "file": Path(file_path).name, "error": str(e)}

    def verify_params_against_blockchain(
        self,
        params_dict: Dict[str, Any],
        passphrase: str,  # Just use passphrase like we do with files
        blockchain_hashes: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        Verify parameters against blockchain records using deterministic signing.

        Args:
            params_dict: Dictionary of parameters to verify
            passphrase: The secret passphrase for signing
            blockchain_hashes: Dictionary containing hashes from blockchain

        Returns:
            Verification result dictionary
        """
        try:
            # Format parameters to standardized string
            params_str = self.format_params_dict(params_dict)
            logger.info(f"VERIFICATION TRACE - Parameters String: {params_str}")

            # Sign the parameters deterministically using the passphrase
            from services.crypto_service import sign_hash_deterministic

            signed_params = sign_hash_deterministic(params_str, passphrase)
            logger.info(
                f"VERIFICATION TRACE - Deterministic Params Signature: {signed_params}"
            )

            # Hash the signature to get what should be on the blockchain
            params_signature_hash = hashlib.sha256(signed_params.encode()).hexdigest()
            logger.info(
                f"VERIFICATION TRACE - Params Signature Hash (for blockchain): {params_signature_hash}"
            )

            # Check if the signature hash exists in blockchain data
            hash_match = params_signature_hash in blockchain_hashes["params"]
            logger.info(f"VERIFICATION TRACE - Params Hash Match: {hash_match}")

            if not hash_match:
                logger.error(
                    f"VERIFICATION TRACE - Params hash not found in blockchain. Available hashes: {blockchain_hashes['params']}"
                )

            # Return verification result
            return {
                "verified": hash_match,
                "params_str": params_str,
                "hash_match": hash_match,
                "deterministic_signature": signed_params,
                "signature_hash": params_signature_hash,
            }

        except Exception as e:
            logger.error(f"Error verifying parameters: {e}")
            import traceback

            traceback.print_exc()
            return {"verified": False, "error": str(e)}

    def generate_audit_report(
        self,
        files_to_verify: List[Dict[str, str]],
        params_dict: Optional[Dict[str, Any]],
        passphrase: str,  # Just passphrase, not private key
        blockchain_hashes: Dict[str, List[str]],
        transaction_count: int,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive audit report for files and parameters.

        Args:
            files_to_verify: List of dictionaries with file paths and types
            params_dict: Optional dictionary of parameters to verify
            passphrase: The secret passphrase for signing
            blockchain_hashes: Dictionary containing hashes from blockchain
            transaction_count: Count of transactions in blockchain data

        Returns:
            Audit report dictionary
        """
        import datetime

        # Initialize the report
        report = {
            "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "transaction_count": transaction_count,
            "file_verifications": [],
            "params_verification": None,
            "all_verified": True,
        }

        # Verify each file
        for file_info in files_to_verify:
            file_path = file_info["path"]
            file_type = file_info["type"]

            # Verify the file
            verification = self.verify_file_against_blockchain(
                file_path, file_type, passphrase, blockchain_hashes
            )

            report["file_verifications"].append(verification)
            report["all_verified"] = report["all_verified"] and verification.get(
                "verified", False
            )

        # Verify parameters if provided
        if params_dict:
            params_verification = self.verify_params_against_blockchain(
                params_dict, passphrase, blockchain_hashes
            )

            report["params_verification"] = params_verification
            report["all_verified"] = report["all_verified"] and params_verification.get(
                "verified", False
            )

        return report

    def print_audit_report(self, report: Dict[str, Any]) -> None:
        """
        Print a formatted audit report to the console.

        Args:
            report: Audit report dictionary
        """
        print("\n" + "=" * 80)
        print("BLOCKCHAIN FILE INTEGRITY AUDIT REPORT")
        print("=" * 80)
        print(f"Audit Date: {report['audit_date']}")
        print(f"Transaction Count: {report['transaction_count']}")

        print("\n" + "-" * 80)
        print("FILE VERIFICATION RESULTS:")

        for verification in report["file_verifications"]:
            file_name = verification.get("file", "Unknown file")
            file_type = verification.get("file_type", "")

            print(f"\nFILE: {file_name} ({file_type})")
            if verification.get("verified", False):
                print("✅ VERIFICATION SUCCESSFUL")
                print(f"  Original Hash: {verification.get('original_hash', 'N/A')}")
                print(f"  Signature: {verification.get('signature', 'N/A')}")
                print(f"  Signature Hash: {verification.get('signature_hash', 'N/A')}")
                print(f"  Found in blockchain: Yes")
            else:
                print("❌ VERIFICATION FAILED")
                if "error" in verification:
                    print(f"  Error: {verification['error']}")
                else:
                    print(
                        f"  Original Hash: {verification.get('original_hash', 'N/A')}"
                    )
                    print(f"  Signature: {verification.get('signature', 'N/A')}")
                    print(
                        f"  Signature Hash: {verification.get('signature_hash', 'N/A')}"
                    )
                    print(f"  Found in blockchain: No")

        if report.get("params_verification"):
            print("\n" + "-" * 80)
            print("PARAMETERS VERIFICATION RESULTS:")

            params_verification = report["params_verification"]
            if params_verification.get("verified", False):
                print("✅ VERIFICATION SUCCESSFUL")
                print(f"  Parameters: {params_verification.get('params_str', 'N/A')}")
                print(f"  Signature: {params_verification.get('signature', 'N/A')}")
                print(
                    f"  Signature Hash: {params_verification.get('signature_hash', 'N/A')}"
                )
                print(f"  Found in blockchain: Yes")
            else:
                print("❌ VERIFICATION FAILED")
                if "error" in params_verification:
                    print(f"  Error: {params_verification['error']}")
                else:
                    print(
                        f"  Parameters: {params_verification.get('params_str', 'N/A')}"
                    )
                    print(f"  Signature: {params_verification.get('signature', 'N/A')}")
                    print(
                        f"  Signature Hash: {params_verification.get('signature_hash', 'N/A')}"
                    )
                    print(f"  Found in blockchain: No")

        # Overall conclusion
        print("\n" + "=" * 80)
        print("AUDIT CONCLUSION:")
        if report["all_verified"]:
            print("✅ All files and parameters have been verified successfully.")
            print("The data integrity is confirmed. No modifications detected.")
        else:
            print("❌ Some verifications failed. See the detailed report above.")
            print("Data integrity issues detected or files may have been modified.")
        print("=" * 80)

    def save_audit_report(
        self, report: Dict[str, Any], output_path: Union[str, Path]
    ) -> Path:
        """
        Save the audit report to a file.

        Args:
            report: The audit report dictionary
            output_path: Path to save the report to

        Returns:
            Path to the saved report
        """
        output_path = Path(output_path)

        # Create directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Audit report saved to {output_path}")
        return output_path
