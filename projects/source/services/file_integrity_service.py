# services/file_integrity_service.py
import time
import shutil
import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

import config
from utils.hash_file_utils import calculate_file_hash
from services.user_contract_service import update_user_local_state
from utils.algorand import get_user_local_state

logger = logging.getLogger(__name__)

# Create storage directories if they don't exist
STORAGE_ROOT = Path(config.BASE_DIR) / "storage" / "files"
BOOK_DATA_DIR = STORAGE_ROOT / "book_data"
RESEARCH_DIR = STORAGE_ROOT / "research"

for directory in [STORAGE_ROOT, BOOK_DATA_DIR, RESEARCH_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


class FileIntegrityService:
    """Service for managing file integrity verification using blockchain."""

    def __init__(self):
        self.book_data_dir = BOOK_DATA_DIR
        self.research_dir = RESEARCH_DIR

    def hash_params_string(self, params_str: str) -> str:
        """
        Create a hash of the parameters string.

        Args:
            params_str: The full parameters string

        Returns:
            Hash of the parameters string
        """
        import hashlib

        return hashlib.sha256(params_str.encode()).hexdigest()

    def calculate_and_store_hashes(
        self,
        user_id: str,
        book_id: str,
        book_file_path: Union[str, Path],
        research_file_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, str]:
        """
        Calculate hashes for the book file and optionally research file.

        Args:
            user_id: User identifier
            book_id: Book identifier
            book_file_path: Path to the book data file (required)
            research_file_path: Path to the research file (optional)

        Returns:
            Dictionary with book_hash and optional research_hash
        """
        # Calculate book hash (required)
        book_hash = calculate_file_hash(book_file_path)
        logger.info(f"Generated book hash: {book_hash} for {Path(book_file_path).name}")

        # Initialize result dictionary
        result = {"book_hash": book_hash}

        # Calculate research hash (optional)
        research_hash = ""
        if research_file_path:
            try:
                research_file_path = Path(research_file_path)
                if research_file_path.exists():
                    research_hash = calculate_file_hash(research_file_path)
                    logger.info(
                        f"Generated research hash: {research_hash} for {research_file_path.name}"
                    )
                    result["research_hash"] = research_hash
                else:
                    logger.warning(f"Research file not found: {research_file_path}")
            except Exception as e:
                logger.error(f"Error calculating research file hash: {e}")
        else:
            logger.info("No research file provided, using empty research hash")

        result["research_hash"] = research_hash

        return result

    def update_contract_with_signed_hashes(
        self,
        user_id: str,
        book_id: str,
        book_file_path: Union[str, Path],
        private_key_path: Union[str, Path],
        research_file_path: Optional[Union[str, Path]] = None,
        additional_params: Optional[Dict[str, str]] = None,
        passphrase: Optional[str] = None,
    ) -> bool:
        """
        Update the smart contract with cryptographically signed file hashes.

        Args:
            user_id: User identifier
            book_id: Book identifier
            book_file_path: Path to the book data file
            private_key_path: Path to the private key PEM file
            research_file_path: Path to the research file (optional)
            additional_params: Additional parameters to include (optional)
            passphrase: Passphrase to decrypt private key if encrypted

        Returns:
            True if successful, False otherwise
        """
        try:
            from services.crypto_service import sign_hash, load_private_key
            from cryptography.hazmat.primitives import serialization

            # Load private key with passphrase if provided
            private_key = load_private_key(private_key_path, passphrase)

            # Get private key in PEM format for signing
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Calculate hashes
            hashes = self.calculate_and_store_hashes(
                user_id, book_id, book_file_path, research_file_path
            )

            # Get file hashes
            book_hash = hashes["book_hash"]
            research_hash = hashes.get("research_hash", "")

            # Sign the hashes
            signed_book_hash = sign_hash(book_hash, private_key_pem)
            signed_research_hash = (
                sign_hash(research_hash, private_key_pem) if research_hash else ""
            )

            # Create parameters dictionary
            params_dict = {
                "book_file": Path(book_file_path).name,
                "user": user_id,
                "book": book_id,
            }

            # Add research file if provided
            if research_file_path and research_hash:
                params_dict["research_file"] = Path(research_file_path).name

            # Add additional parameters
            if additional_params:
                params_dict.update(additional_params)

            # Format and hash parameters
            params_str = "|".join([f"{k}:{v}" for k, v in sorted(params_dict.items())])
            signed_params = sign_hash(params_str, private_key_pem)

            # Update blockchain with signed hashes
            from services.user_contract_service import update_user_local_state

            result = update_user_local_state(
                user_id, book_id, signed_book_hash, signed_research_hash, signed_params
            )

            if result:
                logger.info(
                    f"Successfully updated contract with signed hashes for {user_id}/{book_id}"
                )
            else:
                logger.error(
                    f"Failed to update contract with signed hashes for {user_id}/{book_id}"
                )

            return result

        except Exception as e:
            logger.error(f"Error updating contract with signed hashes: {e}")
            return False

    def update_contract_with_file_hashes(
        self,
        user_id: str,
        book_id: str,
        book_file_path: Union[str, Path],
        research_file_path: Optional[Union[str, Path]] = None,
        additional_params: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Update the smart contract with file hashes.
        """
        try:
            # Calculate hashes
            hashes = self.calculate_and_store_hashes(
                user_id, book_id, book_file_path, research_file_path
            )

            book_hash = hashes["book_hash"]
            research_hash = hashes.get(
                "research_hash", ""
            )  # Empty string if not provided

            # Create a parameter string with file metadata
            params_dict = {
                "book_file": Path(book_file_path).name,
                "user": user_id,
                "book": book_id,
                # No timestamp included here
            }

            # Add research file if provided
            if research_file_path and research_hash:
                params_dict["research_file"] = Path(research_file_path).name

            # Add any additional parameters
            if additional_params:
                params_dict.update(additional_params)

            # Convert to string format - sort by key for consistency
            full_params_str = "|".join(
                [f"{k}:{v}" for k, v in sorted(params_dict.items())]
            )

            # Generate a hash of the parameters string
            params_hash = self.hash_params_string(full_params_str)

            # Use just the hash directly as the params string
            params_str = params_hash

            # Update the contract's local state with hash values
            result = update_user_local_state(
                user_id, book_id, book_hash, research_hash, params_str
            )

            if result:
                logger.info(
                    f"Successfully updated contract with file hashes for {user_id}/{book_id}"
                )
            else:
                logger.error(
                    f"Failed to update contract with file hashes for {user_id}/{book_id}"
                )

            return result
        except Exception as e:
            logger.error(f"Error updating contract with file hashes: {e}")
            return False

    def verify_file(
        self, user_id: str, book_id: str, file_path: Union[str, Path], file_type: str
    ) -> bool:
        """
        Verify if a file matches the hash stored on the blockchain.

        Args:
            user_id: User identifier
            book_id: Book identifier
            file_path: Path to the file to verify
            file_type: Type of file ('book' or 'research')

        Returns:
            True if the file matches the stored hash, False otherwise
        """
        from services.contract_service import get_contract_for_user_book

        try:
            # Get contract info
            contract_info = get_contract_for_user_book(user_id, book_id)
            if not contract_info:
                logger.error(f"No contract found for user {user_id} and book {book_id}")
                return False

            app_id = contract_info["app_id"]
            user_address = contract_info["user_address"]

            # Get the local state
            local_state = get_user_local_state(app_id, user_address)

            # Get the stored hash
            if file_type.lower() == "book":
                hash_name = "book_hash"
                stored_hash = local_state.get(hash_name, "").replace("String: ", "")
                if not stored_hash:
                    logger.error(f"No {hash_name} found in contract")
                    return False
            elif file_type.lower() == "research":
                hash_name = "research_hash"
                stored_hash = local_state.get(hash_name, "").replace("String: ", "")
                if not stored_hash:
                    logger.warning(f"No {hash_name} found in contract")
                    # Not an error since research hash is optional
                    return False
            else:
                raise ValueError(
                    f"Invalid file type: {file_type}. Must be 'book' or 'research'"
                )

            # Calculate the current file hash
            current_hash = calculate_file_hash(file_path)

            # Compare the hashes
            match = current_hash == stored_hash

            if match:
                logger.info(
                    f"File {Path(file_path).name} matches the {hash_name} stored on the blockchain"
                )
            else:
                logger.warning(
                    f"File {Path(file_path).name} does NOT match the {hash_name} stored on the blockchain.\n"
                    f"Stored hash: {stored_hash}\n"
                    f"Current hash: {current_hash}"
                )

            return match
        except Exception as e:
            logger.error(f"Error verifying file: {e}")
            return False

    # Add this new method
    def verify_params(
        self,
        user_id: str,
        book_id: str,
        params_dict: Dict[str, str],
        params_hash: str = None,
    ) -> bool:
        """
        Verify if a parameters dictionary matches a hash stored on the blockchain.

        Args:
            user_id: User identifier
            book_id: Book identifier
            params_dict: Dictionary of parameters to verify
            params_hash: Optional known hash to verify against (otherwise retrieved from blockchain)

        Returns:
            True if the parameters match, False otherwise
        """
        try:
            # Convert dict to string format
            params_str = "|".join([f"{k}:{v}" for k, v in sorted(params_dict.items())])

            # Generate hash from provided params
            calculated_hash = self.hash_params_string(params_str)

            # If no hash provided, get from blockchain
            if not params_hash:
                # Get contract info
                from services.contract_service import get_contract_for_user_book

                contract_info = get_contract_for_user_book(user_id, book_id)
                if not contract_info:
                    logger.error(
                        f"No contract found for user {user_id} and book {book_id}"
                    )
                    return False

                app_id = contract_info["app_id"]
                user_address = contract_info["user_address"]

                # Get the local state
                from utils.algorand import get_user_local_state

                local_state = get_user_local_state(app_id, user_address)

                # Get the stored params string
                stored_params = local_state.get("params", "").replace("String: ", "")

                params_hash = stored_params

            # Compare hashes
            match = calculated_hash == params_hash

            if match:
                logger.info(
                    f"Parameters verified successfully against hash {params_hash}"
                )
            else:
                logger.warning(
                    f"Parameters do NOT match the stored hash.\n"
                    f"Stored hash: {params_hash}\n"
                    f"Calculated hash: {calculated_hash}"
                )

            return match
        except Exception as e:
            logger.error(f"Error verifying parameters: {e}")
            return False

    def get_file_history(self, user_id: str, book_id: str) -> List[Dict[str, Any]]:
        """
        Get the history of file hashes for a user/book from the blockchain transactions.

        Args:
            user_id: User identifier
            book_id: Book identifier

        Returns:
            List of file hash records from the transaction history
        """
        from services.explorer_service import explore_contract

        try:
            # Get explorer data
            explorer_info = explore_contract(user_id, book_id, include_csv=False)

            if not explorer_info:
                logger.error(f"No explorer data found for {user_id}/{book_id}")
                return []

            # Extract file hash history from transactions
            history = []

            for tx in explorer_info.get("transaction_history", []):
                # Only look at update_local transactions from the user
                if (
                    tx.get("app_args")
                    and len(tx.get("app_args", [])) > 0
                    and "update_local" in str(tx.get("app_args", [])[0])
                ):
                    # Get state at this point
                    state = tx.get("tracked_state", {})
                    local_state = state.get("local_state", {})

                    # Book hash is required, params is optional
                    if "book_hash" in local_state:
                        record = {
                            "timestamp": tx.get("timestamp"),
                            "date": tx.get("date"),
                            "transaction_id": tx.get("id"),
                            "book_hash": local_state.get("book_hash"),
                        }

                        # Add research hash if exists
                        if "research_hash" in local_state and local_state.get(
                            "research_hash"
                        ):
                            record["research_hash"] = local_state.get("research_hash")

                        # Add params if exists

                        if "params" in local_state and local_state.get("params"):
                            params_str = local_state.get("params")
                            record["params"] = params_str

                            # Assume the params is directly the hash
                            params_hash = params_str
                            record["params_hash"] = params_hash

                            # Check if we can find the full params metadata
                            metadata_paths = list(
                                STORAGE_ROOT.glob(
                                    f"{user_id}_{book_id}_{params_hash}_metadata.json"
                                )
                            )
                            if metadata_paths:
                                try:
                                    with open(metadata_paths[0], "r") as f:
                                        metadata = json.load(f)
                                    record["full_params"] = metadata.get(
                                        "full_params", {}
                                    )
                                    record["params_decoded"] = True
                                except Exception as e:
                                    logger.warning(
                                        f"Error loading params metadata: {e}"
                                    )
                                    record["params_decoded"] = False
                            else:
                                record["params_decoded"] = False

                        history.append(record)

            return history
        except Exception as e:
            logger.error(f"Error getting file history: {e}")
            return []

    def verify_signed_file(
        self,
        file_path: Union[str, Path],
        file_type: str,
        public_key_path: Union[str, Path],
    ) -> List[Dict[str, Any]]:
        """
        Verify a file against cryptographically signed hashes in transaction records.

        Args:
            file_path: Path to the file to verify
            file_type: Type of file ('book' or 'research')
            public_key_path: Path to the public key PEM file

        Returns:
            List of matching transaction records
        """
        from services.crypto_service import verify_signature

        # Load public key
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()

        # Calculate file hash
        file_path = Path(file_path)
        current_hash = self.calculate_file_hash(file_path)
        logger.info(f"Calculated hash for {file_path.name}: {current_hash}")

        # Determine column name
        hash_column = f"l_{file_type.lower()}_hash"

        # Find matching transactions with valid signatures
        matches = []
        for tx in self.transactions:
            if hash_column not in tx:
                continue

            signed_hash = tx[hash_column]
            if not signed_hash or signed_hash == "NAN":
                continue

            # Verify signature
            is_valid = verify_signature(current_hash, signed_hash, public_key_pem)

            if is_valid:
                match_info = {
                    "transaction_id": tx["transaction_id"],
                    "date": tx["date"],
                    "sender": tx["sender"],
                    "signed_hash": signed_hash,
                    "original_hash": current_hash,
                    "is_valid": is_valid,
                    "file_name": file_path.name,
                    "file_type": file_type,
                }
                matches.append(match_info)

        if matches:
            logger.info(
                f"File {file_path.name} has {len(matches)} valid signed records"
            )
        else:
            logger.warning(f"File {file_path.name} has no valid signed records")

        return matches

    def verify_signed_params(
        self, params_dict: Dict[str, Any], public_key_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """
        Verify parameters against cryptographically signed hashes in transaction records.

        Args:
            params_dict: Dictionary of parameters to verify
            public_key_path: Path to the public key PEM file

        Returns:
            List of matching transaction records
        """
        from services.crypto_service import verify_signature

        # Load public key
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()

        # Format parameters
        params_str = self.format_params_dict(params_dict)
        logger.info(f"Formatted parameters: {params_str}")

        # Find matching transactions with valid signatures
        matches = []
        for tx in self.transactions:
            if "l_params" not in tx:
                continue

            signed_params = tx["l_params"]
            if not signed_params or signed_params == "NAN":
                continue

            # Verify signature
            is_valid = verify_signature(params_str, signed_params, public_key_pem)

            if is_valid:
                match_info = {
                    "transaction_id": tx["transaction_id"],
                    "date": tx["date"],
                    "sender": tx["sender"],
                    "signed_hash": signed_params,
                    "params_str": params_str,
                    "is_valid": is_valid,
                }
                matches.append(match_info)

        if matches:
            logger.info(f"Parameters have {len(matches)} valid signed records")
        else:
            logger.warning(f"Parameters have no valid signed records")

        return matches

    def generate_secure_audit_report(
        self,
        files_to_verify: List[Dict[str, str]],
        params_dict: Optional[Dict[str, Any]],
        public_key_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive audit report using cryptographic verification.

        Args:
            files_to_verify: List of dictionaries with file paths and types
            params_dict: Optional dictionary of parameters to verify
            public_key_path: Path to the public key for signature verification

        Returns:
            Audit report dictionary
        """
        report = {
            "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "csv_file": str(self.csv_path),
            "transaction_count": len(self.transactions),
            "public_key_path": str(public_key_path),
            "file_verifications": [],
            "params_verification": None,
            "all_verified": True,
        }

        # Verify each file
        for file_info in files_to_verify:
            file_path = file_info["path"]
            file_type = file_info["type"]

            matches = self.verify_signed_file(file_path, file_type, public_key_path)
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
            matches = self.verify_signed_params(params_dict, public_key_path)
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

    def print_secure_audit_report(self, report: Dict[str, Any]) -> None:
        """
        Print a formatted secure audit report to the console.

        Args:
            report: Secure audit report dictionary
        """
        print("=" * 80)
        print("SECURE BLOCKCHAIN FILE INTEGRITY AUDIT REPORT")
        print("=" * 80)
        print(f"Audit Date: {report['audit_date']}")
        print(f"CSV Transaction Record: {report['csv_file']}")
        print(f"Transaction Count: {report['transaction_count']}")
        print(f"Public Key: {report['public_key_path']}")

        print("\n" + "-" * 80)
        print("CRYPTOGRAPHICALLY VERIFIED FILE RESULTS:")

        for verification in report["file_verifications"]:
            print(
                f"\n{verification['file_type'].upper()} FILE: {verification['file_name']}"
            )
            if verification["verification_result"]:
                print("✅ VERIFICATION SUCCESSFUL - SIGNATURE VALID")
                print(f"  Match Count: {verification['match_count']}")

                # Show the most recent match
                if verification["matches"]:
                    most_recent = verification["matches"][-1]
                    print(f"  Most Recent Verified Transaction:")
                    print(f"    Transaction ID: {most_recent['transaction_id']}")
                    print(f"    Date: {most_recent['date']}")
            else:
                print("❌ VERIFICATION FAILED - NO VALID SIGNATURE")
                print("  No matching records found with valid signatures")

        if report.get("params_verification"):
            print("\n" + "-" * 80)
            print("CRYPTOGRAPHICALLY VERIFIED PARAMETERS RESULTS:")

            params_verification = report["params_verification"]
            if params_verification["verification_result"]:
                print("✅ VERIFICATION SUCCESSFUL - SIGNATURE VALID")
                print(f"  Match Count: {params_verification['match_count']}")

                # Show the most recent match
                if params_verification.get("matches"):
                    most_recent = params_verification["matches"][-1]
                    print(f"  Most Recent Verified Transaction:")
                    print(f"    Transaction ID: {most_recent['transaction_id']}")
                    print(f"    Date: {most_recent['date']}")
            else:
                print("❌ VERIFICATION FAILED - NO VALID SIGNATURE")
                print("  No matching records found with valid signatures")

        # Overall conclusion
        print("\n" + "=" * 80)
        print("SECURE AUDIT CONCLUSION:")
        if report["all_verified"]:
            print(
                "✅ All files and parameters have been CRYPTOGRAPHICALLY verified successfully."
            )
            print("Both data integrity and AUTHENTICITY are confirmed.")
            print(
                "The signatures prove these files were registered by the genuine key owner."
            )
        else:
            print(
                "❌ Some cryptographic verifications failed. See the detailed report above."
            )
            print(
                "Either the files/parameters have been modified, the signatures are invalid,"
            )
            print("or the wrong public key was used for verification.")
        print("=" * 80)
