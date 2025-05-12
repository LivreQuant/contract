# services/file_integrity_service.py
import time
import logging
from pathlib import Path
from typing import Dict, Optional, Union

from utils.hash_file_utils import calculate_file_hash
from services.user_contract_service import update_user_local_state
from utils.algorand import get_user_local_state

logger = logging.getLogger(__name__)


class FileIntegrityService:
    """Service for managing file integrity verification using blockchain."""

    def __init__(self):
        pass

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

    # In services/file_integrity_service.py

    def update_contract_with_signed_hashes(
        self,
        user_id: str,
        book_id: str,
        book_file_path: Union[str, Path],
        private_key_path: Union[str, Path],
        research_file_path: Optional[Union[str, Path]] = None,
        additional_params: Optional[Dict[str, str]] = None,
        passphrase: Optional[str] = None,
        store_files: bool = False,
    ) -> bool:
        """
        Update the smart contract with cryptographically signed file hashes.
        """
        try:
            from services.crypto_service import sign_hash, load_private_key
            from cryptography.hazmat.primitives import serialization
            import hashlib

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

            # Enhanced logging for book file
            book_filename = Path(book_file_path).name
            logger.info(f"CRYPTO TRACE - Book File: {book_filename}")
            logger.info(f"CRYPTO TRACE - 1. Original File Hash: {book_hash}")

            # Sign the book hash
            signed_book_hash = sign_hash(book_hash, private_key_pem)
            logger.info(
                f"CRYPTO TRACE - 2. Signed Hash (truncated): {signed_book_hash[:50]}..."
            )

            # Hash the signature
            book_signature_hash = hashlib.sha256(signed_book_hash.encode()).hexdigest()
            logger.info(
                f"CRYPTO TRACE - 3. Final Hash Stored on Blockchain: {book_signature_hash}"
            )

            # Log crypto steps for research file if present
            if research_hash:
                research_filename = Path(research_file_path).name
                logger.info(f"CRYPTO TRACE - Research File: {research_filename}")
                logger.info(f"CRYPTO TRACE - 1. Original File Hash: {research_hash}")

                # Sign the research hash
                signed_research_hash = sign_hash(research_hash, private_key_pem)
                logger.info(
                    f"CRYPTO TRACE - 2. Signed Hash (truncated): {signed_research_hash[:50]}..."
                )

                # Hash the signature
                research_signature_hash = hashlib.sha256(
                    signed_research_hash.encode()
                ).hexdigest()
                logger.info(
                    f"CRYPTO TRACE - 3. Final Hash Stored on Blockchain: {research_signature_hash}"
                )
            else:
                signed_research_hash = ""
                research_signature_hash = ""

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

            # Format parameters and log the process
            params_str = "|".join([f"{k}:{v}" for k, v in sorted(params_dict.items())])
            logger.info(f"CRYPTO TRACE - Parameters String: {params_str}")

            # Sign the params
            signed_params = sign_hash(params_str, private_key_pem)
            logger.info(
                f"CRYPTO TRACE - Signed Parameters (truncated): {signed_params[:50]}..."
            )

            # Hash the signature
            params_signature_hash = hashlib.sha256(signed_params.encode()).hexdigest()
            logger.info(
                f"CRYPTO TRACE - Parameters Hash Stored on Blockchain: {params_signature_hash}"
            )

            # Store additional verification metadata locally (optional, but helpful)
            verification_metadata = {
                "user_id": user_id,
                "book_id": book_id,
                "timestamp": time.time(),
                "book_file": {
                    "name": book_filename,
                    "original_hash": book_hash,
                    "signature": signed_book_hash,
                    "signature_hash": book_signature_hash,
                },
                "params": {
                    "string": params_str,
                    "signature": signed_params,
                    "signature_hash": params_signature_hash,
                },
            }

            # Add research file data if available
            if research_hash:
                verification_metadata["research_file"] = {
                    "name": Path(research_file_path).name,
                    "original_hash": research_hash,
                    "signature": signed_research_hash,
                    "signature_hash": research_signature_hash,
                }

            # Save metadata to a local file for future verification
            metadata_dir = Path("verification_metadata")
            metadata_dir.mkdir(exist_ok=True)
            metadata_file = (
                metadata_dir / f"{user_id}_{book_id}_{int(time.time())}.json"
            )

            with open(metadata_file, "w") as f:
                import json

                json.dump(verification_metadata, f, indent=2)

            logger.info(
                f"CRYPTO TRACE - Verification metadata saved to {metadata_file}"
            )

            # Update blockchain with hashed signatures
            from services.user_contract_service import update_user_local_state

            result = update_user_local_state(
                user_id,
                book_id,
                book_signature_hash,
                research_signature_hash,
                params_signature_hash,
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
            import traceback

            traceback.print_exc()
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
