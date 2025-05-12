# services/file_integrity_service.py
import os
import time
import shutil
import logging
import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List, Union

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

    def store_file(
        self, file_path: Union[str, Path], user_id: str, book_id: str, file_type: str
    ) -> Path:
        """
        Store a file in the appropriate directory.

        Args:
            file_path: Path to the file to store
            user_id: User identifier
            book_id: Book identifier
            file_type: Type of file ('book' or 'research')

        Returns:
            Path to the stored file
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Determine destination directory
        if file_type.lower() == "book":
            dest_dir = self.book_data_dir
            extension = file_path.suffix or ".csv"
        elif file_type.lower() == "research":
            dest_dir = self.research_dir
            extension = file_path.suffix or ".pdf"
        else:
            raise ValueError(
                f"Invalid file type: {file_type}. Must be 'book' or 'research'"
            )

        # Create a timestamped filename
        timestamp = int(time.time())
        dest_filename = f"{user_id}_{book_id}_{file_type}_{timestamp}{extension}"
        dest_path = dest_dir / dest_filename

        # Copy the file
        shutil.copy2(file_path, dest_path)
        logger.info(f"Stored {file_type} file for {user_id}/{book_id} at {dest_path}")

        return dest_path

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
        store_files: bool = True,
    ) -> Dict[str, str]:
        """
        Calculate hashes for the book file and optionally research file.

        Args:
            user_id: User identifier
            book_id: Book identifier
            book_file_path: Path to the book data file (required)
            research_file_path: Path to the research file (optional)
            store_files: Whether to store copies of the files

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

        # Store files if requested
        if store_files:
            # Store book file
            book_stored_path = self.store_file(book_file_path, user_id, book_id, "book")
            result["book_stored_path"] = (
                book_stored_path  # Add this line to store the path
            )

            # Store research file if provided
            research_stored_path = None
            if research_file_path and Path(research_file_path).exists():
                research_stored_path = self.store_file(
                    research_file_path, user_id, book_id, "research"
                )
                result["research_stored_path"] = (
                    research_stored_path  # Add this line to store the path
                )

        return result

    def update_contract_with_file_hashes(
        self,
        user_id: str,
        book_id: str,
        book_file_path: Union[str, Path],
        research_file_path: Optional[Union[str, Path]] = None,
        additional_params: Optional[Dict[str, str]] = None,
        store_files: bool = True,
    ) -> bool:
        """
        Update the smart contract with file hashes.
        """
        try:
            # Calculate hashes
            hashes = self.calculate_and_store_hashes(
                user_id, book_id, book_file_path, research_file_path, store_files
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

            # Store the full parameters metadata
            if store_files:
                # Include current timestamp only in metadata, not in the hashed parameters
                metadata = {
                    "user_id": user_id,
                    "book_id": book_id,
                    "timestamp": time.time(),  # For metadata only
                    "params_hash": params_hash,
                    "full_params": params_dict,
                    "full_params_str": full_params_str,
                    "book_file": {
                        "path": str(hashes.get("book_stored_path", "")),
                        "hash": book_hash,
                        "original_filename": Path(book_file_path).name,
                    },
                }

                # Add research file metadata if available
                if research_file_path and research_hash:
                    metadata["research_file"] = {
                        "path": str(hashes.get("research_stored_path", "")),
                        "hash": research_hash,
                        "original_filename": Path(research_file_path).name,
                    }

                metadata_path = (
                    STORAGE_ROOT / f"{user_id}_{book_id}_{params_hash}_metadata.json"
                )
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                logger.info(f"Stored full params metadata in {metadata_path}")

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
