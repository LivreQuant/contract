import logging
from typing import Any, Dict

import algokit_utils
from algosdk import mnemonic

from smart_contracts.artifacts.assets_contract.assets_contract_client import (
    AssetsContractClient,
    AssetsContractFactory
)
from projects.trader.smart_contracts.service.config import (
    ALGOD_TOKEN, ALGOD_SERVER, ALGOD_PORT,
    INDEXER_TOKEN, INDEXER_SERVER, INDEXER_PORT
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("assets_contract")


def get_algod_client():
    """Get the Algorand client."""
    return algokit_utils.AlgorandClient(
        {
            "algod": {
                "token": ALGOD_TOKEN,
                "url": f"{ALGOD_SERVER}:{ALGOD_PORT}"
            },
            "indexer": {
                "token": INDEXER_TOKEN,
                "url": f"{INDEXER_SERVER}:{INDEXER_PORT}"
            }
        }
    )


def get_account_from_mnemonic(mnemonic_phrase: str):
    """Get an account from a mnemonic phrase."""
    try:
        private_key = mnemonic.to_private_key(mnemonic_phrase)
        return algokit_utils.Account(private_key=private_key)
    except Exception as e:
        logger.error(f"Error getting account from mnemonic: {e}")
        raise


def get_app_client(
    app_id: int,
    sender_mnemonic: str
) -> AssetsContractClient:
    """Get a client for an existing contract."""
    algorand = get_algod_client()
    account = get_account_from_mnemonic(sender_mnemonic)

    return algorand.client.get_typed_app_client(
        AssetsContractClient,
        app_id=app_id,
        default_sender=account.address,
        default_signer=account
    )


def get_app_factory(deployer_mnemonic: str) -> AssetsContractFactory:
    """Get a factory for creating new contracts."""
    algorand = get_algod_client()
    deployer = get_account_from_mnemonic(deployer_mnemonic)

    return algorand.client.get_typed_app_factory(
        AssetsContractFactory,
        default_sender=deployer.address,
        default_signer=deployer
    )


def encode_params(params_dict: Dict[str, Any]) -> bytes:
    """
    Encode parameters into the format expected by the contract.
    Format: "key1:value1|key2:value2|..."
    """
    params_str = "|".join([f"{k}:{v}" for k, v in params_dict.items()])
    return params_str.encode("utf-8")


def decode_params(params_bytes: bytes) -> Dict[str, str]:
    """
    Decode parameters from the format used by the contract.
    Format: "key1:value1|key2:value2|..."
    """
    params_str = params_bytes.decode("utf-8")
    if params_str == "NAN":
        return {}

    result = {}
    for item in params_str.split("|"):
        if ":" in item:
            key, value = item.split(":", 1)
            result[key] = value
    return result


def log_transaction_result(result, operation_name):
    """Log the result of a transaction."""
    tx_id = result.tx_id if hasattr(result, 'tx_id') else "Unknown"
    logger.info(f"{operation_name} - Transaction ID: {tx_id}")

    if hasattr(result, 'confirmed_round'):
        logger.info(f"Confirmed in round: {result.confirmed_round}")
