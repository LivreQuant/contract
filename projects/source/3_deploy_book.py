import logging
import time
import json
import os
from pathlib import Path
from dotenv import load_dotenv
import base64

# Load environment variables
load_dotenv()

# Import algokit utils and other necessary modules
from algosdk import account, mnemonic, encoding
from algosdk.v2client import algod

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("deploy_trader")

# Get environment variables
ALGOD_TOKEN = os.getenv(
    "ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")
USER_MNEMONIC = os.getenv("USER_MNEMONIC")

# Check if we have the necessary environment variables
if not ADMIN_MNEMONIC:
    raise ValueError(
        "ADMIN_MNEMONIC environment variable not set. Please check your .env file."
    )
if not USER_MNEMONIC:
    raise ValueError(
        "USER_MNEMONIC environment variable not set. Please check your .env file."
    )


def get_algod_client():
    """Create and return an algod client."""
    algod_address = f"{ALGOD_SERVER}:{ALGOD_PORT}"
    return algod.AlgodClient(ALGOD_TOKEN, algod_address)


def get_account_from_mnemonic(mnemonic_phrase):
    """Get account information from a mnemonic phrase."""
    private_key = mnemonic.to_private_key(mnemonic_phrase)
    address = account.address_from_private_key(private_key)
    return private_key, address


def compile_program(client, source_code):
    """Compile TEAL source code to binary."""
    compile_response = client.compile(source_code)
    return base64.b64decode(compile_response["result"])


def wait_for_confirmation(client, txid):
    """Wait for a transaction to be confirmed."""
    last_round = client.status().get("last-round")
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get("confirmed-round") and txinfo.get("confirmed-round") > 0):
        logger.info("Waiting for confirmation...")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    logger.info(
        f"Transaction {txid} confirmed in round {txinfo.get('confirmed-round')}"
    )
    return txinfo


def deploy_trader_contract():
    """Deploy the trader contract to the Algorand network."""
    # Initialize Algorand client
    algod_client = get_algod_client()

    # Get account information
    admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)
    user_private_key, user_address = get_account_from_mnemonic(USER_MNEMONIC)

    logger.info(f"Admin address: {admin_address}")
    logger.info(f"User address: {user_address}")

    # Check account balances
    admin_info = algod_client.account_info(admin_address)
    user_info = algod_client.account_info(user_address)

    admin_balance = admin_info.get("amount") / 1_000_000  # Convert microAlgos to Algos
    user_balance = user_info.get("amount") / 1_000_000

    logger.info(f"Admin balance: {admin_balance} Algos")
    logger.info(f"User balance: {user_balance} Algos")

    # Load approval and clear programs
    artifacts_dir = Path("projects/trader/smart_contracts/artifacts/trader_app")

    # First, find the file with .teal extension for the approval program
    approval_files = list(artifacts_dir.glob("*.teal"))
    if not approval_files:
        raise FileNotFoundError("No TEAL files found in artifacts directory")

    # Look for approval_program.teal
    approval_program_path = None
    clear_program_path = None

    for file in approval_files:
        if "approval" in file.name.lower():
            approval_program_path = file
        elif "clear" in file.name.lower():
            clear_program_path = file

    if not approval_program_path or not clear_program_path:
        # Just use the first two files as a fallback
        if len(approval_files) >= 2:
            approval_program_path = approval_files[0]
            clear_program_path = approval_files[1]
        else:
            raise FileNotFoundError(
                "Could not identify approval and clear program files"
            )

    logger.info(f"Using approval program: {approval_program_path}")
    logger.info(f"Using clear program: {clear_program_path}")

    # Read and compile the programs
    with open(approval_program_path, "r") as f:
        approval_program_source = f.read()

    with open(clear_program_path, "r") as f:
        clear_program_source = f.read()

    approval_program = compile_program(algod_client, approval_program_source)
    clear_program = compile_program(algod_client, clear_program_source)

    # Define global schema and local schema
    global_schema = algod.StateSchema(
        num_uints=0, num_byte_slices=5
    )  # Adjust based on your contract
    local_schema = algod.StateSchema(
        num_uints=0, num_byte_slices=3
    )  # Adjust based on your contract

    # Define application parameters
    params = algod_client.suggested_params()

    # Create unsigned transaction
    txn = algod.transaction.ApplicationCreateTxn(
        sender=admin_address,
        sp=params,
        on_complete=algod.transaction.OnComplete.NoOpOC,
        approval_program=approval_program,
        clear_program=clear_program,
        global_schema=global_schema,
        local_schema=local_schema,
    )

    # Sign transaction
    signed_txn = txn.sign(admin_private_key)

    # Send transaction
    txid = algod_client.send_transaction(signed_txn)
    logger.info(f"Transaction sent with ID: {txid}")

    # Wait for confirmation
    tx_info = wait_for_confirmation(algod_client, txid)

    # Get the application ID
    app_id = tx_info.get("application-index")
    logger.info(f"Created application with ID: {app_id}")

    # Fund the contract account
    app_address = algod.logic.get_application_address(app_id)
    logger.info(f"Application address: {app_address}")

    # Fund the application with 1 Algo
    fund_amount = 1_000_000  # 1 Algo in microAlgos

    params = algod_client.suggested_params()
    fund_txn = algod.transaction.PaymentTxn(
        sender=admin_address, sp=params, receiver=app_address, amt=fund_amount
    )

    signed_fund_txn = fund_txn.sign(admin_private_key)
    fund_txid = algod_client.send_transaction(signed_fund_txn)
    logger.info(f"Funding transaction sent with ID: {fund_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, fund_txid)
    logger.info(f"Funded contract with 1 Algo")

    # Initialize the contract
    user_id = "user123"
    book_id = "book456"
    params_str = "region:NA|asset_class:EQUITIES|instrument_class:STOCKS"

    # Convert strings to bytes
    user_id_bytes = user_id.encode()
    book_id_bytes = book_id.encode()
    params_bytes = params_str.encode()

    # Create application call transaction to initialize contract
    params = algod_client.suggested_params()
    app_args = [
        "initialize".encode(),  # Method selector for initialize
        user_id_bytes,
        book_id_bytes,
        params_bytes,
    ]

    initialize_txn = algod.transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=algod.transaction.OnComplete.NoOpOC,
        app_args=app_args,
    )

    signed_initialize_txn = initialize_txn.sign(admin_private_key)
    initialize_txid = algod_client.send_transaction(signed_initialize_txn)
    logger.info(f"Initialization transaction sent with ID: {initialize_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, initialize_txid)
    logger.info(f"Contract initialized successfully")

    # User opt-in to the contract
    params = algod_client.suggested_params()
    opt_in_txn = algod.transaction.ApplicationOptInTxn(
        sender=user_address, sp=params, index=app_id
    )

    signed_opt_in_txn = opt_in_txn.sign(user_private_key)
    opt_in_txid = algod_client.send_transaction(signed_opt_in_txn)
    logger.info(f"Opt-in transaction sent with ID: {opt_in_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, opt_in_txid)
    logger.info(f"User opted in successfully")

    # Save contract information
    contract_info = {
        "app_id": app_id,
        "app_address": app_address,
        "user_address": user_address,
        "admin_address": admin_address,
        "user_id": user_id,
        "book_id": book_id,
        "parameters": params_str,
        "creation_timestamp": time.time(),
    }

    # Save to file
    contract_info_file = f"contract_{app_id}_info.json"
    with open(contract_info_file, "w") as f:
        json.dump(contract_info, f, indent=2)

    logger.info(f"Contract information saved to {contract_info_file}")

    return app_id, contract_info


if __name__ == "__main__":
    try:
        app_id, contract_info = deploy_trader_contract()
        print(f"\nTrader contract deployed with app ID: {app_id}")
        print(f"Contract address: {contract_info['app_address']}")
        print(f"User address: {contract_info['user_address']}")
        print(f"Contract information saved to contract_{app_id}_info.json")
    except Exception as e:
        logger.error(f"Error deploying contract: {e}", exc_info=True)
