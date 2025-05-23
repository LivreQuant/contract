import logging
import time
import json
import os
from pathlib import Path
from dotenv import load_dotenv
import base64

load_dotenv()

from algosdk import account, mnemonic, encoding
from algosdk.v2client import algod
from algosdk import transaction
from algosdk import logic

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


def create_method_signature(method_signature):
    """
    Create a method signature for ARC-4 compatible smart contracts.
    This creates the first 4 bytes of the SHA-512/256 hash of the method signature.

    Args:
        method_signature (str): The method signature string (e.g., "initialize(bytes,bytes,bytes)uint64")

    Returns:
        bytes: The first 4 bytes of the hash
    """
    # SHA-512/256 is not directly available in hashlib
    # We can use SHA-512 and truncate to 256 bits or use a different approach

    # For Algorand, we can use algosdk's encoding module which has the correct hash function
    from algosdk import encoding

    # Get the method signature hash using algosdk
    return encoding.checksum(method_signature.encode())[:4]


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
    artifacts_dir = Path("../source/artifacts")

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
    global_schema = transaction.StateSchema(
        num_uints=0, num_byte_slices=5
    )  # Adjust based on your contract
    local_schema = transaction.StateSchema(
        num_uints=0, num_byte_slices=3
    )  # Adjust based on your contract

    # Define application parameters
    params = algod_client.suggested_params()

    # Create unsigned transaction
    txn = transaction.ApplicationCreateTxn(
        sender=admin_address,
        sp=params,
        on_complete=transaction.OnComplete.NoOpOC,
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
    app_address = logic.get_application_address(app_id)
    logger.info(f"Application address: {app_address}")

    # Fund the application with 1 Algo
    fund_amount = 1_000_000  # 1 Algo in microAlgos

    params = algod_client.suggested_params()
    fund_txn = transaction.PaymentTxn(
        sender=admin_address, sp=params, receiver=app_address, amt=fund_amount
    )

    signed_fund_txn = fund_txn.sign(admin_private_key)
    fund_txid = algod_client.send_transaction(signed_fund_txn)
    logger.info(f"Funding transaction sent with ID: {fund_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, fund_txid)
    logger.info(f"Funded contract with 1 Algo")

    # Define the real user values for initialize (COMES FROM PROFILE + PORTFOLIO FORMS)
    user_id = "user123"
    book_id = "book456"
    params_str = "region:NA|asset_class:EQUITIES|instrument_class:STOCKS"

    # Convert strings to bytes with ABI encoding
    # Add a 2-byte length prefix to each string
    user_id_bytes = len(user_id).to_bytes(2, byteorder="big") + user_id.encode()
    book_id_bytes = len(book_id).to_bytes(2, byteorder="big") + book_id.encode()
    params_bytes = len(params_str).to_bytes(2, byteorder="big") + params_str.encode()

    # Create application call transaction to initialize contract
    # Note: initialize only accepts 3 parameters, not the user address
    params = algod_client.suggested_params()
    init_app_args = [
        create_method_signature("initialize(byte[],byte[],byte[])uint64"),
        user_id_bytes,
        book_id_bytes,
        params_bytes,
    ]

    initialize_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=init_app_args,
    )

    signed_initialize_txn = initialize_txn.sign(admin_private_key)
    initialize_txid = algod_client.send_transaction(signed_initialize_txn)
    logger.info(f"Initialization transaction sent with ID: {initialize_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, initialize_txid)
    logger.info(f"Contract initialized with initial values")

    # Now update the contract with the actual user address using update_global
    params = algod_client.suggested_params()

    # For the update_global method
    update_app_args = [
        create_method_signature("update_global(byte[],byte[],account,byte[])uint64"),
        user_id_bytes,
        book_id_bytes,
        (1).to_bytes(8, "big"),  # Index 0 in accounts array (0 is the first account)
        params_bytes,
    ]

    update_txn = transaction.ApplicationCallTxn(
        sender=admin_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=update_app_args,
        accounts=[
            user_address
        ],  # Pass the user address as the first entry in the accounts array
    )

    signed_update_txn = update_txn.sign(admin_private_key)
    update_txid = algod_client.send_transaction(signed_update_txn)
    logger.info(f"Update global parameters transaction sent with ID: {update_txid}")

    # Wait for confirmation
    wait_for_confirmation(algod_client, update_txid)
    logger.info(f"Contract global parameters updated with real user address")

    # Add after the update_global confirmation
    # Fetch the application's global state
    app_info = algod_client.application_info(app_id)
    global_state = app_info["params"]["global-state"]

    # Decode and print each key-value pair in the global state
    logger.info("Global state after update_global:")
    for item in global_state:
        key_bytes = base64.b64decode(item["key"])
        try:
            key = key_bytes.decode("utf-8")
        except:
            key = key_bytes.hex()

        if item["value"]["type"] == 1:  # bytes value
            if key == "address":
                # If it's an address, convert it properly
                addr_bytes = base64.b64decode(item["value"]["bytes"])
                if len(addr_bytes) == 32:
                    try:
                        addr = encoding.encode_address(addr_bytes)
                        value = f"Address: {addr}"
                    except:
                        value = f"Bytes: {addr_bytes.hex()}"
                else:
                    value = f"Bytes: {addr_bytes.hex()}"
            else:
                # Otherwise just show the bytes
                value_bytes = base64.b64decode(item["value"]["bytes"])
                try:
                    value = f"String: {value_bytes.decode('utf-8')}"
                except:
                    value = f"Bytes: {value_bytes.hex()}"
        else:  # uint value
            value = f"UInt: {item['value']['uint']}"

        logger.info(f"Key: {key}, Value: {value}")

    # Specifically check if the address matches
    address_found = False
    for item in global_state:
        key_bytes = base64.b64decode(item["key"])
        try:
            key = key_bytes.decode("utf-8")
        except:
            key = key_bytes.hex()

        if key == "address" and item["value"]["type"] == 1:  # bytes value for address
            address_found = True
            addr_bytes = base64.b64decode(item["value"]["bytes"])
            if len(addr_bytes) == 32:
                try:
                    stored_address = encoding.encode_address(addr_bytes)
                    logger.info(f"Address stored in contract: {stored_address}")
                    logger.info(f"User address trying to opt in: {user_address}")
                    if stored_address == user_address:
                        logger.info("✅ Addresses MATCH")
                    else:
                        logger.error("❌ Addresses DON'T MATCH")
                except Exception as e:
                    logger.error(f"Error decoding address: {e}")
            else:
                logger.error(f"Address bytes wrong length, got {len(addr_bytes)} bytes")

    if not address_found:
        logger.error("No 'address' key found in global state")

    # User opt-in to the contract using the ABI method call
    params = algod_client.suggested_params()

    # Create the method selector for opt_in
    opt_in_selector = create_method_signature("opt_in()uint64")

    opt_in_txn = transaction.ApplicationCallTxn(
        sender=user_address,
        sp=params,
        index=app_id,
        on_complete=transaction.OnComplete.OptInOC,
        app_args=[opt_in_selector],  # Pass the ABI method selector
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
