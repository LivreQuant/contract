import logging
import json
import time
import os
import argparse
from pathlib import Path
from dotenv import load_dotenv
import base64

from algosdk import account, mnemonic, encoding
from algosdk.v2client import algod

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
  level=logging.INFO,
  format="%(asctime)s %(levelname)s: %(message)s"
)
logger = logging.getLogger("admin_operations")

# Get environment variables
ALGOD_TOKEN = os.getenv("ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")


def get_algod_client():
  """Create and return an algod client."""
  algod_address = f"{ALGOD_SERVER}:{ALGOD_PORT}"
  return algod.AlgodClient(ALGOD_TOKEN, algod_address)


def get_account_from_mnemonic(mnemonic_phrase):
  """Get account information from a mnemonic phrase."""
  private_key = mnemonic.to_private_key(mnemonic_phrase)
  address = account.address_from_private_key(private_key)
  return private_key, address


def wait_for_confirmation(client, txid):
  """Wait for a transaction to be confirmed."""
  last_round = client.status().get('last-round')
  txinfo = client.pending_transaction_info(txid)
  while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
    logger.info("Waiting for confirmation...")
    last_round += 1
    client.status_after_block(last_round)
    txinfo = client.pending_transaction_info(txid)
  logger.info(f"Transaction {txid} confirmed in round {txinfo.get('confirmed-round')}")
  return txinfo


def update_contract_status(app_id, new_status):
  """
  Update the status of the contract.

  Args:
      app_id: Application ID
      new_status: New status value ('ACTIVE', 'INACTIVE-STOP', or 'INACTIVE-SOLD')
  """
  # Validate status
  valid_statuses = ['ACTIVE', 'INACTIVE-STOP', 'INACTIVE-SOLD']
  if new_status not in valid_statuses:
    raise ValueError(f"Status must be one of {valid_statuses}")

  # Initialize Algorand client
  algod_client = get_algod_client()

  # Get account information
  admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

  # Create application call transaction to update status
  params = algod_client.suggested_params()
  app_args = [
    "update_status".encode(),  # Method selector for update_status
    new_status.encode()
  ]

  update_txn = algod.transaction.ApplicationCallTxn(
    sender=admin_address,
    sp=params,
    index=app_id,
    on_complete=algod.transaction.OnComplete.NoOpOC,
    app_args=app_args
  )

  signed_update_txn = update_txn.sign(admin_private_key)
  update_txid = algod_client.send_transaction(signed_update_txn)
  logger.info(f"Update status transaction sent with ID: {update_txid}")

  # Wait for confirmation
  wait_for_confirmation(algod_client, update_txid)
  logger.info(f"Contract status updated to {new_status}")


def update_contract_address(app_id, new_address):
  """
  Update the address of the contract.

  Args:
      app_id: Application ID
      new_address: New Algorand address
  """
  # Initialize Algorand client
  algod_client = get_algod_client()

  # Get account information
  admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

  # Create application call transaction to update address
  params = algod_client.suggested_params()
  app_args = [
    "update_address".encode(),  # Method selector for update_address
    encoding.decode_address(new_address)
  ]

  update_txn = algod.transaction.ApplicationCallTxn(
    sender=admin_address,
    sp=params,
    index=app_id,
    on_complete=algod.transaction.OnComplete.NoOpOC,
    app_args=app_args
  )

  signed_update_txn = update_txn.sign(admin_private_key)
  update_txid = algod_client.send_transaction(signed_update_txn)
  logger.info(f"Update address transaction sent with ID: {update_txid}")

  # Wait for confirmation
  wait_for_confirmation(algod_client, update_txid)
  logger.info(f"Contract address updated to {new_address}")


def update_contract_params(app_id, new_params):
  """
  Update the parameters of the contract.

  Args:
      app_id: Application ID
      new_params: New parameters string in format "key1:value1|key2:value2|..."
  """
  # Initialize Algorand client
  algod_client = get_algod_client()

  # Get account information
  admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

  # Create application call transaction to update params
  params = algod_client.suggested_params()
  app_args = [
    "update_params".encode(),  # Method selector for update_params
    new_params.encode()
  ]

  update_txn = algod.transaction.ApplicationCallTxn(
    sender=admin_address,
    sp=params,
    index=app_id,
    on_complete=algod.transaction.OnComplete.NoOpOC,
    app_args=app_args
  )

  signed_update_txn = update_txn.sign(admin_private_key)
  update_txid = algod_client.send_transaction(signed_update_txn)
  logger.info(f"Update params transaction sent with ID: {update_txid}")

  # Wait for confirmation
  wait_for_confirmation(algod_client, update_txid)
  logger.info(f"Contract parameters updated to {new_params}")


def delete_contract(app_id):
  """
  Delete the contract.

  Args:
      app_id: Application ID
  """
  # Initialize Algorand client
  algod_client = get_algod_client()

  # Get account information
  admin_private_key, admin_address = get_account_from_mnemonic(ADMIN_MNEMONIC)

  # Create application call transaction to delete application
  params = algod_client.suggested_params()

  delete_txn = algod.transaction.ApplicationDeleteTxn(
    sender=admin_address,
    sp=params,
    index=app_id
  )

  signed_delete_txn = delete_txn.sign(admin_private_key)
  delete_txid = algod_client.send_transaction(signed_delete_txn)
  logger.info(f"Delete transaction sent with ID: {delete_txid}")

  # Wait for confirmation
  wait_for_confirmation(algod_client, delete_txid)
  logger.info(f"Contract deleted successfully")


def get_contract_state(app_id):
  """
  Get the current state of the contract.

  Args:
      app_id: Application ID

  Returns:
      dict: Contract state information
  """
  # Initialize Algorand client
  algod_client = get_algod_client()

  # Get application information
  app_info = algod_client.application_info(app_id)

  # Get global state
  global_state = app_info['params']['global-state'] if 'global-state' in app_info['params'] else []

  # Process global state
  processed_state = {}
  for state_var in global_state:
    key = base64.b64decode(state_var['key']).decode('utf-8')
    value = state_var['value']

    if value['type'] == 1:  # bytes
      try:
        processed_state[key] = base64.b64decode(value['bytes']).decode('utf-8')
      except UnicodeDecodeError:
        processed_state[key] = base64.b64decode(value['bytes']).hex()
    else:  # uint
      processed_state[key] = value['uint']

  return processed_state


def parse_arguments():
  """Parse command line arguments."""
  parser = argparse.ArgumentParser(description='Admin operations for the trader contract')

  subparsers = parser.add_subparsers(dest='command', help='Command to execute', required=True)

  # Status command
  status_parser = subparsers.add_parser('status', help='Update contract status')
  status_parser.add_argument('app_id', type=int, help='Application ID')
  status_parser.add_argument('new_status', choices=['ACTIVE', 'INACTIVE-STOP', 'INACTIVE-SOLD'], help='New status value')

  # Address command
  address_parser = subparsers.add_parser('address', help='Update contract address')
  address_parser.add_argument('app_id', type=int, help='Application ID')
  address_parser.add_argument('new_address', help='New Algorand address')

  # Params command
  params_parser = subparsers.add_parser('params', help='Update contract parameters')
  params_parser.add_argument('app_id', type=int, help='Application ID')
  params_parser.add_argument('new_params', help='New parameters string (key1:value1|key2:value2|...)')

  # Delete command
  delete_parser = subparsers.add_parser('delete', help='Delete the contract')
  delete_parser.add_argument('app_id', type=int, help='Application ID')

  # State command
  state_parser = subparsers.add_parser('state', help='Get contract state')
  state_parser.add_argument('app_id', type=int, help='Application ID')

  return parser.parse_args()


def main():
  """Main entry point for the script."""
  if not ADMIN_MNEMONIC:
    raise ValueError("ADMIN_MNEMONIC environment variable not set. Please check your .env file.")

  args = parse_arguments()

  try:
    if args.command == 'status':
      update_contract_status(args.app_id, args.new_status)
    elif args.command == 'address':
      update_contract_address(args.app_id, args.new_address)
    elif args.command == 'params':
      update_contract_params(args.app_id, args.new_params)
    elif args.command == 'delete':
      delete_contract(args.app_id)
    elif args.command == 'state':
      state = get_contract_state(args.app_id)
      print(json.dumps(state, indent=2))
  except Exception as e:
    logger.error(f"Error executing command: {e}", exc_info=True)
    raise


if __name__ == "__main__":
  main()
