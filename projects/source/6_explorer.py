import logging
import json
import time
import os
import argparse
import base64
import datetime
from pathlib import Path
from tabulate import tabulate
from dotenv import load_dotenv
import matplotlib.pyplot as plt
import pandas as pd

from algosdk import account, mnemonic, encoding
from algosdk.v2client import algod, indexer

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
  level=logging.INFO,
  format="%(asctime)s %(levelname)s: %(message)s"
)
logger = logging.getLogger("contract_explorer")

# Get environment variables
ALGOD_TOKEN = os.getenv("ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")

INDEXER_TOKEN = os.getenv("INDEXER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
INDEXER_SERVER = os.getenv("INDEXER_SERVER", "http://localhost")
INDEXER_PORT = os.getenv("INDEXER_PORT", "8980")


def get_algod_client():
  """Create and return an algod client."""
  algod_address = f"{ALGOD_SERVER}:{ALGOD_PORT}"
  return algod.AlgodClient(ALGOD_TOKEN, algod_address)


def get_indexer_client():
  """Create and return an indexer client."""
  indexer_address = f"{INDEXER_SERVER}:{INDEXER_PORT}"
  return indexer.IndexerClient(INDEXER_TOKEN, indexer_address)


def decode_state_value(value):
  """Decode a state value from the Algorand blockchain."""
  if value['type'] == 1:  # bytes
    try:
      return base64.b64decode(value['bytes']).decode('utf-8')
    except UnicodeDecodeError:
      # Try to decode as parameters format
      try:
        params_bytes = base64.b64decode(value['bytes'])
        params_str = params_bytes.decode('utf-8')
        if '|' in params_str and ':' in params_str:
          # This looks like a parameters string
          params_dict = {}
          for pair in params_str.split('|'):
            if ':' in pair:
              k, v = pair.split(':', 1)
              params_dict[k] = v
          return params_dict
        return params_str
      except:
        # Return as hex if not decodable as string or parameters
        return base64.b64decode(value['bytes']).hex()
  else:  # uint
    return value['uint']


def get_contract_info(app_id):
  """
  Get detailed information about a contract.

  Args:
      app_id: Application ID

  Returns:
      dict: Contract information
  """
  # Initialize Algorand client
  algod_client = get_algod_client()

  try:
    # Get application information
    app_info = algod_client.application_info(app_id)

    # Prepare contract information dictionary
    contract_info = {
      "app_id": app_id,
      "creator": app_info['params']['creator'],
      "app_address": encoding.encode_address(encoding.checksum(b'appID' + app_id.to_bytes(8, 'big'))),
      "approval_program": base64.b64decode(app_info['params']['approval-program']).hex(),
      "clear_program": base64.b64decode(app_info['params']['clear-state-program']).hex(),
      "global_state_schema": {
        "num_byte_slices": app_info['params']['global-state-schema']['num-byte-slice'],
        "num_uints": app_info['params']['global-state-schema']['num-uint'],
      },
      "local_state_schema": {
        "num_byte_slices": app_info['params']['local-state-schema']['num-byte-slice'],
        "num_uints": app_info['params']['local-state-schema']['num-uint'],
      },
      "created_at_round": app_info['created-at-round'],
      "deleted": app_info.get('deleted', False),
      "global_state": {}
    }

    # Process global state
    global_state = app_info['params'].get('global-state', [])
    for state_var in global_state:
      key = base64.b64decode(state_var['key']).decode('utf-8')
      contract_info['global_state'][key] = decode_state_value(state_var['value'])

    return contract_info

  except Exception as e:
    logger.error(f"Error getting contract info: {e}")
    return None


def get_transaction_history(app_id, limit=50):
  """
  Get transaction history for a contract.

  Args:
      app_id: Application ID
      limit: Maximum number of transactions to retrieve

  Returns:
      list: Transaction history
  """
  # Initialize indexer client
  indexer_client = get_indexer_client()

  try:
    # Search for transactions involving the application
    response = indexer_client.search_transactions(
      application_id=app_id,
      limit=limit
    )

    # Process transactions
    transactions = []
    for tx in response.get('transactions', []):
      tx_type = tx.get('tx-type')
      if tx_type == 'appl':  # Application transaction
        # Extract application arguments
        app_args = []
        for arg in tx.get('application-transaction', {}).get('application-args', []):
          try:
            decoded_arg = base64.b64decode(arg).decode('utf-8')
            app_args.append(decoded_arg)
          except:
            app_args.append(base64.b64decode(arg).hex())

        # Create transaction record
        transaction = {
          "id": tx['id'],
          "sender": tx['sender'],
          "timestamp": tx.get('round-time'),
          "date": datetime.datetime.fromtimestamp(tx.get('round-time')).strftime('%Y-%m-%d %H:%M:%S') if tx.get('round-time') else None,
          "type": tx_type,
          "application_id": tx.get('application-transaction', {}).get('application-id'),
          "on_completion": tx.get('application-transaction', {}).get('on-completion'),
          "app_args": app_args,
          "global_state_delta": tx.get('global-state-delta'),
          "local_state_delta": tx.get('local-state-delta'),
          "confirmed_round": tx.get('confirmed-round')
        }

        transactions.append(transaction)

    # Sort transactions by timestamp
    transactions.sort(key=lambda x: x.get('timestamp', 0) or 0)

    return transactions

  except Exception as e:
    logger.error(f"Error getting transaction history: {e}")
    return []


def get_participants(app_id, limit=50):
  """
  Get participants (accounts that have opted in) for a contract.

  Args:
      app_id: Application ID
      limit: Maximum number of accounts to retrieve

  Returns:
      list: Participants
  """
  # Initialize indexer client
  indexer_client = get_indexer_client()

  try:
    # Search for accounts that have opted in to the application
    response = indexer_client.search_accounts(
      application_id=app_id,
      limit=limit
    )

    # Process accounts
    participants = []
    for account in response.get('accounts', []):
      # Find this application's local state
      local_state = None
      for app_local_state in account.get('apps-local-state', []):
        if app_local_state.get('id') == app_id:
          local_state = {}
          for kv in app_local_state.get('key-value', []):
            key = base64.b64decode(kv['key']).decode('utf-8')
            local_state[key] = decode_state_value(kv['value'])
          break

      # Create participant record
      participant = {
        "address": account['address'],
        "opted_in_at_round": None,  # Would need to search transactions to find this
        "opted_out": local_state is None,
        "local_state": local_state or {}
      }

      participants.append(participant)

    return participants

  except Exception as e:
    logger.error(f"Error getting participants: {e}")
    return []


def analyze_parameter_changes(transactions):
  """
  Analyze changes to contract parameters over time.

  Args:
      transactions: Transaction history

  Returns:
      list: Parameter change history
  """
  param_changes = []

  for tx in transactions:
    # Check if this is a update_params transaction
    if tx.get('app_args') and len(tx.get('app_args', [])) > 0 and tx.get('app_args')[0] == 'update_params':
      if len(tx.get('app_args', [])) > 1:
        # Create parameter change record
        change = {
          "timestamp": tx.get('timestamp'),
          "date": tx.get('date'),
          "sender": tx.get('sender'),
          "new_params_raw": tx.get('app_args')[1],
          "transaction_id": tx.get('id')
        }

        # Try to parse parameters
        try:
          if '|' in tx.get('app_args')[1] and ':' in tx.get('app_args')[1]:
            params_dict = {}
            for pair in tx.get('app_args')[1].split('|'):
              if ':' in pair:
                k, v = pair.split(':', 1)
                params_dict[k] = v
            change["new_params"] = params_dict
        except:
          change["new_params"] = None

        param_changes.append(change)

  return param_changes


def generate_activity_chart(transactions, output_file=None):
  """
  Generate a chart showing contract activity over time.

  Args:
      transactions: Transaction history
      output_file: Optional file to save the chart to
  """
  # Extract timestamps
  timestamps = [tx.get('timestamp') for tx in transactions if tx.get('timestamp')]

  if not timestamps:
    logger.warning("No timestamp data available for chart generation")
    return

  # Convert timestamps to dates
  dates = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]

  # Group by day
  date_counts = {}
  for date in dates:
    date_str = date.strftime('%Y-%m-%d')
    date_counts[date_str] = date_counts.get(date_str, 0) + 1

  # Create dataframe for plotting
  df = pd.DataFrame(list(date_counts.items()), columns=['Date', 'Transactions'])
  df['Date'] = pd.to_datetime(df['Date'])
  df = df.sort_values('Date')

  # Create plot
  plt.figure(figsize=(12, 6))
  plt.bar(df['Date'], df['Transactions'], width=0.8)
  plt.title(f"Contract Activity Over Time (App ID: {transactions[0].get('application_id')})")
  plt.xlabel("Date")
  plt.ylabel("Number of Transactions")
  plt.grid(axis='y', linestyle='--', alpha=0.7)
  plt.tight_layout()

  if output_file:
    plt.savefig(output_file)
    logger.info(f"Chart saved to {output_file}")
  else:
    plt.show()


def search_contracts_by_address(address, limit=20):
  """
  Search for contracts created by a specific address.

  Args:
      address: Creator address
      limit: Maximum number of contracts to retrieve

  Returns:
      list: Contracts
  """
  # Initialize indexer client
  indexer_client = get_indexer_client()

  try:
    # Search for applications created by the address
    response = indexer_client.search_applications(
      creator=address,
      limit=limit
    )

    # Process applications
    contracts = []
    for app in response.get('applications', []):
      contract = {
        "app_id": app['id'],
        "created_at_round": app.get('created-at-round'),
        "deleted": app.get('deleted', False)
      }

      # Add global state if available
      global_state = {}
      for kv in app.get('params', {}).get('global-state', []):
        key = base64.b64decode(kv['key']).decode('utf-8')
        global_state[key] = decode_state_value(kv['value'])

      contract["global_state"] = global_state

      contracts.append(contract)

    return contracts

  except Exception as e:
    logger.error(f"Error searching contracts: {e}")
    return []


def print_contract_summary(contract_info):
  """Print a summary of contract information."""
  if not contract_info:
    print("Contract not found or error retrieving information.")
    return

  print("\n=== CONTRACT SUMMARY ===")
  print(f"App ID: {contract_info['app_id']}")
  print(f"Creator: {contract_info['creator']}")
  print(f"App Address: {contract_info['app_address']}")
  print(f"Created at Round: {contract_info['created_at_round']}")
  print(f"Status: {'Deleted' if contract_info['deleted'] else 'Active'}")

  print("\nGlobal State Schema:")
  print(f"  Byte Slices: {contract_info['global_state_schema']['num_byte_slices']}")
  print(f"  Integers: {contract_info['global_state_schema']['num_uints']}")

  print("Local State Schema:")
  print(f"  Byte Slices: {contract_info['local_state_schema']['num_byte_slices']}")
  print(f"  Integers: {contract_info['local_state_schema']['num_uints']}")

  print("\nGlobal State:")
  for key, value in contract_info['global_state'].items():
    if isinstance(value, dict):
      print(f"  {key}:")
      for k, v in value.items():
        print(f"    {k}: {v}")
    else:
      print(f"  {key}: {value}")


def print_transaction_history(transactions):
  """Print transaction history in a tabular format."""
  if not transactions:
    print("No transactions found for this contract.")
    return

  table_data = []
  for tx in transactions:
    # Extract method name if available
    method = "Unknown"
    if tx.get('app_args') and len(tx.get('app_args')) > 0:
      method = tx.get('app_args')[0]

    # Add row to table
    table_data.append([
      tx.get('date') or "Unknown",
      tx.get('sender')[:12] + "..." if tx.get('sender') else "Unknown",
      tx.get('on_completion') or "NoOp",
      method,
      tx.get('id')[:12] + "..." if tx.get('id') else "Unknown"
    ])

  print("\n=== TRANSACTION HISTORY ===")
  print(tabulate(
    table_data,
    headers=["Date", "Sender", "Operation", "Method", "Transaction ID"],
    tablefmt="grid"
  ))


def print_participants(participants):
  """Print contract participants in a tabular format."""
  if not participants:
    print("No participants found for this contract.")
    return

  table_data = []
  for p in participants:
    # Count number of local state variables
    state_count = len(p['local_state'])

    # Add row to table
    table_data.append([
      p['address'][:12] + "..." if p['address'] else "Unknown",
      "No" if p['opted_out'] else "Yes",
      state_count
    ])

  print("\n=== CONTRACT PARTICIPANTS ===")
  print(tabulate(
    table_data,
    headers=["Address", "Opted In", "# Local State Variables"],
    tablefmt="grid"
  ))

  # Ask if user wants to see details for any participant
  print("\nTo view details for a specific participant, use the participant-detail command.")


def print_parameter_changes(param_changes):
  """Print parameter change history."""
  if not param_changes:
    print("No parameter changes found for this contract.")
    return

  table_data = []
  for change in param_changes:
    # Format parameters
    params_str = "Error parsing parameters"
    if change.get('new_params'):
      params_str = ", ".join([f"{k}={v}" for k, v in change['new_params'].items()])

    # Add row to table
    table_data.append([
      change.get('date') or "Unknown",
      change.get('sender')[:12] + "..." if change.get('sender') else "Unknown",
      params_str
    ])

  print("\n=== PARAMETER CHANGE HISTORY ===")
  print(tabulate(
    table_data,
    headers=["Date", "Sender", "New Parameters"],
    tablefmt="grid"
  ))


def print_participant_detail(app_id, address):
  """Print detailed information for a specific participant."""
  # Initialize Algorand client
  algod_client = get_algod_client()

  try:
    # Get account information
    account_info = algod_client.account_info(address)

    # Find this application's local state
    local_state = None
    for app_local_state in account_info.get('apps-local-state', []):
      if app_local_state.get('id') == app_id:
        local_state = {}
        for kv in app_local_state.get('key-value', []):
          key = base64.b64decode(kv['key']).decode('utf-8')
          local_state[key] = decode_state_value(kv['value'])
        break

    print(f"\n=== PARTICIPANT DETAILS: {address} ===")
    print(f"Opted In: {'No' if local_state is None else 'Yes'}")

    if local_state:
      print("\nLocal State:")
      for key, value in local_state.items():
        if isinstance(value, dict):
          print(f"  {key}:")
          for k, v in value.items():
            print(f"    {k}: {v}")
        else:
          print(f"  {key}: {value}")

    # Get transaction history for this participant with this contract
    indexer_client = get_indexer_client()
    response = indexer_client.search_transactions(
      application_id=app_id,
      address=address,
      limit=20
    )

    table_data = []
    for tx in response.get('transactions', []):
      if tx.get('tx-type') == 'appl':
        # Extract method name if available
        method = "Unknown"
        app_args = tx.get('application-transaction', {}).get('application-args', [])
        if app_args and len(app_args) > 0:
          try:
            method = base64.b64decode(app_args[0]).decode('utf-8')
          except:
            pass

        # Add row to table
        timestamp = tx.get('round-time')
        date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else "Unknown"

        table_data.append([
          date,
          tx.get('application-transaction', {}).get('on-completion') or "NoOp",
          method,
          tx.get('id')[:12] + "..." if tx.get('id') else "Unknown"
        ])

    if table_data:
      print("\nTransaction History:")
      print(tabulate(
        table_data,
        headers=["Date", "Operation", "Method", "Transaction ID"],
        tablefmt="grid"
      ))
    else:
      print("\nNo transactions found for this participant with this contract.")

  except Exception as e:
    logger.error(f"Error getting participant details: {e}")
    print(f"Error getting participant details: {e}")


def parse_arguments():
  """Parse command line arguments."""
  parser = argparse.ArgumentParser(description='Algorand Contract Explorer')

  subparsers = parser.add_subparsers(dest='command', help='Command to execute', required=True)

  # Info command
  info_parser = subparsers.add_parser('info', help='Get detailed information about a contract')
  info_parser.add_argument('app_id', type=int, help='Application ID')

  # History command
  history_parser = subparsers.add_parser('history', help='Get transaction history for a contract')
  history_parser.add_argument('app_id', type=int, help='Application ID')
  history_parser.add_argument('--limit', type=int, default=50, help='Maximum number of transactions to retrieve')

  # Participants command
  participants_parser = subparsers.add_parser('participants', help='Get participants for a contract')
  participants_parser.add_argument('app_id', type=int, help='Application ID')
  participants_parser.add_argument('--limit', type=int, default=50, help='Maximum number of participants to retrieve')

  # Participant detail command
  participant_detail_parser = subparsers.add_parser('participant-detail', help='Get detailed information for a specific participant')
  participant_detail_parser.add_argument('app_id', type=int, help='Application ID')
  participant_detail_parser.add_argument('address', help='Participant address')

  # Parameters command
  parameters_parser = subparsers.add_parser('parameters', help='Analyze parameter changes for a contract')
  parameters_parser.add_argument('app_id', type=int, help='Application ID')

  # Activity command
  activity_parser = subparsers.add_parser('activity', help='Generate activity chart for a contract')
  activity_parser.add_argument('app_id', type=int, help='Application ID')
  activity_parser.add_argument('--output', help='Output file to save the chart')

  # Search command
  search_parser = subparsers.add_parser('search', help='Search for contracts by creator address')
  search_parser.add_argument('address', help='Creator address')
  search_parser.add_argument('--limit', type=int, default=20, help='Maximum number of contracts to retrieve')

  # Summary command - combines several views into one
  summary_parser = subparsers.add_parser('summary', help='Get a comprehensive summary of a contract')
  summary_parser.add_argument('app_id', type=int, help='Application ID')

  return parser.parse_args()


def main():
  """Main entry point for the script."""
  args = parse_arguments()

  try:
    if args.command == 'info':
      contract_info = get_contract_info(args.app_id)
      print_contract_summary(contract_info)

    elif args.command == 'history':
      transactions = get_transaction_history(args.app_id, args.limit)
      print_transaction_history(transactions)

    elif args.command == 'participants':
      participants = get_participants(args.app_id, args.limit)
      print_participants(participants)

    elif args.command == 'participant-detail':
      print_participant_detail(args.app_id, args.address)

    elif args.command == 'parameters':
      transactions = get_transaction_history(args.app_id)
      param_changes = analyze_parameter_changes(transactions)
      print_parameter_changes(param_changes)

    elif args.command == 'activity':
      transactions = get_transaction_history(args.app_id)
      generate_activity_chart(transactions, args.output)

    elif args.command == 'search':
      contracts = search_contracts_by_address(args.address, args.limit)
      if contracts:
        table_data = []
        for c in contracts:
          status = "Deleted" if c.get('deleted') else "Active"
          name = "Unknown"
          # Try to extract name or ID from global state
          if 'g_user_id' in c.get('global_state', {}):
            name = c['global_state']['g_user_id']
          elif 'g_book_id' in c.get('global_state', {}):
            name = c['global_state']['g_book_id']

          table_data.append([
            c['app_id'],
            status,
            name
          ])

        print("\n=== CONTRACTS CREATED BY ADDRESS ===")
        print(f"Creator: {args.address}")
        print(tabulate(
          table_data,
          headers=["App ID", "Status", "Identifier"],
          tablefmt="grid"
        ))
      else:
        print(f"No contracts found for creator {args.address}")

    elif args.command == 'summary':
      # Get contract info
      contract_info = get_contract_info(args.app_id)
      print_contract_summary(contract_info)

      # Get transaction history
      transactions = get_transaction_history(args.app_id, 20)  # Limit to 20 for summary
      print_transaction_history(transactions)

      # Get participants
      participants = get_participants(args.app_id, 10)  # Limit to 10 for summary
      print_participants(participants)

      # Get parameter changes
      param_changes = analyze_parameter_changes(transactions)
      print_parameter_changes(param_changes)

      # Generate activity chart
      if len(transactions) > 0:
        print("\nTo generate an activity chart, use the activity command.")

  except Exception as e:
    logger.error(f"Error executing command: {e}", exc_info=True)
    print(f"Error: {e}")


if __name__ == "__main__":
  main()
