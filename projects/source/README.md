# Algorand Trading Smart Contract

This repository contains a smart contract for trader applications on the Algorand blockchain, along with utilities to deploy and interact with the contract.

## Table of Contents

- [Setup](#setup)
- [Wallet Management](#wallet-management)
- [Contract Deployment](#contract-deployment)
- [Admin Operations](#admin-operations)
- [User Operations](#user-operations)
- [Contract Explorer](#contract-explorer)
- [Complete Contract Lifecycle](#complete-contract-lifecycle)

## Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/algorand-trader-app.git
cd algorand-trader-app
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. Create or update your `.env` file with the necessary environment variables:

```
# Algorand node connection
ALGOD_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_SERVER=http://localhost
ALGOD_PORT=4001

INDEXER_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
INDEXER_SERVER=http://localhost
INDEXER_PORT=8980

# Admin wallet (deployer)
ADMIN_MNEMONIC=your_admin_mnemonic_here

# User wallet
USER_MNEMONIC=your_user_mnemonic_here
```

## Wallet Management

### Generate and Fund Wallets

Run the wallet generation script to create admin and user wallets:

```bash
python fund_user_wallet.py
```

This script:
- Creates admin and user wallets if they don't exist
- Funds the user wallet from the admin wallet
- Updates the `.env` file with the wallet mnemonics
- Saves wallet information to JSON files in a `wallets` directory

## Contract Deployment

### Build the Contract

Build the smart contract to generate TEAL files:

```bash
python projects/trader/smart_contracts/__main__.py build
```

### Deploy the Contract

Deploy the contract to the Algorand network:

```bash
python deploy_trader.py
```

This will:
1. Deploy the contract using the admin wallet
2. Fund the contract with 1 Algo
3. Initialize the contract with sample parameters
4. Opt the user in to the contract
5. Save contract information to a JSON file

## Admin Operations

The admin can perform various operations on the contract using the `admin_operations.py` script:

### View Contract State

```bash
python admin_operations.py state 12345  # Replace 12345 with your app ID
```

### Update Contract Status

```bash
python admin_operations.py status 12345 ACTIVE  # Options: ACTIVE, INACTIVE-STOP, INACTIVE-SOLD
```

### Update Contract Address

```bash
python admin_operations.py address 12345 NEW_ALGORAND_ADDRESS
```

### Update Contract Parameters

```bash
python admin_operations.py params 12345 "region:EMEA|asset_class:FX|instrument_class:SPOT"
```

### Delete Contract (make sure it's inactive first)

```bash
python admin_operations.py delete 12345
```

## User Operations

Users can interact with the contract using the `user_operations.py` script:

### Opt In to a Contract

```bash
python user_operations.py opt-in 12345  # Replace 12345 with your app ID
```

### Update Local State

```bash
python user_operations.py update-local 12345 "book_hash_123" "research_hash_456" "local_param1:value1|local_param2:value2"
```

### View Local State

```bash
python user_operations.py local-state 12345
```

### Close Out from a Contract

```bash
python user_operations.py close-out 12345
```

## Contract Explorer

The contract explorer (`contract_explorer.py`) allows third-party users to explore contracts, view transaction history, and analyze parameters without needing to deploy or interact with the contracts directly.

### View Contract Information

Get detailed information about a contract:

```bash
python contract_explorer.py info 12345  # Replace 12345 with app ID
```

### View Transaction History

See the transaction history of a contract:

```bash
python contract_explorer.py history 12345  # Optionally add --limit 100
```

### List Contract Participants

See all accounts that have opted in to a contract:

```bash
python contract_explorer.py participants 12345
```

### View Participant Details

Get detailed information about a specific participant:

```bash
python contract_explorer.py participant-detail 12345 PARTICIPANT_ADDRESS
```

### Analyze Parameter Changes

Track changes to contract parameters over time:

```bash
python contract_explorer.py parameters 12345
```

### Visualize Contract Activity

Generate a chart showing contract activity over time:

```bash
python contract_explorer.py activity 12345  # Optionally add --output chart.png
```

### Search for Contracts

Find contracts created by a specific address:

```bash
python contract_explorer.py search CREATOR_ADDRESS  # Optionally add --limit 50
```

### Get Comprehensive Summary

Get a comprehensive summary of a contract, including information, history, participants, and parameter changes:

```bash
python contract_explorer.py summary 12345
```

## Contract Analysis

The contract explorer enables several types of analysis:

1. **Historical Analysis**: Track changes to the contract state and parameters over time
2. **User Behavior Analysis**: Examine patterns in user interactions with the contract
3. **Compliance Verification**: Verify that contract operations comply with expected behaviors
4. **Performance Metrics**: Analyze transaction frequency and user engagement

### Additional Explorer Dependencies

The explorer script requires additional dependencies:

```bash
pip install tabulate matplotlib pandas
```

## Complete Contract Lifecycle

The typical lifecycle of a contract is as follows:

1. **Deploy**: Create the contract and initialize it with parameters
   ```bash
   python deploy_trader.py
   ```

2. **Interact**: Admin and users interact with the contract
   ```bash
   # Admin updates parameters
   python admin_operations.py params 12345 "region:EMEA|asset_class:FX|instrument_class:SPOT"

   # User updates local state
   python user_operations.py update-local 12345 "book_hash_123" "research_hash_456" "local_param1:value1|local_param2:value2"
   ```

3. **Analyze**: Third parties analyze contract behavior
   ```bash
   python contract_explorer.py summary 12345
   ```

4. **Deactivate**: Admin sets the contract to inactive when it's no longer needed
   ```bash
   python admin_operations.py status 12345 INACTIVE-STOP
   ```

5. **Close Out**: Users close out from the contract
   ```bash
   python user_operations.py close-out 12345
   ```

6. **Delete**: Admin deletes the contract
   ```bash
   python admin_operations.py delete 12345
   ```

## Project Structure

```
├── .env                            # Environment variables
├── requirements.txt                # Dependencies
├── fund_user_wallet.py             # Wallet management script
├── deploy_trader.py                # Contract deployment script
├── admin_operations.py             # Admin operations script
├── user_operations.py              # User operations script
├── contract_explorer.py            # Contract explorer script
├── wallets/                        # Wallet information
│   ├── admin_wallet.json
│   └── user_wallet.json
└── projects/
    └── trader/
        └── smart_contracts/
            ├── __main__.py         # Build and deployment utilities
            ├── trader_app/         # Contract implementation
            │   ├── contract.py     # Smart contract code
            │   └── deploy_config.py # Deployment configuration
            └── artifacts/          # Generated artifacts
                └── trader_app/     # Contract artifacts
                    ├── *.teal      # TEAL files
                    └── *.arc56.json # Contract specification
```

## Notes

- Make sure your local Algorand node is running before executing these scripts
- Fund both admin and user accounts with sufficient Algos before deployment and interaction
- Always set a contract to inactive before attempting to delete it
- Keep your mnemonic phrases secure and do not share them

## Requirements

- Python 3.10 or higher
- Algorand Python SDK (py-algorand-sdk)
- AlgoKit (for local development)
- Algorand node access (local or testnet/mainnet)
- Additional packages for the explorer: tabulate, matplotlib, pandas
