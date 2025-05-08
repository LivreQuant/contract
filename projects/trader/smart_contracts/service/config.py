import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Algorand node connection
ALGOD_TOKEN = os.getenv("ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")

INDEXER_TOKEN = os.getenv("INDEXER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
INDEXER_SERVER = os.getenv("INDEXER_SERVER", "http://localhost")
INDEXER_PORT = os.getenv("INDEXER_PORT", "8980")

# Admin wallet (deployer)
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")

# User wallet
USER_MNEMONIC = os.getenv("USER_MNEMONIC")

# Contract configuration
DEFAULT_FUNDING_AMOUNT = 1_000_000  # 1 Algo in microAlgos
