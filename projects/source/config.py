# config.py
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "db"
WALLETS_DIR = DB_DIR / "wallets"
CONTRACTS_DIR = DB_DIR / "contracts"

# Ensure directories exist
DB_DIR.mkdir(exist_ok=True)
WALLETS_DIR.mkdir(exist_ok=True)
CONTRACTS_DIR.mkdir(exist_ok=True)

# Algorand node connection
ALGOD_TOKEN = os.getenv(
    "ALGOD_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ALGOD_SERVER = os.getenv("ALGOD_SERVER", "http://localhost")
ALGOD_PORT = os.getenv("ALGOD_PORT", "4001")

INDEXER_TOKEN = os.getenv(
    "INDEXER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
INDEXER_SERVER = os.getenv("INDEXER_SERVER", "http://localhost")
INDEXER_PORT = os.getenv("INDEXER_PORT", "8980")

# Admin wallet (deployer)
ADMIN_MNEMONIC = os.getenv("ADMIN_MNEMONIC")

# Security settings
SECRET_PASS_PHRASE = os.getenv("SECRET_PASS_PHRASE")
ENCRYPT_WALLETS = True if SECRET_PASS_PHRASE else False

# Smart contract settings
CONTRACT_APPROVAL_PATH = BASE_DIR / "artifacts" / "BookContract.approval.teal"
CONTRACT_CLEAR_PATH = BASE_DIR / "artifacts" / "BookContract.clear.teal"
DEFAULT_FUNDING_AMOUNT = 1_000_000  # 1 Algo in microAlgos

# Default parameters
DEFAULT_PARAMS_STR = "region:NA|asset_class:EQUITIES|instrument_class:STOCKS"
