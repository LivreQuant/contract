import dataclasses
import importlib
import json
import logging
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from shutil import rmtree

from algokit_utils.config import config
from dotenv import load_dotenv

# Set trace_all to True to capture all transactions, defaults to capturing traces only on failure
# Learn more about using AlgoKit AVM Debugger to debug your TEAL source codes and inspect various kinds of
# Algorand transactions in atomic groups -> https://github.com/algorandfoundation/algokit-avm-vscode-debugger
config.configure(debug=True, trace_all=False)

# Set up logging and load environment variables.
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s %(levelname)-10s: %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Loading .env")
load_dotenv()

# Determine the root path based on this file's location.
root_path = Path(__file__).parent

# ----------------------- Contract Configuration ----------------------- #


@dataclasses.dataclass
class SmartContract:
    path: Path
    name: str
    deploy: Callable[[], None] | None = None


def import_contract(folder: Path) -> Path:
    """Imports the contract from a folder if it exists."""
    contract_path = folder / "contract.py"
    if contract_path.exists():
        return contract_path
    else:
        raise Exception(f"Contract not found in {folder}")


def import_deploy_if_exists(folder: Path) -> Callable[[], None] | None:
    """Imports the deploy function from a folder if it exists."""
    try:
        module_name = f"{folder.parent.name}.{folder.name}.deploy_config"
        deploy_module = importlib.import_module(module_name)
        return deploy_module.deploy  # type: ignore[no-any-return, misc]
    except ImportError:
        return None


def has_contract_file(directory: Path) -> bool:
    """Checks whether the directory contains a contract.py file."""
    return (directory / "contract.py").exists()


# Use the current directory (root_path) as the base for contract folders and exclude
# folders that start with '_' (internal helpers).
contracts: list[SmartContract] = [
    SmartContract(
        path=import_contract(folder),
        name=folder.name,
        deploy=import_deploy_if_exists(folder),
    )
    for folder in root_path.iterdir()
    if folder.is_dir() and has_contract_file(folder) and not folder.name.startswith("_")
]

# -------------------------- Build Logic -------------------------- #

deployment_extension = "py"


def _get_output_path(output_dir: Path, deployment_extension: str) -> Path:
    """Constructs the output path for the generated client file."""
    return output_dir / Path(
        "{contract_name}"
        + ("_client" if deployment_extension == "py" else "Client")
        + f".{deployment_extension}"
    )


def ensure_schema_compatibility(arc56_path):
    """
    Ensures the ARC56 JSON file has all the structure expected by the client generator.
    """
    with open(arc56_path, "r") as f:
        arc56_data = json.load(f)

    modified = False

    # Fix schema field
    if (
        "schema" not in arc56_data
        and "state" in arc56_data
        and "schema" in arc56_data["state"]
    ):
        arc56_data["schema"] = {
            "global": {
                "num_byte_slices": arc56_data["state"]["schema"]["global"]["bytes"],
                "num_uints": arc56_data["state"]["schema"]["global"]["ints"],
            },
            "local": {
                "num_byte_slices": arc56_data["state"]["schema"]["local"]["bytes"],
                "num_uints": arc56_data["state"]["schema"]["local"]["ints"],
            },
        }
        modified = True
        logger.info(f"Fixed schema format in {arc56_path}")

    # Fix state structure
    if (
        "state" in arc56_data
        and "global" not in arc56_data["state"]
        and "schema" in arc56_data["state"]
    ):
        # Add empty state.global and state.local mappings
        arc56_data["state"]["global"] = {}
        arc56_data["state"]["local"] = {}
        modified = True
        logger.info(f"Added state.global and state.local mappings in {arc56_path}")

    # Add contract field if missing
    if "contract" not in arc56_data:
        contract_name = arc56_path.stem.split(".")[
            0
        ]  # Get contract name from file name
        arc56_data["contract"] = {
            "name": contract_name,
            "methods": [],
            "desc": f"Contract {contract_name}",
            "networks": {},
        }

        # If there are methods in the ARC56 JSON, copy them to the contract field
        if "methods" in arc56_data:
            arc56_data["contract"]["methods"] = arc56_data["methods"]

        modified = True
        logger.info(f"Added contract field in {arc56_path}")

    # Ensure we have methods
    methods = arc56_data.get("methods", [])
    if (
        "methods" not in arc56_data
        and "contract" in arc56_data
        and "methods" in arc56_data["contract"]
    ):
        methods = arc56_data["contract"]["methods"]

    # Add hints field with entries for each method
    arc56_data["hints"] = {}
    for method in methods:
        # Generate method signature
        method_name = method.get("name", "")
        args_types = ",".join([arg.get("type", "") for arg in method.get("args", [])])
        return_type = method.get("returns", {}).get("type", "void")
        signature = f"{method_name}({args_types}){return_type}"

        # Add empty hints for this method
        arc56_data["hints"][signature] = {}

    modified = True
    logger.info(f"Added method hints in {arc56_path}")

    # Log current structure after modifications for debugging
    logger.debug(f"ARC56 JSON state structure: {arc56_data.get('state', {}).keys()}")

    # Save if modified
    if modified:
        with open(arc56_path, "w") as f:
            json.dump(arc56_data, f, indent=4)


def build(output_dir: Path, contract_path: Path) -> Path:
    """
    Builds the contract by exporting (compiling) its source and generating a client.
    If the output directory already exists, it is cleared.
    """
    output_dir = output_dir.resolve()
    if output_dir.exists():
        rmtree(output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)
    logger.info(f"Exporting {contract_path} to {output_dir}")

    build_result = subprocess.run(
        [
            "algokit",
            "--no-color",
            "compile",
            "python",
            str(contract_path.resolve()),
            f"--out-dir={output_dir}",
            "--no-output-arc32",
            "--output-arc56",
            "--output-source-map",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if build_result.returncode:
        raise Exception(f"Could not build contract:\n{build_result.stdout}")

    # Look for arc56.json files and generate the client based on them.
    app_spec_file_names: list[str] = [
        file.name for file in output_dir.glob("*.arc56.json")
    ]

    client_file: str | None = None
    if not app_spec_file_names:
        logger.warning(
            "No '*.arc56.json' file found (likely a logic signature being compiled). Skipping client generation."
        )
    else:
        for file_name in app_spec_file_names:
            client_file = file_name
            print(file_name)

            # Add this line to fix the schema before generating the client
            ensure_schema_compatibility(output_dir / file_name)

            generate_result = subprocess.run(
                [
                    "algokit",
                    "generate",
                    "client",
                    str(output_dir),
                    "--output",
                    str(_get_output_path(output_dir, deployment_extension)),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if generate_result.returncode:
                if "No such command" in generate_result.stdout:
                    raise Exception(
                        "Could not generate typed client, requires AlgoKit 2.0.0 or later. Please update AlgoKit"
                    )
                else:
                    raise Exception(
                        f"Could not generate typed client:\n{generate_result.stdout}"
                    )
    if client_file:
        return output_dir / client_file
    return output_dir


# --------------------------- Main Logic --------------------------- #


def main(action: str, contract_name: str | None = None) -> None:
    """Main entry point to build and/or deploy smart contracts."""
    artifact_path = root_path / "artifacts"
    # Filter contracts based on an optional specific contract name.
    filtered_contracts = [
        contract
        for contract in contracts
        if contract_name is None or contract.name == contract_name
    ]

    match action:
        case "build":
            for contract in filtered_contracts:
                logger.info(f"Building app at {contract.path}")
                build(artifact_path / contract.name, contract.path)
        case "deploy":
            for contract in filtered_contracts:
                output_dir = artifact_path / contract.name
                app_spec_file_name = next(
                    (
                        file.name
                        for file in output_dir.iterdir()
                        if file.is_file() and file.suffixes == [".arc56", ".json"]
                    ),
                    None,
                )
                if app_spec_file_name is None:
                    raise Exception("Could not deploy app, .arc56.json file not found")
                if contract.deploy:
                    logger.info(f"Deploying app {contract.name}")
                    contract.deploy()
        case "all":
            for contract in filtered_contracts:
                logger.info(f"Building app at {contract.path}")
                build(artifact_path / contract.name, contract.path)
                if contract.deploy:
                    logger.info(f"Deploying {contract.name}")
                    contract.deploy()
        case _:
            logger.error(f"Unknown action: {action}")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    elif len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        main("all")
