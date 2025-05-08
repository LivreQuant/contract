import logging

import algokit_utils

logger = logging.getLogger(__name__)


# define deployment behaviour based on supplied app spec
def deploy() -> None:
    from smart_contracts.artifacts.assets_contract.assets_contract_client import (
        AssetsContractClient,
        AssetsContractFactory,
    )

    algorand = algokit_utils.AlgorandClient.from_environment()
    deployer = algorand.account.from_environment("DEPLOYER")

    factory = algorand.client.get_typed_app_factory(
        AssetsContractFactory, default_sender=deployer.address
    )

    app_client, result = factory.deploy(
        on_update=algokit_utils.OnUpdate.AppendApp,
        on_schema_break=algokit_utils.OnSchemaBreak.AppendApp,
    )

    if result.operation_performed in [
        algokit_utils.OperationPerformed.Create,
        algokit_utils.OperationPerformed.Replace,
    ]:
        algorand.send.payment(
            algokit_utils.PaymentParams(
                amount=algokit_utils.AlgoAmount(algo=1),
                sender=deployer.address,
                receiver=app_client.app_address,
            )
        )

        # Initialize the contract with sample values
        user_id = bytes("user123", "utf-8")
        asset_id = bytes("asset456", "utf-8")
        parameters = bytes("param1:value1|param2:value2", "utf-8")

        response = app_client.send.initialize(args=(user_id, asset_id, parameters))
        logger.info(
            f"Initialized {app_client.app_name} ({app_client.app_id}) with "
            f"user_id={user_id}, asset_id={asset_id}, parameters={parameters}"
        )
