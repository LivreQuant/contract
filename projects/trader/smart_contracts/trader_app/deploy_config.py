import logging

import algokit_utils

logger = logging.getLogger(__name__)


# define deployment behaviour based on supplied app spec
def deploy() -> None:
    from smart_contracts.artifacts.book_contract.book_contract_client import (
        BookContractClient,
        BookContractFactory,
    )

    algorand = algokit_utils.AlgorandClient.from_environment()
    deployer = algorand.account.from_environment("DEPLOYER")

    factory = algorand.client.get_typed_app_factory(
        BookContractFactory, default_sender=deployer.address
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
        g_user_id = bytes("", "utf-8")
        g_book_id = bytes("", "utf-8")
        g_params = bytes("", "utf-8")

        response = app_client.send.initialize(args=(g_user_id, g_book_id, g_params))
        logger.info(
            f"Initialized {app_client.app_name} ({app_client.app_id}) with "
            f"g_user_id={g_user_id}, g_book_id={g_book_id}, g_params={g_params}"
        )
