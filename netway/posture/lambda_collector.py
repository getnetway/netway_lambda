import logging
from typing import Any

logger = logging.getLogger(__name__)
LAMBDA_CAP = 500

SECRET_KEY_PATTERNS = frozenset({
    "password", "secret", "api_key", "access_key", "token",
    "credential", "private_key", "auth", "passwd", "pwd",
})


def collect_lambda_posture(lambda_client) -> list[dict[str, Any]]:
    functions: list[dict] = []

    for page in lambda_client.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            try:
                config = lambda_client.get_function_configuration(
                    FunctionName=fn["FunctionArn"]
                )
            except Exception as exc:
                logger.warning("GetFunctionConfiguration failed %s: %s",
                               fn["FunctionName"], exc)
                continue

            env_keys: list[str] = list(
                config.get("Environment", {}).get("Variables", {}).keys()
            )
            suspect = [
                k for k in env_keys
                if any(p in k.lower() for p in SECRET_KEY_PATTERNS)
            ]
            vpc = config.get("VpcConfig", {})

            functions.append({
                "function_name": fn["FunctionName"],
                "function_arn":  fn["FunctionArn"],
                "env_var_keys":  env_keys,
                "suspect_keys":  suspect,
                "in_vpc":        bool(vpc.get("VpcId")),
                "vpc_id":        vpc.get("VpcId") or None,
            })

            if len(functions) >= LAMBDA_CAP:
                logger.warning("Lambda cap %d reached — truncating", LAMBDA_CAP)
                return functions

    return functions
