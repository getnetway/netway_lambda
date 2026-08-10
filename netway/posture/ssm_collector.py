import logging
from typing import Any

logger = logging.getLogger(__name__)
SSM_CAP = 1000

SECRET_NAME_PATTERNS = frozenset({
    "password", "secret", "key", "token", "credential", "api-key", "access-key",
})


def collect_ssm_posture(ssm_client) -> list[dict[str, Any]]:
    params: list[dict] = []

    for page in ssm_client.get_paginator("describe_parameters").paginate():
        for p in page["Parameters"]:
            name_lower = p["Name"].lower()
            suspect = (
                p["Type"] != "SecureString"
                and any(pat in name_lower for pat in SECRET_NAME_PATTERNS)
            )
            params.append({
                "name":    p["Name"],
                "type":    p["Type"],
                "suspect": suspect,
            })
            if len(params) >= SSM_CAP:
                logger.warning("SSM cap %d reached — truncating", SSM_CAP)
                return params

    return params
