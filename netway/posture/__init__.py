import logging
from datetime import datetime, timezone
from typing import Any

import boto3

from .sg_collector     import collect_security_groups
from .vpc_collector    import collect_vpc_posture
from .lambda_collector import collect_lambda_posture
from .ssm_collector    import collect_ssm_posture

logger = logging.getLogger(__name__)


def collect_posture(
    session: boto3.Session,
    regions: list[str],
    account_id: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version":   "1.0",
        "account_id":       account_id,
        "collected_at":     datetime.now(timezone.utc).isoformat(),
        "regions":          {},
        "lambda_functions": [],
        "ssm_parameters":   [],
    }

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            result["regions"][region] = {
                "security_groups": collect_security_groups(ec2),
                "vpc_posture":     collect_vpc_posture(ec2, region),
            }
        except Exception as exc:
            logger.error("Posture collection failed region=%s: %s", region, exc)
            result["regions"][region] = {"error": str(exc)}

        try:
            result["lambda_functions"] += collect_lambda_posture(
                session.client("lambda", region_name=region)
            )
        except Exception as exc:
            logger.error("Lambda posture failed region=%s: %s", region, exc)

        try:
            result["ssm_parameters"] += collect_ssm_posture(
                session.client("ssm", region_name=region)
            )
        except Exception as exc:
            logger.error("SSM posture failed region=%s: %s", region, exc)

    return result
