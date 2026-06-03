from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

REQUIRED_AWS = ["FLOW_LOGS_S3_BUCKET", "ATHENA_RESULTS_BUCKET"]
REQUIRED_GCP = ["GCP_PROJECT_ID", "FLOW_LOG_BIGQUERY_TABLE"]


def validate_config() -> None:
    provider = os.environ.get("CLOUD_PROVIDER", "aws").lower()
    missing = []

    if provider == "aws":
        source = os.environ.get("FLOW_LOG_SOURCE", "s3_athena")
        if source == "s3_athena":
            for key in REQUIRED_AWS:
                if not os.environ.get(key):
                    missing.append(key)
    elif provider == "gcp":
        source = os.environ.get("FLOW_LOG_SOURCE", "bigquery")
        if source == "bigquery":
            for key in REQUIRED_GCP:
                if not os.environ.get(key):
                    missing.append(key)
    else:
        raise ValueError(f"Unknown CLOUD_PROVIDER={provider!r}")

    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}"
        )
