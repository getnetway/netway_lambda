import os

from .aws import AWSProvider
from .base import CloudProvider, FlowRecord
from .gcp import GCPProvider


def get_provider() -> CloudProvider:
    provider = os.environ.get("CLOUD_PROVIDER", "aws").lower()
    if provider == "aws":
        return AWSProvider()
    if provider == "gcp":
        return GCPProvider()
    raise ValueError(
        f"Unknown CLOUD_PROVIDER={provider!r}. Supported: aws, gcp"
    )


__all__ = ["CloudProvider", "FlowRecord", "AWSProvider", "GCPProvider", "get_provider"]
