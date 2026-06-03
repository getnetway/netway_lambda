from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

# FlowRecord is the shared wire format — defined in netway_common.
# Re-exported here so all Lambda code (providers, flow, detectors) can keep
# their existing `from netway.providers.base import FlowRecord` imports unchanged.
from netway_common.models import FlowRecord  # noqa: F401

__all__ = ["FlowRecord", "CloudProvider"]


class CloudProvider(ABC):

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return 'aws' or 'gcp'."""

    @abstractmethod
    def list_regions(self) -> list[str]:
        """Return configured regions to analyse."""

    @abstractmethod
    def query_flow_logs(
        self,
        region: str,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: list[str] | None = None,
    ) -> list[FlowRecord]:
        """Query flow logs. Returns normalised FlowRecord list. Never raises."""

    @abstractmethod
    def build_ip_resource_map(self, region: str) -> dict[str, dict]:
        """Return mapping of private IP → resource info dict."""

    @abstractmethod
    def get_s3_ip_ranges(self, region: str) -> list[str]:
        """Return CIDR ranges for S3 in this region."""

    @abstractmethod
    def get_aws_api_ip_ranges(self, region: str) -> list[str]:
        """Return CIDR ranges for AWS APIs (not S3) in this region."""

    @abstractmethod
    def list_vpc_endpoints(self, region: str) -> list[dict]:
        """Return existing VPC endpoints."""

    @abstractmethod
    def list_nat_gateways(self, region: str) -> list[dict]:
        """Return NAT gateways with their subnet and AZ."""
