"""
FlowRecord — the shared wire format between Lambda and API server.

Lambda creates, enriches, aggregates, and serializes FlowRecord objects,
then ships them (gzip + HMAC) to the API server via POST /api/v1/ingest.
The server deserializes them via from_dict() and runs detectors.

This is the only code shared between netway_lambda and netway_api.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class FlowRecord:
    """Normalised flow record — identical schema for AWS and GCP."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_out: int
    bytes_in: int
    action: str

    src_resource_id: str | None = None
    src_resource_name: str | None = None
    src_resource_type: str | None = None
    src_az: str | None = None
    src_region: str | None = None
    src_vpc_id: str | None = None

    dst_resource_id: str | None = None
    dst_resource_name: str | None = None
    dst_resource_type: str | None = None
    dst_az: str | None = None
    dst_region: str | None = None
    dst_vpc_id: str | None = None
    dst_is_s3: bool = False
    dst_is_aws_api: bool = False
    dst_is_internet: bool = False
    dst_is_gcs: bool = False
    dst_cloud_provider: str | None = None

    traffic_type: str | None = None
    cost_per_gb: float = 0.0
    estimated_cost: float = 0.0

    src_is_gpu: bool = False
    dst_is_gpu: bool = False
    src_instance_type: str | None = None
    src_tags: dict = field(default_factory=dict)
    via_nat: bool = False
    nat_gateway_id: str | None = None
    via_nat_az: str | None = None  # AZ of the NAT GW the flow passed through (set before pkt_src propagation overwrites src_az)
    pkt_src_aws_service: str | None = None
    pkt_dst_aws_service: str | None = None
    pkt_src_addr: str | None = None
    pkt_dst_addr: str | None = None

    # Aggregation field — set by Lambda aggregate_flows(), used by server detectors
    flow_count: int = 1

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict. timestamp → ISO string."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FlowRecord":
        """Deserialize from dict produced by to_dict(). Unknown keys are dropped gracefully."""
        d = dict(d)
        ts = d.get("timestamp")
        if isinstance(ts, str):
            d["timestamp"] = datetime.fromisoformat(ts)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        d = {k: v for k, v in d.items() if k in known}
        return cls(**d)
