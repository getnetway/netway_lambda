from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta

from .base import CloudProvider, FlowRecord

logger = logging.getLogger(__name__)

GCP_GCS_CIDRS = ["34.128.0.0/10", "35.190.0.0/16", "34.64.0.0/10"]

GPU_MACHINE_PREFIXES = ("a2-highgpu-", "a3-highgpu-", "a3-megagpu-")


def _is_gpu_machine(machine_type: str | None) -> bool:
    if not machine_type:
        return False
    return any(machine_type.startswith(p) for p in GPU_MACHINE_PREFIXES)


class GCPProvider(CloudProvider):

    def __init__(self) -> None:
        self._project_id = os.environ.get("GCP_PROJECT_ID", "")
        self._regions = [
            r.strip()
            for r in os.environ.get("GCP_REGIONS", "us-central1").split(",")
            if r.strip()
        ]
        self._flow_log_source = os.environ.get("FLOW_LOG_SOURCE", "bigquery")
        self._bq_table = os.environ.get(
            "FLOW_LOG_BIGQUERY_TABLE",
            f"{self._project_id}.netway_logs.compute_googleapis_com_vpc_flows",
        )
        self._analysis_days = int(os.environ.get("ANALYSIS_DAYS", "30"))

    @property
    def provider_name(self) -> str:
        return "gcp"

    def list_regions(self) -> list[str]:
        return self._regions

    # ── Flow log queries ──────────────────────────────────────────────────

    def query_flow_logs(
        self,
        region: str,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: list[str] | None = None,
    ) -> list[FlowRecord]:
        try:
            if self._flow_log_source == "bigquery":
                return self._query_bigquery(region, start_time, end_time)
            else:
                return self._query_cloud_logging(region, start_time, end_time)
        except Exception as exc:
            logger.warning("Failed to query GCP flow logs in %s: %s", region, exc)
            return []

    def _query_bigquery(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[FlowRecord]:
        try:
            from google.cloud import bigquery  # type: ignore
        except ImportError:
            logger.warning("google-cloud-bigquery not installed")
            return []

        client = bigquery.Client(project=self._project_id)
        start_str = start_time.strftime("%Y-%m-%d")
        end_str = end_time.strftime("%Y-%m-%d")
        query = f"""
            SELECT
              jsonPayload.start_time as ts,
              jsonPayload.connection.src_ip as srcaddr,
              jsonPayload.connection.dest_ip as dstaddr,
              jsonPayload.connection.src_port as srcport,
              jsonPayload.connection.dest_port as dstport,
              jsonPayload.connection.protocol as protocol,
              CAST(jsonPayload.bytes_sent AS INT64) as bytes,
              jsonPayload.reporter as direction
            FROM `{self._bq_table}`
            WHERE _PARTITIONTIME >= TIMESTAMP('{start_str}')
              AND _PARTITIONTIME < TIMESTAMP('{end_str}')
              AND CAST(jsonPayload.bytes_sent AS INT64) > 0
            ORDER BY bytes DESC
            LIMIT 100000
        """
        try:
            result = client.query(query).result()
            return self._parse_bq_rows(result)
        except Exception as exc:
            logger.warning("BigQuery flow log query failed: %s", exc)
            return []

    def _parse_bq_rows(self, rows) -> list[FlowRecord]:
        records = []
        for row in rows:
            try:
                r = FlowRecord(
                    timestamp=row["ts"] if hasattr(row["ts"], "timestamp") else datetime.fromisoformat(str(row["ts"])),
                    src_ip=str(row.get("srcaddr") or ""),
                    dst_ip=str(row.get("dstaddr") or ""),
                    src_port=int(row.get("srcport") or 0),
                    dst_port=int(row.get("dstport") or 0),
                    protocol=str(row.get("protocol") or "TCP").upper(),
                    bytes_out=int(row.get("bytes") or 0),
                    bytes_in=0,
                    action="ACCEPT",
                )
                records.append(r)
            except Exception:
                continue
        return records

    def _query_cloud_logging(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[FlowRecord]:
        try:
            from google.cloud import logging as gcp_logging  # type: ignore
        except ImportError:
            logger.warning("google-cloud-logging not installed")
            return []

        client = gcp_logging.Client(project=self._project_id)
        start_str = start_time.isoformat()
        end_str = end_time.isoformat()
        filter_str = (
            f'logName="projects/{self._project_id}/logs/compute.googleapis.com%2Fvpc_flows"'
            f' AND timestamp>="{start_str}" AND timestamp<="{end_str}"'
        )
        records = []
        for entry in client.list_entries(filter_=filter_str, max_results=10000):
            try:
                payload = entry.payload
                conn = payload.get("connection", {})
                r = FlowRecord(
                    timestamp=entry.timestamp,
                    src_ip=conn.get("src_ip", ""),
                    dst_ip=conn.get("dest_ip", ""),
                    src_port=int(conn.get("src_port", 0) or 0),
                    dst_port=int(conn.get("dest_port", 0) or 0),
                    protocol=str(conn.get("protocol", "TCP")).upper(),
                    bytes_out=int(payload.get("bytes_sent", 0) or 0),
                    bytes_in=0,
                    action="ACCEPT",
                )
                records.append(r)
            except Exception:
                continue
        return records

    # ── IP to resource mapping ────────────────────────────────────────────

    def build_ip_resource_map(self, region: str) -> dict[str, dict]:
        ip_map: dict[str, dict] = {}
        try:
            from google.cloud import compute_v1  # type: ignore
        except ImportError:
            logger.warning("google-cloud-compute not installed")
            return ip_map

        try:
            client = compute_v1.InstancesClient()
            for zone_item in compute_v1.ZonesClient().list(project=self._project_id):
                if not zone_item.name.startswith(region):
                    continue
                zone = zone_item.name
                request = compute_v1.ListInstancesRequest(
                    project=self._project_id, zone=zone
                )
                for inst in client.list(request=request):
                    labels = dict(inst.labels) if inst.labels else {}
                    machine_type = inst.machine_type.split("/")[-1]
                    for iface in inst.network_interfaces:
                        priv_ip = iface.network_i_p
                        if priv_ip:
                            ip_map[priv_ip] = {
                                "resource_id": str(inst.id),
                                "resource_name": inst.name,
                                "resource_type": "instance",
                                "az": zone,
                                "region": region,
                                "vpc_id": iface.network,
                                "instance_type": machine_type,
                                "is_gpu": _is_gpu_machine(machine_type),
                                "tags": labels,
                            }
        except Exception as exc:
            logger.warning("Failed to build GCP IP map in %s: %s", region, exc)

        return ip_map

    def get_s3_ip_ranges(self, region: str) -> list[str]:
        # GCP uses GCS not S3
        return []

    def get_aws_api_ip_ranges(self, region: str) -> list[str]:
        return []

    def get_gcs_ip_ranges(self) -> list[str]:
        return GCP_GCS_CIDRS

    def list_vpc_endpoints(self, region: str) -> list[dict]:
        # GCP uses Private Service Connect — return empty for now
        return []

    def list_nat_gateways(self, region: str) -> list[dict]:
        result = []
        try:
            from google.cloud import compute_v1  # type: ignore
            client = compute_v1.RoutersClient()
            routers = client.list(project=self._project_id, region=region)
            for router in routers:
                for nat in router.nats:
                    result.append({
                        "nat_id": nat.name,
                        "router": router.name,
                        "region": region,
                        "vpc_id": router.network,
                    })
        except Exception as exc:
            logger.warning("Failed to list GCP NAT gateways in %s: %s", region, exc)
        return result
