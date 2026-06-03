from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Any

from netway.providers.base import CloudProvider, FlowRecord

logger = logging.getLogger(__name__)

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── Cache ─────────────────────────────────────────────────────────────────

_cached_ip_map: dict[str, dict[str, dict]] = {}  # region → ip_map
_cache_built_at: dict[str, float] = {}
_CACHE_TTL = 6 * 3600  # 6 hours


def clear_ip_map_cache() -> None:
    """Invalidate the ip_map cache so the next call rebuilds from live AWS APIs.
    Call once per Lambda invocation to avoid warm-container staleness."""
    _cached_ip_map.clear()
    _cache_built_at.clear()


def build_ip_resource_map(
    provider: CloudProvider, region: str
) -> dict[str, dict]:
    now = time.time()
    if region in _cached_ip_map and (now - _cache_built_at.get(region, 0)) < _CACHE_TTL:
        return _cached_ip_map[region]

    ip_map = provider.build_ip_resource_map(region)
    _cached_ip_map[region] = ip_map
    _cache_built_at[region] = now
    logger.info("Built IP resource map for %s: %d entries", region, len(ip_map))
    return ip_map


def enrich_flows(
    records: list[FlowRecord],
    ip_map: dict[str, dict],
    s3_cidrs: list[str] | None = None,
    api_cidrs: list[str] | None = None,
    gcs_cidrs: list[str] | None = None,
    nat_ips: set[str] | None = None,
    global_s3_ranges: list[dict] | None = None,
) -> list[FlowRecord]:
    """Enrich FlowRecord objects with resource metadata and IP classification."""
    s3_cidrs = s3_cidrs or []
    api_cidrs = api_cidrs or []
    gcs_cidrs = gcs_cidrs or []
    nat_ips = nat_ips or set()
    global_s3_ranges = global_s3_ranges or []

    for rec in records:
        _enrich_src(rec, ip_map)
        _enrich_dst(rec, ip_map, s3_cidrs, api_cidrs, gcs_cidrs, global_s3_ranges)
        _detect_via_nat(rec, nat_ips)
        # Propagate original source info (GPU, SageMaker) onto NAT GW flow records
        # using pkt_srcaddr so ML classifiers can match src_is_gpu / src_resource_type.
        _propagate_pkt_src_info(rec, ip_map)
        # NAT return path: NAT→Instance where packet originated from S3.
        # The instance may not be in ip_map (e.g. terminated), but these bytes
        # still incur NAT processing cost and should be counted.
        if (
            rec.src_resource_type == "nat_gateway"
            and not rec.dst_is_s3
            and _is_private(rec.dst_ip)
            and (rec.pkt_src_aws_service or "").upper() == "S3"
        ):
            rec.dst_is_s3 = True

        # Instance→NAT forward path: Instance ENI records show dstaddr=NAT IP but
        # pkt_dst_aws_service=S3. Set dst_is_s3 so ml_checkpoint_nat classifier fires.
        if (
            rec.dst_resource_type == "nat_gateway"
            and not rec.dst_is_s3
            and (rec.pkt_dst_aws_service or "").upper() == "S3"
        ):
            rec.dst_is_s3 = True


    return records


def _lookup_s3_region(ip: str, global_s3_ranges: list[dict]) -> str | None:
    """Return the AWS region for an S3 IP using the global S3 CIDR table."""
    try:
        addr = ipaddress.ip_address(ip)
        for entry in global_s3_ranges:
            if addr in ipaddress.ip_network(entry["cidr"], strict=False):
                return entry["region"] or None
    except ValueError:
        pass
    return None


def _subnet_info_for_ip(ip: str, ip_map: dict[str, dict]) -> dict | None:
    """Look up which subnet a private IP belongs to using the __subnets__ index."""
    subnets = ip_map.get("__subnets__", [])  # type: ignore[arg-type]
    try:
        addr = ipaddress.ip_address(ip)
        for sn in subnets:
            if addr in ipaddress.ip_network(sn["cidr"], strict=False):
                return sn
    except ValueError:
        pass
    return None


def _enrich_src(rec: FlowRecord, ip_map: dict[str, dict]) -> None:
    info = ip_map.get(rec.src_ip)
    if info:
        rec.src_resource_id = info.get("resource_id")
        rec.src_resource_name = info.get("resource_name")
        rec.src_resource_type = info.get("resource_type")
        rec.src_az = info.get("az")
        rec.src_region = info.get("region")
        rec.src_vpc_id = info.get("vpc_id")
        rec.src_is_gpu = bool(info.get("is_gpu", False))
        rec.src_instance_type = info.get("instance_type")
        rec.src_tags = info.get("tags", {})
    elif _is_private(rec.src_ip):
        # IP not in map (e.g. terminated instance) but private — infer AZ/VPC from subnet CIDR
        sn = _subnet_info_for_ip(rec.src_ip, ip_map)
        if sn:
            rec.src_resource_type = "instance"
            rec.src_az = sn.get("az")
            rec.src_region = sn.get("region")
            rec.src_vpc_id = sn.get("vpc_id")
    else:
        rec.src_resource_type = "public"


def _propagate_pkt_src_info(rec: FlowRecord, ip_map: dict[str, dict]) -> None:
    """For NAT-routed flows, look up the original source (pkt_src_addr) and propagate
    its resource metadata (GPU type, SageMaker type, etc.) so ML classifiers can fire.

    Before overwriting src_az we snapshot the NAT GW's AZ into via_nat_az so the
    nat_wrong_az detector can compare the EC2's AZ (src_az after propagation) with
    the NAT GW's AZ (via_nat_az) to identify cross-AZ NAT routing.
    """
    if not (rec.via_nat and rec.pkt_src_addr):
        return
    orig = ip_map.get(rec.pkt_src_addr)
    if not orig:
        # pkt_srcaddr not in ip_map — fall back to subnet CIDR lookup so the
        # nat_wrong_az detector still gets an EC2 AZ from a terminated instance.
        sn = _subnet_info_for_ip(rec.pkt_src_addr, ip_map)
        if sn:
            if rec.src_resource_type == "nat_gateway" and rec.src_az:
                rec.via_nat_az = rec.src_az
            rec.src_resource_type = "instance"
            rec.src_az = sn.get("az", rec.src_az)
            rec.src_region = sn.get("region", rec.src_region)
            rec.src_vpc_id = sn.get("vpc_id", rec.src_vpc_id)
        return
    # Snapshot NAT GW AZ before propagation overwrites src_az
    if rec.src_resource_type == "nat_gateway" and rec.src_az:
        rec.via_nat_az = rec.src_az
    rec.src_is_gpu = bool(orig.get("is_gpu", False))
    rec.src_instance_type = orig.get("instance_type") or rec.src_instance_type
    rec.src_resource_type = orig.get("resource_type", rec.src_resource_type)
    rec.src_resource_id = orig.get("resource_id", rec.src_resource_id)
    rec.src_resource_name = orig.get("resource_name", rec.src_resource_name)
    rec.src_az = orig.get("az", rec.src_az)
    rec.src_vpc_id = orig.get("vpc_id", rec.src_vpc_id)
    rec.src_tags = orig.get("tags", rec.src_tags)


def _enrich_dst(
    rec: FlowRecord,
    ip_map: dict[str, dict],
    s3_cidrs: list[str],
    api_cidrs: list[str],
    gcs_cidrs: list[str],
    global_s3_ranges: list[dict] | None = None,
) -> None:
    info = ip_map.get(rec.dst_ip)
    if info:
        rec.dst_resource_id = info.get("resource_id")
        rec.dst_resource_name = info.get("resource_name")
        rec.dst_resource_type = info.get("resource_type")
        rec.dst_az = info.get("az")
        rec.dst_region = info.get("region")
        rec.dst_vpc_id = info.get("vpc_id")
        rec.dst_is_gpu = bool(info.get("is_gpu", False))
        return

    # IP range classification — regional S3 (same region, includes via-NAT path)
    if s3_cidrs and _ip_in_cidrs(rec.dst_ip, s3_cidrs):
        rec.dst_is_s3 = True
        rec.dst_resource_type = "s3"
        rec.dst_description = "Amazon S3"
        rec.dst_cloud_provider = "aws"
        return

    if api_cidrs and _ip_in_cidrs(rec.dst_ip, api_cidrs):
        rec.dst_is_aws_api = True
        rec.dst_resource_type = "aws_api"
        rec.dst_cloud_provider = "aws"
        return

    if gcs_cidrs and _ip_in_cidrs(rec.dst_ip, gcs_cidrs):
        rec.dst_is_gcs = True
        rec.dst_resource_type = "gcs"
        rec.dst_cloud_provider = "gcp"
        return

    if not _is_private(rec.dst_ip):
        # Cross-region S3: public IP not in regional S3 CIDRs but flow log identifies it as S3,
        # or IP falls in a global S3 CIDR from another region.
        if (rec.pkt_dst_aws_service or "").upper() == "S3":
            dst_region = _lookup_s3_region(rec.dst_ip, global_s3_ranges or [])
            rec.dst_is_s3 = True
            rec.dst_resource_type = "s3"
            rec.dst_description = "Amazon S3"
            rec.dst_cloud_provider = "aws"
            rec.dst_region = dst_region
            return
        if global_s3_ranges:
            dst_region = _lookup_s3_region(rec.dst_ip, global_s3_ranges)
            if dst_region is not None:
                rec.dst_is_s3 = True
                rec.dst_resource_type = "s3"
                rec.dst_description = "Amazon S3"
                rec.dst_cloud_provider = "aws"
                rec.dst_region = dst_region
                return
        # (debug only, removed after diagnosis)
        pass
        rec.dst_is_internet = True
        rec.dst_resource_type = "internet"
        rec.dst_cloud_provider = "internet"
        return

    # Private IP not in map (e.g., terminated instance receiving RDS responses)
    # — infer AZ and VPC from subnet CIDR so cross-AZ detectors can fire.
    sn = _subnet_info_for_ip(rec.dst_ip, ip_map)
    if sn:
        rec.dst_resource_type = "instance"
        rec.dst_az = sn.get("az")
        rec.dst_region = sn.get("region")
        rec.dst_vpc_id = sn.get("vpc_id")


def _detect_via_nat(rec: FlowRecord, nat_ips: set[str]) -> None:
    """Mark record as going via NAT if src is a NAT Gateway IP."""
    if rec.src_resource_type == "nat_gateway":
        rec.via_nat = True
        rec.nat_gateway_id = rec.src_resource_id
    # Also detect if dst is NAT (outbound path)
    if rec.dst_resource_type == "nat_gateway":
        rec.via_nat = True
        rec.nat_gateway_id = rec.dst_resource_id
    # Explicit NAT IP set from provider
    if rec.src_ip in nat_ips or rec.dst_ip in nat_ips:
        rec.via_nat = True
