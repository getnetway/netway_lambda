"""AWS Lambda entry point for Netway.

Responsibility (post-refactor):
  1. Query Athena for VPC flow logs
  2. Build IP → resource map
  3. Enrich and classify flows
  4. Pre-aggregate to reduce payload size
  5. POST aggregated flows + metadata to Netway API (/api/v1/ingest)
  6. API server runs detectors, saves findings, sends notifications

Detection logic no longer lives in the Lambda.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)

_ATHENA_REGION = os.environ.get("ATHENA_REGION") or os.environ.get("AWS_REGION", "us-east-1")


# ── Athena helpers ────────────────────────────────────────────────────────────

def _run_athena_query(athena, query: str, results_bucket: str, workgroup: str) -> str:
    resp = athena.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": f"s3://{results_bucket}/athena-setup/"},
        WorkGroup=workgroup,
    )
    execution_id = resp["QueryExecutionId"]
    while True:
        status = athena.get_query_execution(QueryExecutionId=execution_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            return execution_id
        if state in ("FAILED", "CANCELLED"):
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", "")
            raise RuntimeError(f"Athena query {execution_id} {state}: {reason}")
        time.sleep(2)


def ensure_athena_table(flow_logs_bucket: str, account_id: str, region: str) -> None:
    results_bucket = os.environ.get("ATHENA_RESULTS_BUCKET", "")
    workgroup = os.environ.get("ATHENA_WORKGROUP", "netway-analyzer")
    athena = boto3.client("athena", region_name=_ATHENA_REGION)

    _run_athena_query(athena, "CREATE DATABASE IF NOT EXISTS netway", results_bucket, workgroup)

    create_sql = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS netway.vpc_flow_logs (
      version              int,
      account_id           string,
      interface_id         string,
      srcaddr              string,
      dstaddr              string,
      srcport              int,
      dstport              int,
      protocol             bigint,
      packets              bigint,
      bytes                bigint,
      start_time           bigint,
      end_time             bigint,
      action               string,
      log_status           string,
      vpc_id               string,
      subnet_id            string,
      instance_id          string,
      tcp_flags            int,
      type                 string,
      pkt_srcaddr          string,
      pkt_dstaddr          string,
      region               string,
      az_id                string,
      sublocation_type     string,
      sublocation_id       string,
      pkt_src_aws_service  string,
      pkt_dst_aws_service  string,
      flow_direction       string,
      traffic_path         int
    )
    PARTITIONED BY (year string, month string, day string)
    ROW FORMAT DELIMITED
    FIELDS TERMINATED BY ' '
    LOCATION 's3://{flow_logs_bucket}/AWSLogs/{account_id}/vpcflowlogs/{region}/'
    TBLPROPERTIES ("skip.header.line.count"="1")
    """
    _run_athena_query(athena, create_sql, results_bucket, workgroup)
    logger.info("Athena table netway.vpc_flow_logs ready")


def add_athena_partitions(
    flow_logs_bucket: str, account_id: str, region: str, analysis_days: int
) -> None:
    results_bucket = os.environ.get("ATHENA_RESULTS_BUCKET", "")
    workgroup = os.environ.get("ATHENA_WORKGROUP", "netway-analyzer")
    athena = boto3.client("athena", region_name=_ATHENA_REGION)

    now = datetime.now(tz=timezone.utc)
    for i in range(analysis_days):
        day_dt = now - timedelta(days=i)
        year, month, day = day_dt.strftime("%Y"), day_dt.strftime("%m"), day_dt.strftime("%d")
        location = (
            f"s3://{flow_logs_bucket}/AWSLogs/{account_id}/"
            f"vpcflowlogs/{region}/{year}/{month}/{day}/"
        )
        sql = f"""
        ALTER TABLE netway.vpc_flow_logs ADD IF NOT EXISTS
        PARTITION (year='{year}', month='{month}', day='{day}')
        LOCATION '{location}'
        """
        try:
            _run_athena_query(athena, sql, results_bucket, workgroup)
        except Exception as exc:
            logger.warning("Failed to add partition %s-%s-%s: %s", year, month, day, exc)


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate_flows(flows) -> list[dict]:
    """
    Aggregate enriched FlowRecords into summary groups.

    Groups by the fields detectors need for pattern matching.
    Sums bytes_out, bytes_in, flow_count per group.

    Reduces millions of flow records to thousands of groups,
    cutting payload size by ~99% before sending to server.
    """
    groups: dict[tuple, dict] = {}

    for f in flows:
        key = (
            f.src_resource_id,
            f.src_resource_name,
            f.src_resource_type,
            f.src_az,
            f.src_region,
            f.src_vpc_id,
            f.src_is_gpu,
            f.src_instance_type,
            json.dumps(f.src_tags, sort_keys=True) if f.src_tags else "{}",
            f.dst_resource_id,
            f.dst_resource_name,
            f.dst_resource_type,
            f.dst_az,
            f.dst_region,
            f.dst_vpc_id,
            f.dst_is_s3,
            f.dst_is_aws_api,
            f.dst_is_internet,
            f.dst_is_gcs,
            f.dst_cloud_provider,
            f.via_nat,
            f.nat_gateway_id,
            f.via_nat_az,
            f.traffic_type,
            f.cost_per_gb,
            f.pkt_src_aws_service,
            f.pkt_dst_aws_service,
            # Keep src_ip / dst_ip of representative flow for top_flows on server
            f.src_ip,
            f.dst_ip,
        )
        if key not in groups:
            groups[key] = {
                "src_ip":            f.src_ip,
                "dst_ip":            f.dst_ip,
                "src_resource_id":   f.src_resource_id,
                "src_resource_name": f.src_resource_name,
                "src_resource_type": f.src_resource_type,
                "src_az":            f.src_az,
                "src_region":        f.src_region,
                "src_vpc_id":        f.src_vpc_id,
                "src_is_gpu":        f.src_is_gpu,
                "src_instance_type": f.src_instance_type,
                "src_tags":          f.src_tags or {},
                "dst_resource_id":   f.dst_resource_id,
                "dst_resource_name": f.dst_resource_name,
                "dst_resource_type": f.dst_resource_type,
                "dst_az":            f.dst_az,
                "dst_region":        f.dst_region,
                "dst_vpc_id":        f.dst_vpc_id,
                "dst_is_s3":         f.dst_is_s3,
                "dst_is_aws_api":    f.dst_is_aws_api,
                "dst_is_internet":   f.dst_is_internet,
                "dst_is_gcs":        f.dst_is_gcs,
                "dst_cloud_provider": f.dst_cloud_provider,
                "via_nat":           f.via_nat,
                "nat_gateway_id":    f.nat_gateway_id,
                "via_nat_az":        f.via_nat_az,
                "traffic_type":      f.traffic_type,
                "cost_per_gb":       f.cost_per_gb,
                "pkt_src_aws_service": f.pkt_src_aws_service,
                "pkt_dst_aws_service": f.pkt_dst_aws_service,
                "bytes_out":         0,
                "bytes_in":          0,
                "flow_count":        0,
                # Unused by detectors but kept for FlowRecord reconstruction on server
                "src_port":          f.src_port,
                "dst_port":          f.dst_port,
                "protocol":          f.protocol,
                "action":            f.action,
                "timestamp":         f.timestamp.isoformat(),
                "estimated_cost":    0.0,
                "dst_is_gpu":        f.dst_is_gpu,
                "pkt_src_addr":      f.pkt_src_addr,
                "pkt_dst_addr":      f.pkt_dst_addr,
            }
        groups[key]["bytes_out"]      += f.bytes_out
        groups[key]["bytes_in"]       += f.bytes_in
        groups[key]["flow_count"]     += 1
        groups[key]["estimated_cost"] += f.estimated_cost

    return list(groups.values())


# ── HMAC signing ──────────────────────────────────────────────────────────────

def _sign_payload(payload_bytes: bytes, api_key: str) -> str:
    """HMAC-SHA256 signature over the raw (compressed) payload bytes."""
    return hmac.new(api_key.encode(), payload_bytes, hashlib.sha256).hexdigest()


# ── Post flows to API ─────────────────────────────────────────────────────────

class TrialExpiredError(Exception):
    pass


def _post_flows_to_api(
    regions_data: dict[str, dict],
    scan_id: str,
    account_id: str,
    provider: str,
    analysis_days: int,
) -> None:
    """POST aggregated enriched flows to the Netway API for server-side detection."""
    api_url = os.environ.get("NETWAY_API_URL")
    api_key = os.environ.get("NETWAY_API_KEY")
    if not api_url or not api_key:
        logger.warning("NETWAY_API_URL or NETWAY_API_KEY not set — skipping ingest POST")
        return

    payload = {
        "scan_id":      scan_id,
        "provider":     provider,
        "account_id":   account_id,
        "analysis_days": analysis_days,
        "regions_data": regions_data,  # {region: {flows: [...], vpc_endpoints: [...]}}
    }

    payload_bytes = json.dumps(payload).encode()
    compressed    = gzip.compress(payload_bytes)
    signature     = _sign_payload(compressed, api_key)

    import httpx
    try:
        resp = httpx.post(
            f"{api_url}/api/v1/ingest",
            content=compressed,
            headers={
                "x-api-key":          api_key,
                "x-netway-signature": signature,
                "Content-Encoding":   "gzip",
                "Content-Type":       "application/json",
            },
            timeout=60,
        )
        if resp.status_code == 402:
            body = resp.json() if resp.content else {}
            if body.get("detail", {}).get("error") == "trial_expired":
                raise TrialExpiredError(body["detail"].get("message", "Trial expired"))
        resp.raise_for_status()
        resp_body = resp.json() if resp.content else {}
        job_id    = resp_body.get("job_id", "unknown")
        logger.info(
            "Flows posted to API: scan_id=%s job_id=%s regions=%s total_groups=%d",
            scan_id,
            job_id,
            list(regions_data.keys()),
            sum(len(v.get("flows", [])) for v in regions_data.values()),
        )
        return job_id
    except TrialExpiredError:
        raise
    except Exception as exc:
        logger.error("Failed to post flows to Netway API: %s", exc)
        raise


# ── Marketplace metering ──────────────────────────────────────────────────────

def report_marketplace_usage() -> None:
    if not os.environ.get("MARKETPLACE_ENABLED", "false").lower() == "true":
        return
    product_code = os.environ.get("MARKETPLACE_PRODUCT_CODE", "").strip()
    if not product_code:
        logger.warning("MARKETPLACE_PRODUCT_CODE not set — skipping metering")
        return
    tier = os.environ.get("NETWAY_TIER", "starter").lower()
    dimension = tier if tier in {"starter", "growth", "scale"} else "starter"
    try:
        client = boto3.client("meteringmarketplace", region_name="us-east-1")
        response = client.meter_usage(
            ProductCode=product_code,
            Timestamp=datetime.now(timezone.utc),
            UsageDimension=dimension,
            UsageQuantity=1,
            DryRun=False,
        )
        logger.info("Marketplace usage reported: dimension=%s record=%s",
                    dimension, response.get("MeteringRecordId", "unknown"))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        logger.warning("Metering ClientError: %s — %s", code, e)
    except BotoCoreError as e:
        logger.warning("Metering network error: %s", e)
    except Exception as e:
        logger.error("Unexpected metering error: %s", e)


# ── Lambda handler ────────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:
    """
    Lambda entry point.

    Queries flow logs, enriches, aggregates, and ships to API server.
    Detection runs server-side.
    """
    from netway.config import validate_config
    from netway.providers import get_provider
    from netway.flow.query import query_flow_logs
    from netway.flow.mapper import build_ip_resource_map, enrich_flows, clear_ip_map_cache
    from netway.flow.classifier import classify_flows

    clear_ip_map_cache()
    validate_config()
    provider  = get_provider()
    trigger   = event.get("trigger", "scheduled")
    scan_id   = str(uuid.uuid4())

    logger.info("Netway scan starting — scan_id=%s trigger=%s provider=%s",
                scan_id, trigger, provider.provider_name)

    analysis_days = int(os.environ.get("ANALYSIS_DAYS", "30"))

    # ── Athena setup ──────────────────────────────────────────────────────────
    account_id = ""
    if os.environ.get("CLOUD_PROVIDER", "aws").lower() == "aws":
        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        for region in provider.list_regions():
            flow_logs_bucket = os.environ.get("FLOW_LOGS_S3_BUCKET", "")
            try:
                ensure_athena_table(flow_logs_bucket, account_id, region)
                add_athena_partitions(flow_logs_bucket, account_id, region, analysis_days)
            except Exception as exc:
                logger.warning("Athena setup failed for %s: %s", region, exc)

    # ── Build IP maps upfront (all regions) ──────────────────────────────────
    all_ip_maps: dict[str, dict] = {}
    for r in provider.list_regions():
        all_ip_maps[r] = build_ip_resource_map(provider, r)

    # ── Per-region: query, enrich, classify, aggregate ───────────────────────
    regions_data: dict[str, dict] = {}
    total_flow_groups = 0

    for region in provider.list_regions():
        logger.info("Scanning region: %s", region)

        flows = query_flow_logs(provider, region, analysis_days=analysis_days)
        if not flows:
            logger.info("No flows in %s — skipping", region)
            continue

        # Merge ip_maps: current region takes precedence
        ip_map = all_ip_maps[region]
        merged_ip_map: dict[str, dict] = {}
        for r, rmap in all_ip_maps.items():
            if r != region:
                merged_ip_map.update({k: v for k, v in rmap.items() if k != "__subnets__"})
        merged_ip_map.update(ip_map)

        s3_cidrs      = provider.get_s3_ip_ranges(region)
        api_cidrs     = provider.get_aws_api_ip_ranges(region)
        gcs_cidrs     = provider.get_gcs_ip_ranges() if hasattr(provider, "get_gcs_ip_ranges") else []
        global_s3     = provider.get_all_s3_ip_ranges() if hasattr(provider, "get_all_s3_ip_ranges") else []

        nat_gateways  = provider.list_nat_gateways(region)
        nat_ips: set[str] = set()
        for ng in nat_gateways:
            nat_ips.update(ng.get("public_ips", []))
            nat_ips.update(ng.get("private_ips", []))

        flows = enrich_flows(flows, merged_ip_map, s3_cidrs, api_cidrs, gcs_cidrs, nat_ips, global_s3)
        flows = classify_flows(flows, provider_name=provider.provider_name)

        # Log traffic-type summary so support can verify enrichment without needing
        # to re-run the scan.  Counts only — no IPs or resource IDs logged here.
        from collections import Counter
        type_counts = Counter(f.traffic_type for f in flows)
        via_nat_count = sum(1 for f in flows if f.via_nat)
        logger.info(
            "[%s] Enrichment summary: %d flows | via_nat=%d | nat_gateways_found=%d "
            "| nat_ips=%d | s3_cidrs=%d | traffic_types=%s",
            region, len(flows), via_nat_count,
            len([v for v in merged_ip_map.values()
                 if isinstance(v, dict) and v.get("resource_type") == "nat_gateway"]),
            len(nat_ips), len(s3_cidrs), dict(type_counts),
        )

        aggregated    = aggregate_flows(flows)
        vpc_endpoints = provider.list_vpc_endpoints(region)

        regions_data[region] = {
            "flows":         aggregated,
            "vpc_endpoints": vpc_endpoints,
        }
        total_flow_groups += len(aggregated)
        logger.info("Region %s: %d flows → %d aggregated groups", region, len(flows), len(aggregated))

    if not regions_data:
        logger.info("No flow data across all regions — nothing to post")
        return {"statusCode": 200, "message": "no_flows"}

    report_marketplace_usage()

    # ── Ship to API server ────────────────────────────────────────────────────
    job_id = "unknown"
    try:
        job_id = _post_flows_to_api(
            regions_data=regions_data,
            scan_id=scan_id,
            account_id=account_id,
            provider=provider.provider_name,
            analysis_days=analysis_days,
        )
    except TrialExpiredError as e:
        logger.error("NETWAY TRIAL EXPIRED — %s", e)
        return {"statusCode": 402, "error": "trial_expired", "message": str(e)}
    except Exception as e:
        logger.error("Failed to ship flows to API: %s", e)
        return {"statusCode": 500, "error": "ingest_failed", "message": str(e)}

    logger.info("Scan complete: scan_id=%s job_id=%s total_groups=%d",
                scan_id, job_id, total_flow_groups)
    return {
        "statusCode":        200,
        "scan_id":           scan_id,
        "job_id":            job_id,
        "regions":           list(regions_data.keys()),
        "total_flow_groups": total_flow_groups,
    }
