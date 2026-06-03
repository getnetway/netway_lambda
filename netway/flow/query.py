from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from netway.providers.base import CloudProvider, FlowRecord

logger = logging.getLogger(__name__)

ANALYSIS_DAYS = int(os.environ.get("ANALYSIS_DAYS", "30"))
MAX_FLOWS = int(os.environ.get("MAX_FLOWS", "10000"))


def query_flow_logs(
    provider: CloudProvider,
    region: str,
    analysis_days: int | None = None,
) -> list[FlowRecord]:
    """Query and return flow records for the analysis window."""
    days = analysis_days if analysis_days is not None else ANALYSIS_DAYS
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(days=days)

    logger.info(
        "Querying %s flow logs in %s from %s to %s",
        provider.provider_name,
        region,
        start_time.date(),
        end_time.date(),
    )

    records = provider.query_flow_logs(region, start_time, end_time)

    # Filter out trivial flows — read at call time so env var changes take effect without cold start
    min_bytes = int(os.environ.get("MIN_BYTES_PER_FLOW", "1073741824"))
    records = [r for r in records if r.bytes_out >= min_bytes]

    # Sort by bytes descending and cap
    records.sort(key=lambda r: r.bytes_out, reverse=True)
    records = records[:MAX_FLOWS]

    logger.info("Retrieved %d flow records in %s", len(records), region)
    return records


def aggregate_flows(records: list[FlowRecord]) -> list[FlowRecord]:
    """Aggregate records with same (src_ip, dst_ip, dst_port) — sum bytes.

    The representative FlowRecord for each group is a COPY of the first record
    seen for that key so that all enriched fields (resource_type, AZ, via_nat,
    via_nat_az, pkt_src_addr, nat_gateway_id, dst_is_s3, etc.) are preserved.
    Only bytes_out and bytes_in are summed across duplicates.
    """
    import copy
    key_map: dict[tuple, FlowRecord] = {}
    for rec in records:
        key = (rec.src_ip, rec.dst_ip, rec.dst_port)
        if key in key_map:
            existing = key_map[key]
            existing.bytes_out += rec.bytes_out
            existing.bytes_in += rec.bytes_in
            existing.flow_count += 1
        else:
            # Deep-copy so mutations (byte accumulation) don't affect the original list
            agg = copy.copy(rec)
            agg.flow_count = 1
            key_map[key] = agg
    result = sorted(key_map.values(), key=lambda r: r.bytes_out, reverse=True)
    return result[:MAX_FLOWS]
