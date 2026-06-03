from __future__ import annotations

import os
from netway.providers.base import FlowRecord

MIN_MONTHLY_SAVING = float(os.environ.get("MIN_MONTHLY_SAVING", "100"))
ANALYSIS_DAYS = int(os.environ.get("ANALYSIS_DAYS", "30"))

# Cost rates in USD per GB
AWS_RATES = {
    "cross_az": 0.01,
    "cross_region": 0.09,
    "nat_processing": 0.045,
    "internet_out": 0.09,
    "same_az": 0.0,
}

GCP_RATES = {
    "cross_zone": 0.01,
    "cross_region": 0.08,
    "nat_processing": 0.045,
    "internet_out_premium": 0.12,
    "internet_out_standard": 0.085,
    "same_zone": 0.0,
}

NCCL_PORTS = {1234, 2222}  # Common ML distributed training ports


def classify_flows(
    records: list[FlowRecord],
    provider_name: str = "aws",
) -> list[FlowRecord]:
    """Set traffic_type, cost_per_gb, estimated_cost on each FlowRecord."""
    for rec in records:
        _classify_one(rec, provider_name)
    return records


def _classify_one(rec: FlowRecord, provider_name: str) -> None:
    if provider_name == "gcp":
        _classify_gcp(rec)
    else:
        _classify_aws(rec)

    # Compute estimated cost
    gb = rec.bytes_out / 1e9
    rec.estimated_cost = gb * rec.cost_per_gb


def _classify_aws(rec: FlowRecord) -> None:
    # 1. ML: training data cross-region (GPU → S3 in different region)
    if (
        rec.src_is_gpu
        and (rec.dst_is_s3 or rec.dst_is_gcs)
        and rec.src_region
        and rec.dst_region
        and rec.src_region != rec.dst_region
    ):
        rec.traffic_type = "ml_training_xregion"
        rec.cost_per_gb = 0.09
        return

    # 2. ML: checkpoint via NAT (GPU → S3 via NAT)
    if rec.src_is_gpu and rec.dst_is_s3 and rec.via_nat:
        rec.traffic_type = "ml_checkpoint_nat"
        rec.cost_per_gb = AWS_RATES["nat_processing"]
        return

    # 3. ML: gradient sync cross-AZ (GPU ↔ GPU different AZ)
    if (
        rec.src_is_gpu
        and rec.dst_resource_type == "instance"
        and getattr(rec, "dst_is_gpu", False)
        and rec.src_az
        and rec.dst_az
        and rec.src_az != rec.dst_az
        and rec.src_region == rec.dst_region
    ):
        rec.traffic_type = "ml_gradient_sync"
        rec.cost_per_gb = 0.02  # both directions
        return

    # 4. ML: inference cold start loading (SageMaker → S3 via NAT)
    if rec.src_resource_type == "sagemaker" and rec.dst_is_s3 and rec.via_nat:
        rec.traffic_type = "ml_inference_load"
        rec.cost_per_gb = AWS_RATES["nat_processing"]
        return

    # 5. ML: feature store cross-region
    if (
        rec.src_is_gpu
        and rec.dst_resource_type in ("rds", "elasticache", "dynamodb")
        and rec.src_region
        and rec.dst_region
        and rec.src_region != rec.dst_region
    ):
        rec.traffic_type = "ml_feature_pull"
        rec.cost_per_gb = 0.02
        return

    # 6. ML: data gravity (S3 egress to internet — specialist GPU cloud)
    if rec.dst_is_internet and rec.src_is_gpu and rec.src_resource_type in ("s3_bucket", "instance"):
        # Detect as data gravity pattern when large volumes go to internet
        rec.traffic_type = "ml_data_gravity"
        rec.cost_per_gb = AWS_RATES["internet_out"]
        return

    # 7. S3 via NAT
    if rec.dst_is_s3 and rec.via_nat:
        rec.traffic_type = "via_nat_to_s3"
        rec.cost_per_gb = AWS_RATES["nat_processing"]
        return

    # 8. AWS API via NAT
    if rec.dst_is_aws_api and rec.via_nat:
        rec.traffic_type = "via_nat_to_aws_api"
        rec.cost_per_gb = AWS_RATES["nat_processing"]
        return

    # 9. Cross-AZ (same region)
    if (
        rec.src_az
        and rec.dst_az
        and rec.src_az != rec.dst_az
        and rec.src_region
        and rec.dst_region
        and rec.src_region == rec.dst_region
    ):
        rec.traffic_type = "cross_az"
        rec.cost_per_gb = AWS_RATES["cross_az"]
        return

    # 10. Cross-region
    if rec.src_region and rec.dst_region and rec.src_region != rec.dst_region:
        rec.traffic_type = "cross_region"
        rec.cost_per_gb = AWS_RATES["cross_region"]
        return

    # 11. Internet egress
    if rec.dst_is_internet:
        rec.traffic_type = "to_internet"
        rec.cost_per_gb = AWS_RATES["internet_out"]
        return

    # 12. Same AZ — free
    rec.traffic_type = "same_az"
    rec.cost_per_gb = 0.0


def _classify_gcp(rec: FlowRecord) -> None:
    # GCP: VM → GCS via Cloud NAT
    if rec.dst_is_gcs and rec.via_nat:
        rec.traffic_type = "gcp_nat_to_gcs"
        rec.cost_per_gb = GCP_RATES["nat_processing"]
        return

    # GCP: cross-zone same region
    if (
        rec.src_az
        and rec.dst_az
        and rec.src_az != rec.dst_az
        and rec.src_region
        and rec.dst_region
        and rec.src_region == rec.dst_region
    ):
        rec.traffic_type = "gcp_cross_zone"
        rec.cost_per_gb = GCP_RATES["cross_zone"]
        return

    # GCP: cross-region
    if rec.src_region and rec.dst_region and rec.src_region != rec.dst_region:
        rec.traffic_type = "cross_region"
        rec.cost_per_gb = GCP_RATES["cross_region"]
        return

    # Internet egress
    if rec.dst_is_internet:
        rec.traffic_type = "to_internet"
        rec.cost_per_gb = GCP_RATES["internet_out_premium"]
        return

    rec.traffic_type = "same_zone"
    rec.cost_per_gb = 0.0
