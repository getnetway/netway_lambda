from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import requests

from .base import CloudProvider, FlowRecord

logger = logging.getLogger(__name__)

GPU_INSTANCE_PREFIXES = (
    "p2.", "p3.", "p4d.", "p5.", "g3.", "g4dn.", "g5.", "g6.", "trn1.",
)

_IP_RANGES_CACHE: dict[str, Any] = {}
_IP_RANGES_FETCHED_AT: float = 0.0
_IP_RANGES_TTL = 3600


def _fetch_ip_ranges() -> dict:
    global _IP_RANGES_CACHE, _IP_RANGES_FETCHED_AT
    now = time.time()
    if _IP_RANGES_CACHE and (now - _IP_RANGES_FETCHED_AT) < _IP_RANGES_TTL:
        return _IP_RANGES_CACHE
    try:
        resp = requests.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10
        )
        resp.raise_for_status()
        _IP_RANGES_CACHE = resp.json()
        _IP_RANGES_FETCHED_AT = now
    except Exception as exc:
        logger.warning("Failed to fetch AWS IP ranges: %s", exc)
        if not _IP_RANGES_CACHE:
            _IP_RANGES_CACHE = {"prefixes": []}
    return _IP_RANGES_CACHE


def _clean_svc(val: str | None) -> str | None:
    """Strip VPC flow log sentinel '-' so downstream code sees None instead."""
    if not val or val.strip() == "-":
        return None
    return val.strip()


def _is_gpu(instance_type: str | None) -> bool:
    if not instance_type:
        return False
    return any(instance_type.startswith(p) for p in GPU_INSTANCE_PREFIXES)


def _ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


class AWSProvider(CloudProvider):

    def __init__(self) -> None:
        self._regions = [
            r.strip()
            for r in os.environ.get("AWS_REGIONS", os.environ.get("AWS_REGION", "us-east-1")).split(",")
            if r.strip()
        ]
        self._flow_log_source = os.environ.get("FLOW_LOG_SOURCE", "s3_athena")
        self._flow_logs_bucket = os.environ.get("FLOW_LOGS_S3_BUCKET", "")
        self._flow_logs_prefix = os.environ.get("FLOW_LOGS_S3_PREFIX", "AWSLogs/")
        self._athena_database = os.environ.get("ATHENA_DATABASE", "netway")
        self._athena_results_bucket = os.environ.get("ATHENA_RESULTS_BUCKET", "")
        self._athena_workgroup = os.environ.get("ATHENA_WORKGROUP", "netway-analyzer")
        self._athena_region = (
            os.environ.get("ATHENA_REGION") or os.environ.get("AWS_REGION", "ap-south-1")
        )
        self._analysis_days = int(os.environ.get("ANALYSIS_DAYS", "30"))

        role_arn = os.environ.get("AWS_ROLE_ARN")
        if role_arn:
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="netway-analyzer"
            )["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        else:
            self._session = boto3.Session()

        # Cache for IP ranges per region
        self._s3_ranges_cache: dict[str, list[str]] = {}
        self._api_ranges_cache: dict[str, list[str]] = {}

    @property
    def provider_name(self) -> str:
        return "aws"

    def list_regions(self) -> list[str]:
        return self._regions

    def _client(self, service: str, region: str):
        return self._session.client(service, region_name=region)

    # ── Flow log queries ──────────────────────────────────────────────────

    def query_flow_logs(
        self,
        region: str,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: list[str] | None = None,
    ) -> list[FlowRecord]:
        try:
            if self._flow_log_source == "s3_athena":
                return self._query_athena(region, start_time, end_time)
            else:
                return self._query_cloudwatch(region, start_time, end_time)
        except Exception as exc:
            logger.warning("Failed to query flow logs in %s: %s", region, exc)
            return []

    def _query_athena(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[FlowRecord]:
        athena = self._client("athena", self._athena_region)
        records: list[FlowRecord] = []
        current = start_time
        while current.date() <= end_time.date():
            year = current.strftime("%Y")
            month = current.strftime("%m")
            day = current.strftime("%d")
            query = f"""
                SELECT
                  from_unixtime(start_time) AS ts,
                  srcaddr, dstaddr,
                  CAST(srcport AS BIGINT) AS srcport,
                  CAST(dstport AS BIGINT) AS dstport,
                  protocol,
                  CAST(bytes AS BIGINT) AS bytes,
                  CAST(packets AS BIGINT) AS packets,
                  action,
                  flow_direction,
                  pkt_srcaddr,
                  pkt_dstaddr,
                  pkt_src_aws_service,
                  pkt_dst_aws_service
                FROM {self._athena_database}.vpc_flow_logs
                WHERE year='{year}' AND month='{month}' AND day='{day}'
                  AND CAST(bytes AS BIGINT) > 0
                  AND action = 'ACCEPT'
                ORDER BY bytes DESC
                LIMIT 100000
            """
            try:
                rows = self._run_athena_query(athena, query)
                records.extend(self._parse_athena_rows(rows))
            except Exception as exc:
                logger.warning("Athena query failed for %s-%s-%s: %s", year, month, day, exc)
            current += timedelta(days=1)
        return records

    def _run_athena_query(self, athena, query: str) -> list[dict]:
        resp = athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": self._athena_database},
            ResultConfiguration={
                "OutputLocation": f"s3://{self._athena_results_bucket}/"
            },
            WorkGroup=self._athena_workgroup,
        )
        execution_id = resp["QueryExecutionId"]
        while True:
            status = athena.get_query_execution(QueryExecutionId=execution_id)
            state = status["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED",):
                break
            if state in ("FAILED", "CANCELLED"):
                reason = status["QueryExecution"]["Status"].get("StateChangeReason", "no reason given")
                raise RuntimeError(f"Athena query {execution_id} {state}: {reason}")
            time.sleep(2)

        paginator = athena.get_paginator("get_query_results")
        columns: list[str] = []
        rows: list[dict] = []
        for page in paginator.paginate(QueryExecutionId=execution_id):
            for i, row in enumerate(page["ResultSet"]["Rows"]):
                values = [cell.get("VarCharValue", "") for cell in row["Data"]]
                if not columns:
                    # First row across all pages is the header
                    columns = values
                    continue
                rows.append(dict(zip(columns, values)))
        return rows

    def _parse_athena_rows(self, rows: list[dict]) -> list[FlowRecord]:
        """Parse rows returned by _run_athena_query (header already stripped, values are strings)."""
        records = []
        for row in rows:
            try:
                # Athena returns all values as strings — cast explicitly
                ts_raw = row.get("ts", "2000-01-01 00:00:00") or "2000-01-01 00:00:00"
                r = FlowRecord(
                    timestamp=datetime.fromisoformat(ts_raw),
                    src_ip=row.get("srcaddr", "") or "",
                    dst_ip=row.get("dstaddr", "") or "",
                    src_port=int(row.get("srcport") or 0),
                    dst_port=int(row.get("dstport") or 0),
                    protocol=str(row.get("protocol") or "TCP").upper(),
                    bytes_out=int(row.get("bytes") or 0),
                    bytes_in=0,
                    action=str(row.get("action") or "ACCEPT").upper(),
                    pkt_src_addr=_clean_svc(row.get("pkt_srcaddr")),
                    pkt_dst_addr=_clean_svc(row.get("pkt_dstaddr")),
                    pkt_src_aws_service=_clean_svc(row.get("pkt_src_aws_service")),
                    pkt_dst_aws_service=_clean_svc(row.get("pkt_dst_aws_service")),
                )
                records.append(r)
            except Exception:
                continue
        return records

    def _query_cloudwatch(
        self, region: str, start_time: datetime, end_time: datetime
    ) -> list[FlowRecord]:
        logs = self._client("logs", region)
        log_group = os.environ.get("CLOUDWATCH_LOG_GROUP", "/aws/vpc/flowlogs")
        query = """
            fields @timestamp, srcAddr, dstAddr, srcPort, dstPort,
                   protocol, bytes, action
            | filter bytes > 0 and action = "ACCEPT"
            | sort bytes desc
            | limit 10000
        """
        try:
            resp = logs.start_query(
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query,
            )
            query_id = resp["queryId"]
            while True:
                result = logs.get_query_results(queryId=query_id)
                if result["status"] in ("Complete",):
                    break
                if result["status"] in ("Failed", "Cancelled", "Timeout"):
                    return []
                time.sleep(2)
            return self._parse_cw_results(result["results"])
        except Exception as exc:
            logger.warning("CloudWatch Logs query failed: %s", exc)
            return []

    def _parse_cw_results(self, results: list) -> list[FlowRecord]:
        records = []
        for row in results:
            fields = {item["field"]: item["value"] for item in row}
            try:
                ts_raw = fields.get("@timestamp", "2000-01-01T00:00:00.000Z")
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                r = FlowRecord(
                    timestamp=ts,
                    src_ip=fields.get("srcAddr", ""),
                    dst_ip=fields.get("dstAddr", ""),
                    src_port=int(fields.get("srcPort", 0) or 0),
                    dst_port=int(fields.get("dstPort", 0) or 0),
                    protocol=str(fields.get("protocol", "6")),
                    bytes_out=int(fields.get("bytes", 0) or 0),
                    bytes_in=0,
                    action=str(fields.get("action", "ACCEPT")).upper(),
                )
                records.append(r)
            except Exception:
                continue
        return records

    # ── IP to resource mapping ────────────────────────────────────────────

    def build_ip_resource_map(self, region: str) -> dict[str, dict]:
        ip_map: dict[str, dict] = {}
        ec2 = self._client("ec2", region)

        # EC2 instances
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for inst in reservation["Instances"]:
                        itype = inst.get("InstanceType", "")
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        name = tags.get("Name", inst["InstanceId"])
                        for iface in inst.get("NetworkInterfaces", []):
                            priv_ip = iface.get("PrivateIpAddress")
                            if priv_ip:
                                ip_map[priv_ip] = {
                                    "resource_id": inst["InstanceId"],
                                    "resource_name": name,
                                    "resource_type": "instance",
                                    "az": inst.get("Placement", {}).get("AvailabilityZone", ""),
                                    "region": region,
                                    "vpc_id": inst.get("VpcId", ""),
                                    "instance_type": itype,
                                    "is_gpu": _is_gpu(itype),
                                    "tags": tags,
                                }
                            # Association public IP
                            assoc = iface.get("Association", {})
                            pub_ip = assoc.get("PublicIp")
                            if pub_ip:
                                ip_map[pub_ip] = ip_map.get(priv_ip, {}).copy()
                                ip_map[pub_ip]["public_ip"] = pub_ip
        except Exception as exc:
            logger.warning("Failed to describe instances in %s: %s", region, exc)

        # RDS instances — map private IPs to RDS metadata.
        #
        # Flow logs record private IPs, not hostnames.  We use three strategies
        # in order of reliability:
        #   1. Direct ENI lookup filtered by the RDS instance's security groups —
        #      the ENI private IP is exactly what appears in flow logs and is stable.
        #   2. DNS resolution of the endpoint hostname — works most of the time but
        #      can return a different IP than the one recorded in flow logs when the
        #      RDS DNS entry changes (e.g. after a failover or when DNS TTLs differ).
        #   3. Store by hostname — last-resort fallback if flows somehow contain the
        #      hostname string instead of an IP (should not happen with VPC flow logs).
        try:
            rds = self._client("rds", region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    endpoint = db.get("Endpoint", {})
                    host = endpoint.get("Address", "")
                    if not host:
                        continue
                    db_id = db["DBInstanceIdentifier"]
                    rds_info = {
                        "resource_id": db_id,
                        "resource_name": db_id,
                        "resource_type": "rds",
                        "az": db.get("AvailabilityZone", ""),
                        "region": region,
                        "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId", ""),
                        "instance_type": db.get("DBInstanceClass", ""),
                        "is_gpu": False,
                        "tags": {},
                    }

                    # Strategy 1: look up ENIs via the RDS instance's security groups.
                    # ENI private IP == the exact IP that appears in VPC flow logs.
                    sg_ids = [
                        sg["VpcSecurityGroupId"]
                        for sg in db.get("VpcSecurityGroups", [])
                        if sg.get("Status") == "active"
                    ]
                    eni_ips_found: list[str] = []
                    if sg_ids:
                        try:
                            eni_resp = ec2.describe_network_interfaces(
                                Filters=[{"Name": "group-id", "Values": sg_ids}]
                            )
                            for eni in eni_resp.get("NetworkInterfaces", []):
                                # RequesterManaged=True means AWS (not the customer) created
                                # this ENI — true for RDS, ELB, etc., never for EC2 instances.
                                # This reliably separates RDS ENIs from customer EC2 ENIs that
                                # happen to share the same security group.
                                if not eni.get("RequesterManaged", False):
                                    continue
                                priv_ip = eni.get("PrivateIpAddress")
                                if priv_ip:
                                    ip_map[priv_ip] = rds_info
                                    eni_ips_found.append(priv_ip)
                        except Exception as eni_exc:
                            logger.warning("RDS ENI lookup failed for %s: %s", db_id, eni_exc)

                    # Strategy 2: DNS resolution (fallback for any IPs not yet found).
                    try:
                        resolved = [info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET)]
                        for resolved_ip in resolved:
                            if resolved_ip not in ip_map:
                                ip_map[resolved_ip] = rds_info
                        logger.info(
                            "RDS %s (%s): ENI IPs=%s DNS IPs=%s",
                            db_id, host, eni_ips_found, resolved,
                        )
                    except Exception as dns_exc:
                        logger.warning("RDS DNS resolution failed for %s: %s", host, dns_exc)
                        if eni_ips_found:
                            logger.info(
                                "RDS %s (%s): DNS failed but ENI IPs=%s — using those",
                                db_id, host, eni_ips_found,
                            )

                    # Strategy 3: store by hostname (last resort).
                    ip_map[host] = rds_info
        except Exception as exc:
            logger.warning("Failed to describe RDS in %s: %s", region, exc)

        # NAT Gateways
        try:
            nats = ec2.describe_nat_gateways()
            for nat in nats.get("NatGateways", []):
                if nat.get("State") != "available":
                    continue
                # Look up the AZ from the NAT gateway's SubnetId
                try:
                    sub = ec2.describe_subnets(SubnetIds=[nat.get("SubnetId", "")])
                    nat_az = sub["Subnets"][0]["AvailabilityZone"] if sub.get("Subnets") else ""
                except Exception:
                    nat_az = ""
                for addr in nat.get("NatGatewayAddresses", []):
                    priv_ip = addr.get("PrivateIp")
                    pub_ip = addr.get("PublicIp")
                    info = {
                        "resource_id": nat["NatGatewayId"],
                        "resource_name": nat["NatGatewayId"],
                        "resource_type": "nat_gateway",
                        "az": nat_az,
                        "region": region,
                        "vpc_id": nat.get("VpcId", ""),
                        "is_gpu": False,
                        "tags": {},
                    }
                    if priv_ip:
                        ip_map[priv_ip] = info
                    if pub_ip:
                        ip_map[pub_ip] = {**info, "is_public": True}
        except Exception as exc:
            logger.warning("Failed to describe NAT gateways in %s: %s", region, exc)

        # ── SageMaker endpoint ENI discovery via SageMaker API ───────────────
        # Explicitly resolves ENI IPs for InService endpoints via their VpcConfig
        # so the ip_map tags them as "sagemaker" regardless of ENI description format.
        # (ENI descriptions vary: "SageMaker Endpoint Management", "SageMaker", or empty.)
        _sm_eni_ips: set[str] = set()
        try:
            sm_client = boto3.client("sagemaker", region_name=region)
            sm_paginator = sm_client.get_paginator("list_endpoints")
            for sm_page in sm_paginator.paginate(StatusEquals="InService"):
                for ep in sm_page["Endpoints"]:
                    ep_name = ep["EndpointName"]
                    try:
                        ep_desc = sm_client.describe_endpoint(EndpointName=ep_name)
                        config_name = ep_desc.get("EndpointConfigName", "")
                        cfg_desc = sm_client.describe_endpoint_config(
                            EndpointConfigName=config_name
                        )
                        # Collect all subnets + SGs from each variant's model VpcConfig
                        sm_subnets: list[str] = []
                        sm_sgs: list[str] = []
                        for variant in cfg_desc.get("ProductionVariants", []):
                            try:
                                model_name = variant.get("ModelName", "")
                                model_desc = sm_client.describe_model(ModelName=model_name)
                                vpc = model_desc.get("VpcConfig", {})
                                sm_subnets.extend(vpc.get("Subnets", []))
                                sm_sgs.extend(vpc.get("SecurityGroupIds", []))
                            except Exception:
                                pass
                        if not sm_subnets and not sm_sgs:
                            continue
                        # Find ENIs in those subnets that are RequesterManaged
                        filters = []
                        if sm_subnets:
                            filters.append({"Name": "subnet-id", "Values": sm_subnets})
                        sm_eni_resp = ec2.describe_network_interfaces(Filters=filters) if filters else {"NetworkInterfaces": []}
                        for sm_eni in sm_eni_resp.get("NetworkInterfaces", []):
                            if not sm_eni.get("RequesterManaged", False):
                                continue
                            sm_ip = sm_eni.get("PrivateIpAddress")
                            if not sm_ip:
                                continue
                            _sm_eni_ips.add(sm_ip)
                            sm_eni_desc = sm_eni.get("Description", f"SageMaker Endpoint {ep_name}")
                            ip_map[sm_ip] = {
                                "resource_id": sm_eni["NetworkInterfaceId"],
                                "resource_name": sm_eni_desc or f"SageMaker/{ep_name}",
                                "resource_type": "sagemaker",
                                "az": sm_eni.get("AvailabilityZone", ""),
                                "region": region,
                                "vpc_id": sm_eni.get("VpcId", ""),
                                "is_gpu": False,
                                "tags": {},
                            }
                        logger.info(
                            "SageMaker endpoint %s: subnets=%s ENI IPs=%s",
                            ep_name, sm_subnets, list(_sm_eni_ips),
                        )
                    except Exception as ep_exc:
                        logger.warning("SageMaker endpoint %s ENI lookup failed: %s", ep_name, ep_exc)
        except Exception as sm_exc:
            logger.warning("SageMaker endpoint ENI discovery failed in %s: %s", region, sm_exc)

        # ENIs for Lambda and SageMaker (description-based fallback)
        try:
            paginator = ec2.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for eni in page["NetworkInterfaces"]:
                    desc = eni.get("Description", "")
                    priv_ip = eni.get("PrivateIpAddress")
                    if not priv_ip:
                        continue
                    tags = {t["Key"]: t["Value"] for t in eni.get("TagSet", [])}
                    if "AWS Lambda" in desc or "lambda" in desc.lower():
                        ip_map[priv_ip] = {
                            "resource_id": eni["NetworkInterfaceId"],
                            "resource_name": desc,
                            "resource_type": "lambda",
                            "az": eni.get("AvailabilityZone", ""),
                            "region": region,
                            "vpc_id": eni.get("VpcId", ""),
                            "is_gpu": False,
                            "tags": {},
                        }
                    elif (
                        "SageMaker" in desc
                        or "sagemaker" in desc.lower()
                        or "amazon sagemaker" in desc.lower()
                        or any("sagemaker" in k.lower() for k in tags)
                        or priv_ip in _sm_eni_ips  # already tagged via SM API above
                    ):
                        ip_map[priv_ip] = {
                            "resource_id": eni["NetworkInterfaceId"],
                            "resource_name": desc or f"SageMaker ENI {eni['NetworkInterfaceId']}",
                            "resource_type": "sagemaker",
                            "az": eni.get("AvailabilityZone", ""),
                            "region": region,
                            "vpc_id": eni.get("VpcId", ""),
                            "is_gpu": False,
                            "tags": {},
                        }
                    elif "Amazon FSx" in desc:
                        if priv_ip not in ip_map:
                            ip_map[priv_ip] = {
                                "resource_id": eni["NetworkInterfaceId"],
                                "resource_name": desc,
                                "resource_type": "fsx",
                                "az": eni.get("AvailabilityZone", ""),
                                "region": region,
                                "vpc_id": eni.get("VpcId", ""),
                                "is_gpu": False,
                                "tags": {},
                            }
                    elif "RDSNetworkInterface" in desc or desc.startswith("RDS"):
                        # RDS ENI — use as fallback if hostname resolution missed this IP
                        if priv_ip not in ip_map:
                            ip_map[priv_ip] = {
                                "resource_id": eni["NetworkInterfaceId"],
                                "resource_name": desc,
                                "resource_type": "rds",
                                "az": eni.get("AvailabilityZone", ""),
                                "region": region,
                                "vpc_id": eni.get("VpcId", ""),
                                "is_gpu": False,
                                "tags": {},
                            }
        except Exception as exc:
            logger.warning("Failed to describe ENIs in %s: %s", region, exc)

        # Subnet CIDR → AZ index for inferring AZ of unknown private IPs
        # (e.g., terminated EC2 instances that are no longer in describe_instances)
        try:
            subnets = ec2.describe_subnets()
            subnet_cidrs = [
                {
                    "cidr": sn["CidrBlock"],
                    "az": sn.get("AvailabilityZone", ""),
                    "vpc_id": sn.get("VpcId", ""),
                    "region": region,
                }
                for sn in subnets.get("Subnets", [])
            ]
            # Store under a sentinel key that can't be a valid IP address
            ip_map["__subnets__"] = subnet_cidrs  # type: ignore[assignment]
        except Exception as exc:
            logger.warning("Failed to describe subnets in %s: %s", region, exc)

        logger.info("IP map for %s (%d entries): %s", region, len(ip_map),
                    {k: f"{v.get('resource_type')}(gpu={v.get('is_gpu', False)})"
                     for k, v in ip_map.items() if k != "__subnets__"})
        return ip_map

    def get_s3_ip_ranges(self, region: str) -> list[str]:
        if region in self._s3_ranges_cache:
            return self._s3_ranges_cache[region]
        data = _fetch_ip_ranges()
        cidrs = [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("service") == "S3" and p.get("region") == region
        ]
        self._s3_ranges_cache[region] = cidrs
        return cidrs

    def get_all_s3_ip_ranges(self) -> list[dict]:
        """Return all S3 IP prefixes globally as [{cidr, region}] for cross-region detection."""
        data = _fetch_ip_ranges()
        return [
            {"cidr": p["ip_prefix"], "region": p.get("region", "")}
            for p in data.get("prefixes", [])
            if p.get("service") == "S3" and p.get("ip_prefix")
        ]

    def get_aws_api_ip_ranges(self, region: str) -> list[str]:
        if region in self._api_ranges_cache:
            return self._api_ranges_cache[region]
        data = _fetch_ip_ranges()
        s3_cidrs = set(self.get_s3_ip_ranges(region))
        cidrs = [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("service") == "AMAZON"
            and p.get("region") == region
            and p["ip_prefix"] not in s3_cidrs
        ]
        self._api_ranges_cache[region] = cidrs
        return cidrs

    def list_vpc_endpoints(self, region: str) -> list[dict]:
        try:
            ec2 = self._client("ec2", region)
            # Filter to only available endpoints; correct filter name is 'vpc-endpoint-state'
            resp = ec2.describe_vpc_endpoints(
                Filters=[{"Name": "vpc-endpoint-state", "Values": ["available"]}]
            )
            return [
                {
                    "service": ep.get("ServiceName", ""),
                    "vpc_id": ep.get("VpcId", ""),
                    "state": ep.get("State", ""),
                    "type": ep.get("VpcEndpointType", ""),
                }
                for ep in resp.get("VpcEndpoints", [])
            ]
        except Exception as exc:
            logger.warning("Failed to list VPC endpoints in %s: %s", region, exc)
            return []

    def list_nat_gateways(self, region: str) -> list[dict]:
        try:
            ec2 = self._client("ec2", region)
            resp = ec2.describe_nat_gateways(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )
            result = []
            for nat in resp.get("NatGateways", []):
                subnet = nat.get("SubnetId", "")
                # Get AZ from subnet
                az = ""
                try:
                    sn_resp = ec2.describe_subnets(SubnetIds=[subnet])
                    az = sn_resp["Subnets"][0].get("AvailabilityZone", "")
                except Exception:
                    pass
                addrs = nat.get("NatGatewayAddresses", [])
                pub_ips = [a.get("PublicIp") for a in addrs if a.get("PublicIp")]
                priv_ips = [a.get("PrivateIp") for a in addrs if a.get("PrivateIp")]
                result.append({
                    "nat_id": nat["NatGatewayId"],
                    "subnet_id": subnet,
                    "az": az,
                    "vpc_id": nat.get("VpcId", ""),
                    "public_ips": pub_ips,
                    "private_ips": priv_ips,
                })
            return result
        except Exception as exc:
            logger.warning("Failed to list NAT gateways in %s: %s", region, exc)
            return []
