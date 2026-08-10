import logging
from typing import Any

logger = logging.getLogger(__name__)


def collect_vpc_posture(ec2_client, region: str) -> dict[str, Any]:
    return {
        "default_vpcs":               _default_vpcs(ec2_client),
        "vpcs_without_flow_logs":     _vpcs_without_flow_logs(ec2_client),
        "subnets_auto_assign_public": _subnets_auto_assign_public(ec2_client),
        "nacls":                      _nacls(ec2_client),
        "internet_gateways":          _internet_gateways(ec2_client),
    }


def _default_vpcs(ec2_client) -> list[str]:
    return [
        vpc["VpcId"]
        for page in ec2_client.get_paginator("describe_vpcs").paginate(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        )
        for vpc in page["Vpcs"]
    ]


def _vpcs_without_flow_logs(ec2_client) -> list[str]:
    all_ids = {
        vpc["VpcId"]
        for page in ec2_client.get_paginator("describe_vpcs").paginate()
        for vpc in page["Vpcs"]
    }
    with_logs = {
        fl["ResourceId"]
        for page in ec2_client.get_paginator("describe_flow_logs").paginate(
            Filters=[{"Name": "resource-type", "Values": ["VPC"]}]
        )
        for fl in page["FlowLogs"]
    }
    return list(all_ids - with_logs)


def _subnets_auto_assign_public(ec2_client) -> list[str]:
    return [
        s["SubnetId"]
        for page in ec2_client.get_paginator("describe_subnets").paginate()
        for s in page["Subnets"]
        if s.get("MapPublicIpOnLaunch")
    ]


def _nacls(ec2_client) -> list[dict]:
    nacls = []
    for page in ec2_client.get_paginator("describe_network_acls").paginate():
        for nacl in page["NetworkAcls"]:
            nacls.append({
                "nacl_id":    nacl["NetworkAclId"],
                "vpc_id":     nacl["VpcId"],
                "is_default": nacl["IsDefault"],
                "entries": [
                    {
                        "rule_number": e["RuleNumber"],
                        "protocol":    e["Protocol"],
                        "rule_action": e["RuleAction"],
                        "egress":      e["Egress"],
                        "cidr":        e.get("CidrBlock", e.get("Ipv6CidrBlock", "")),
                        "port_range":  e.get("PortRange"),
                    }
                    for e in nacl.get("Entries", [])
                ],
                "subnet_ids": [a["SubnetId"] for a in nacl.get("Associations", [])],
            })
    return nacls


def _internet_gateways(ec2_client) -> list[dict]:
    igws = []
    for page in ec2_client.get_paginator("describe_internet_gateways").paginate():
        for igw in page["InternetGateways"]:
            igws.append({
                "igw_id":        igw["InternetGatewayId"],
                "attached_vpcs": [
                    a["VpcId"] for a in igw.get("Attachments", [])
                    if a["State"] == "available"
                ],
            })
    return igws
