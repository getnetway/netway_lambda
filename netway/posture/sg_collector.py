import logging
from typing import Any

logger = logging.getLogger(__name__)
SG_CAP = 1000


def collect_security_groups(ec2_client) -> list[dict[str, Any]]:
    paginator = ec2_client.get_paginator("describe_security_groups")
    groups: list[dict] = []

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            try:
                enis = ec2_client.describe_network_interfaces(
                    Filters=[{"Name": "group-id", "Values": [sg["GroupId"]]}]
                )["NetworkInterfaces"]
                attached = [e["NetworkInterfaceId"] for e in enis]
            except Exception as exc:
                logger.warning("ENI lookup failed for %s: %s", sg["GroupId"], exc)
                attached = []

            groups.append({
                "group_id":              sg["GroupId"],
                "group_name":            sg["GroupName"],
                "vpc_id":                sg.get("VpcId", ""),
                "description":           sg.get("Description", ""),
                "ip_permissions":        sg.get("IpPermissions", []),
                "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
                "network_interfaces":    attached,
            })
            if len(groups) >= SG_CAP:
                logger.warning("SG cap %d reached — truncating", SG_CAP)
                return groups

    return groups
