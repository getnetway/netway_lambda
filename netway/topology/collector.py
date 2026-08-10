import boto3
import logging
from typing import Any

logger = logging.getLogger(__name__)


class TopologyCollector:
    def __init__(
        self,
        session: boto3.Session,
        regions: list[str],
        account_id: str,
    ) -> None:
        self._session = session
        self._regions = regions
        self._account_id = account_id

    def collect_all(self) -> dict[str, Any]:
        from datetime import datetime, timezone
        result: dict[str, Any] = {
            "account_id": self._account_id,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "regions": {},
        }
        for region in self._regions:
            try:
                result["regions"][region] = self._collect_region(region)
            except Exception as exc:
                logger.warning("topology collection failed for region %s: %s", region, exc)
        return result

    def _collect_region(self, region: str) -> dict[str, Any]:
        ec2 = self._session.client("ec2", region_name=region)
        return {
            "vpcs":               self._collect_vpcs(ec2),
            "subnets":            self._collect_subnets(ec2),
            "peering_connections": self._collect_peerings(ec2),
            "transit_gateways":   self._collect_tgw(ec2),
            "tgw_attachments":    self._collect_tgw_attachments(ec2),
            "tgw_route_tables":   self._collect_tgw_route_tables(ec2),
            "vpc_route_tables":   self._collect_vpc_route_tables(ec2),
            "vpc_endpoints":      self._collect_vpc_endpoints(ec2),
            "internet_gateways":  self._collect_igw(ec2),
            "nat_gateways":       self._collect_nat_gateways(ec2),
            "instances":          self._collect_instances(ec2),
        }

    def _collect_vpcs(self, ec2) -> list[dict]:
        vpcs = []
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for v in page["Vpcs"]:
                vpcs.append({
                    "vpc_id":      v["VpcId"],
                    "cidr_blocks": [
                        c["CidrBlock"]
                        for c in v.get("CidrBlockAssociationSet", [])
                        if c["CidrBlockState"]["State"] == "associated"
                    ] or [v["CidrBlock"]],
                    "state":      v["State"],
                    "is_default": v.get("IsDefault", False),
                    "owner_id":   v.get("OwnerId", self._account_id),
                    "tags":       self._flatten_tags(v.get("Tags", [])),
                })
        return vpcs

    def _collect_subnets(self, ec2) -> list[dict]:
        subnets = []
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for s in page["Subnets"]:
                subnets.append({
                    "subnet_id":         s["SubnetId"],
                    "vpc_id":            s["VpcId"],
                    "cidr_block":        s["CidrBlock"],
                    "availability_zone": s["AvailabilityZone"],
                    "state":             s["State"],
                    "tags":              self._flatten_tags(s.get("Tags", [])),
                })
        return subnets

    def _collect_peerings(self, ec2) -> list[dict]:
        peerings = []
        paginator = ec2.get_paginator("describe_vpc_peering_connections")
        for page in paginator.paginate():
            for p in page["VpcPeeringConnections"]:
                status = p["Status"]["Code"]
                if status == "deleted":
                    continue
                peerings.append({
                    "peering_id":        p["VpcPeeringConnectionId"],
                    "status":            status,
                    "requester_vpc_id":  p["RequesterVpcInfo"]["VpcId"],
                    "requester_account": p["RequesterVpcInfo"]["OwnerId"],
                    "requester_cidr":    p["RequesterVpcInfo"].get("CidrBlock", ""),
                    "requester_region":  p["RequesterVpcInfo"].get("Region", ""),
                    "accepter_vpc_id":   p["AccepterVpcInfo"]["VpcId"],
                    "accepter_account":  p["AccepterVpcInfo"]["OwnerId"],
                    "accepter_cidr":     p["AccepterVpcInfo"].get("CidrBlock", ""),
                    "accepter_region":   p["AccepterVpcInfo"].get("Region", ""),
                    "tags":              self._flatten_tags(p.get("Tags", [])),
                })
        return peerings

    def _collect_tgw(self, ec2) -> list[dict]:
        tgws = []
        paginator = ec2.get_paginator("describe_transit_gateways")
        for page in paginator.paginate():
            for t in page["TransitGateways"]:
                if t["State"] == "deleted":
                    continue
                tgws.append({
                    "tgw_id":    t["TransitGatewayId"],
                    "owner_id":  t["OwnerId"],
                    "state":     t["State"],
                    "tags":      self._flatten_tags(t.get("Tags", [])),
                })
        return tgws

    def _collect_tgw_attachments(self, ec2) -> list[dict]:
        attachments = []
        paginator = ec2.get_paginator("describe_transit_gateway_attachments")
        for page in paginator.paginate():
            for a in page["TransitGatewayAttachments"]:
                if a["State"] in ("deleted", "deleting"):
                    continue
                attachments.append({
                    "attachment_id":          a["TransitGatewayAttachmentId"],
                    "tgw_id":                 a["TransitGatewayId"],
                    "resource_type":          a["ResourceType"],
                    "resource_id":            a["ResourceId"],
                    "resource_owner_account": a.get("ResourceOwnerId", ""),
                    "state":                  a["State"],
                    "association_route_table_id": (
                        a.get("Association", {}).get("TransitGatewayRouteTableId", "")
                    ),
                    "tags": self._flatten_tags(a.get("Tags", [])),
                })
        return attachments

    def _collect_tgw_route_tables(self, ec2) -> list[dict]:
        tables = []
        paginator = ec2.get_paginator("describe_transit_gateway_route_tables")
        for page in paginator.paginate():
            for rt in page["TransitGatewayRouteTables"]:
                if rt["State"] == "deleted":
                    continue
                routes = self._get_tgw_routes(ec2, rt["TransitGatewayRouteTableId"])
                propagations = self._get_tgw_propagations(ec2, rt["TransitGatewayRouteTableId"])
                tables.append({
                    "route_table_id": rt["TransitGatewayRouteTableId"],
                    "tgw_id":         rt["TransitGatewayId"],
                    "state":          rt["State"],
                    "routes":         routes,
                    "propagations":   propagations,
                })
        return tables

    def _get_tgw_routes(self, ec2, route_table_id: str) -> list[dict]:
        resp = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=route_table_id,
            Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
        )
        return [
            {
                "destination_cidr": r.get("DestinationCidrBlock", ""),
                "state":            r["State"],
                "type":             r["Type"],
                "attachment_id":    (
                    r["TransitGatewayAttachments"][0]["TransitGatewayAttachmentId"]
                    if r.get("TransitGatewayAttachments") else ""
                ),
            }
            for r in resp.get("Routes", [])
        ]

    def _get_tgw_propagations(self, ec2, route_table_id: str) -> list[dict]:
        paginator = ec2.get_paginator("get_transit_gateway_route_table_propagations")
        propagations = []
        for page in paginator.paginate(TransitGatewayRouteTableId=route_table_id):
            for p in page["TransitGatewayRouteTablePropagations"]:
                propagations.append({
                    "attachment_id": p["TransitGatewayAttachmentId"],
                    "resource_id":   p["ResourceId"],
                    "resource_type": p["ResourceType"],
                    "state":         p["State"],
                })
        return propagations

    def _collect_vpc_route_tables(self, ec2) -> list[dict]:
        tables = []
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page["RouteTables"]:
                tables.append({
                    "route_table_id": rt["RouteTableId"],
                    "vpc_id":         rt["VpcId"],
                    "routes": [
                        {
                            "destination_cidr": r.get("DestinationCidrBlock", ""),
                            "target_type":      self._route_target_type(r),
                            "target_id":        self._route_target_id(r),
                            "state":            r.get("State", "active"),
                        }
                        for r in rt["Routes"]
                        if r.get("State") != "blackhole"
                    ],
                    "subnet_associations": [
                        a.get("SubnetId", "") for a in rt.get("Associations", [])
                        if not a.get("Main", False) and a.get("SubnetId")
                    ],
                    "main": any(a.get("Main", False) for a in rt.get("Associations", [])),
                })
        return tables

    @staticmethod
    def _route_target_type(route: dict) -> str:
        for key, label in [
            ("GatewayId", "igw" if route.get("GatewayId", "").startswith("igw-") else "vgw"),
            ("TransitGatewayId", "transit-gateway"),
            ("VpcPeeringConnectionId", "vpc-peering"),
            ("NatGatewayId", "nat-gateway"),
            ("VpcEndpointId", "vpc-endpoint"),
            ("NetworkInterfaceId", "network-interface"),
        ]:
            if key in route and route[key]:
                if key == "GatewayId":
                    return "igw" if route[key].startswith("igw-") else "vgw"
                return label
        return "local"

    @staticmethod
    def _route_target_id(route: dict) -> str:
        for key in [
            "GatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
            "NatGatewayId", "VpcEndpointId", "NetworkInterfaceId",
        ]:
            if route.get(key):
                return route[key]
        return "local"

    def _collect_vpc_endpoints(self, ec2) -> list[dict]:
        endpoints = []
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate():
            for e in page["VpcEndpoints"]:
                if e["State"] in ("deleted", "deleting"):
                    continue
                endpoints.append({
                    "endpoint_id":   e["VpcEndpointId"],
                    "vpc_id":        e["VpcId"],
                    "service_name":  e["ServiceName"],
                    "endpoint_type": e["VpcEndpointType"],
                    "state":         e["State"],
                    "route_table_ids": e.get("RouteTableIds", []),
                })
        return endpoints

    def _collect_igw(self, ec2) -> list[dict]:
        igws = []
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page["InternetGateways"]:
                attachments = igw.get("Attachments", [])
                igws.append({
                    "igw_id":     igw["InternetGatewayId"],
                    "vpc_id":     attachments[0]["VpcId"] if attachments else None,
                    "state":      attachments[0]["State"] if attachments else "detached",
                    "tags":       self._flatten_tags(igw.get("Tags", [])),
                })
        return igws

    def _collect_nat_gateways(self, ec2) -> list[dict]:
        nats = []
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate(
            Filter=[{"Name": "state", "Values": ["available", "pending"]}]
        ):
            for n in page["NatGateways"]:
                nats.append({
                    "nat_id":       n["NatGatewayId"],
                    "vpc_id":       n["VpcId"],
                    "subnet_id":    n["SubnetId"],
                    "state":        n["State"],
                    "connectivity": n.get("ConnectivityType", "public"),
                    "public_ip":    (
                        n["NatGatewayAddresses"][0].get("PublicIp", "")
                        if n.get("NatGatewayAddresses") else ""
                    ),
                    "tags": self._flatten_tags(n.get("Tags", [])),
                })
        return nats

    def _collect_instances(self, ec2) -> list[dict]:
        """Collect running/stopped EC2 instances (exclude terminated)."""
        instances = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "stopping", "pending"]}]
        ):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    tags = self._flatten_tags(inst.get("Tags", []))
                    instances.append({
                        "instance_id":   inst["InstanceId"],
                        "vpc_id":        inst.get("VpcId", ""),
                        "subnet_id":     inst.get("SubnetId", ""),
                        "instance_type": inst["InstanceType"],
                        "state":         inst["State"]["Name"],
                        "name":          tags.get("Name", ""),
                        "private_ip":    inst.get("PrivateIpAddress", ""),
                        "tags":          tags,
                    })
        return instances

    @staticmethod
    def _flatten_tags(tags: list[dict]) -> dict[str, str]:
        return {t["Key"]: t["Value"] for t in tags}
