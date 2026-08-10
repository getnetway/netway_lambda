# Netway

VPC observability for AWS — network cost leak detection, compliance gap identification, VPC network visibility, and topology change history. One CloudFormation stack, one daily scan.

**This repo** is the open-source Lambda agent that runs inside your AWS account. Detection logic, dashboard, and alerts run on hosted infrastructure at [basavytix.com](https://basavytix.com).

14-day free trial · $299/month after · [Get started](https://basavytix.com)

---

## The problem

AWS makes it easy to start but hard to understand what's actually running and what it costs:

- **NAT gateway bills are opaque.** $800/month shows up as a line item with no breakdown by workload or traffic type. S3 traffic routed through NAT instead of a VPC endpoint can silently cost thousands per month — and you won't see it without querying flow logs yourself.
- **Cross-AZ transfer is invisible.** $0.01/GB × millions of internal service calls adds up fast. Nothing in the AWS console tells you which services are responsible.
- **Security posture has no free central view.** Finding every security group with `0.0.0.0/0` ingress, every SSM parameter storing a secret unencrypted, every Lambda with a plaintext API key in its environment — this requires AWS Config or Security Hub, which cost more than the problems they find.
- **Network topology changes leave no trail** unless you've pre-configured Config rules or CloudTrail queries. A new internet gateway attachment or a peering connection added last Tuesday? No record unless you were looking.

---

## What Netway does

### Network cost leak detection

The agent queries your VPC flow logs in S3 via Athena, enriches each flow with resource metadata, and classifies traffic by type. The hosted API runs 14 detection patterns against the aggregated summaries.

| Traffic type | Typical cost |
|---|---|
| S3 traffic routed via NAT gateway | Avoidable — VPC endpoint is free |
| Cross-AZ transfers | $0.01/GB |
| Cross-region traffic | $0.02/GB |
| Internet egress | $0.09/GB |
| Redundant/duplicate transfer paths | Varies |

Findings include the estimated monthly cost and the specific resources responsible (instance IDs, VPC IDs, NAT gateway IDs).

### Compliance gap identification

Four posture collectors snapshot your configuration on every scan. The hosted API runs checks against each snapshot and tracks findings across scans — flagging new issues and resolving old ones when config is fixed.

| Collector | What it checks |
|---|---|
| **SG** | Security groups with unrestricted ingress (`0.0.0.0/0` / `::/0`) on sensitive ports (22, 3389, 5432, etc.) |
| **SSM** | Parameters with secret-like names (`password`, `secret`, `key`, `token`) stored as `String` instead of `SecureString` |
| **Lambda** | Functions with environment variable **keys** that look like secrets — catches plaintext credentials in Lambda config |
| **VPC** | Default VPCs still active, VPCs without flow log coverage |

The agent collects only the **key names** of environment variables and SSM parameters. Values never leave your account.

### VPC network visibility

Every scan snapshots your VPC topology — subnets, internet gateways, NAT gateways, VPC endpoints, peering connections, routing tables, and flow log coverage across all in-scope VPCs. The dashboard gives you a current-state map of your network without needing AWS Config.

### Topology change history

Each scan diffs the current snapshot against the previous one. Changes are stored with severity:

| Severity | Example |
|---|---|
| `critical` | Internet gateway attached to a previously internal VPC |
| `high` | New VPC peering connection, inbound security group rule added |
| `medium` | Subnet route table changed, NAT gateway added |
| `low` | Tag update, description change |

No Config rules or CloudTrail queries needed — you get a searchable change log from the first scan.

---

## How it works

```
Your AWS Account
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │      netway-analyzer Lambda (this repo, open source)    │   │
│  │                                                         │   │
│  │  Cost pipeline              Posture pipeline            │   │
│  │  ─────────────              ─────────────────           │   │
│  │  VPC Flow Logs → S3         sg_collector.py             │   │
│  │         │                   ssm_collector.py            │   │
│  │      Athena                 lambda_collector.py         │   │
│  │         │                   vpc_collector.py            │   │
│  │  classify + aggregate       topology/collector.py       │   │
│  │         │                         │                     │   │
│  │  flow summaries      posture snapshot + topology diffs  │   │
│  │         └──────────┬───────────────┘                    │   │
│  └────────────────────┼────────────────────────────────────┘   │
│                       │  HTTPS  (gzip + HMAC-SHA256)           │
└───────────────────────┼─────────────────────────────────────────┘
                        ▼
                api.basavytix.com  (hosted, not open source)
                ┌──────────────────────────────────────┐
                │  14 cost detection patterns          │
                │  Posture checks + finding lifecycle  │
                │  Topology diff engine                │
                │  Dashboard, email + Slack alerts     │
                └──────────────────────────────────────┘
```

The Lambda runs on a daily EventBridge schedule. You can also invoke it manually at any time.

---

## Why open source the agent

The agent is the part that runs inside your account and touches your data. Open sourcing it means you can audit exactly what is collected and what is sent before deploying anything. The detection logic and dashboard run on our infrastructure — that part is not open source.

### What the agent sends

| Data | Sent? |
|---|---|
| Raw VPC flow log lines | ❌ No |
| Application payload or packet contents | ❌ No |
| IAM credentials or secrets | ❌ No |
| SSM parameter values | ❌ No — only name, type, and whether it looks like a secret |
| Lambda environment variable values | ❌ No — only key names |
| EC2 user data | ❌ No |
| Aggregated traffic summaries (bytes, flow counts, resource IDs) | ✅ Yes |
| VPC topology snapshot (resource IDs, CIDR blocks, route table associations) | ✅ Yes |
| Security group rule metadata (port ranges, protocol, CIDR — not traffic) | ✅ Yes |

The entry point is [`lambda_handler.py`](lambda_handler.py). The posture collectors are in [`netway/posture/`](netway/posture/). The topology collector is in [`netway/topology/collector.py`](netway/topology/collector.py).

---

## Pricing

| | |
|---|---|
| Free trial | 14 days, full access |
| Subscription | $299/month |
| Accounts | Unlimited AWS accounts per subscription |
| Regions | Unlimited regions |

[Start free trial →](https://basavytix.com)

---

## Deploy

**Prerequisites:** AWS CLI configured, Netway API key from [basavytix.com](https://basavytix.com)

```bash
# 1. Deploy — creates Lambda, Athena workgroup, S3 bucket, IAM role, EventBridge schedule (~3 min)
./netway-deploy.sh deploy --api-key <your-api-key> --regions us-east-1

# Deploy to multiple regions at once
./netway-deploy.sh deploy --api-key <your-api-key> --regions us-east-1,eu-west-1,ap-south-1

# 2. Trigger first scan and wait for results
./netway-deploy.sh scan --wait

# 3. Check stack status across all deployed regions
./netway-deploy.sh status
```

Your API key and regions are saved to `~/.netway/` after the first deploy — subsequent commands don't need them repeated.

**All commands:**

```
./netway-deploy.sh deploy   --api-key <key> --regions <r1,r2,...> [--vpcs <ids|ALL>]
./netway-deploy.sh scan     [--wait]
./netway-deploy.sh status
./netway-deploy.sh update   [--yes]      # re-deploy with local template changes
./netway-deploy.sh upgrade  [--yes]      # pull latest template from S3 and update
./netway-deploy.sh delete   [--yes]
./netway-deploy.sh outputs
```

---

## IAM permissions

| Permission | Purpose |
|---|---|
| `ec2:Describe*` | Enrich flows with instance/VPC/subnet metadata; collect topology |
| `ec2:DescribeSecurityGroups` | SG posture collector |
| `ec2:DescribeNetworkAcls` | Network ACL posture check |
| `ssm:DescribeParameters` | SSM posture collector (key names only) |
| `lambda:GetFunctionConfiguration` | Lambda env var key collector |
| `lambda:ListFunctions` | Enumerate Lambda functions in scope |
| `s3:GetObject`, `s3:ListBucket` | Read VPC flow logs |
| `s3:PutObject` | Write Athena query results |
| `athena:StartQueryExecution`, `athena:GetQueryResults` | Query flow logs |
| `logs:CreateLogGroup`, `logs:PutLogEvents` | Lambda execution logs |

Full policy in [`cloudformation/netway-deploy.yml`](cloudformation/netway-deploy.yml).

---

## Project structure

```
netway_lambda/
  lambda_handler.py          Entry point
  netway/
    runner.py                Pipeline orchestration
    flow/
      query.py               Athena query builder and executor
      mapper.py              IP → resource enrichment (EC2, NAT GW, subnets)
      classifier.py          Traffic type classification
    posture/
      sg_collector.py        Security group rule snapshot
      ssm_collector.py       SSM parameter metadata snapshot
      lambda_collector.py    Lambda env var key snapshot
      vpc_collector.py       VPC / flow log coverage snapshot
    topology/
      collector.py           VPC topology snapshot + change diff
    providers/
      aws.py                 AWS SDK wrappers
  netway_common/
    models.py                Shared wire format
  cloudformation/
    netway-deploy.yml        CloudFormation template
```

---

## Local development

```bash
git clone https://github.com/basavytix/netway_lambda
cd netway_lambda
pip install -r requirements.txt
cp .env.example .env
# Set NETWAY_API_KEY, NETWAY_API_URL, FLOW_LOGS_S3_BUCKET

python -c "import json; from lambda_handler import handler; print(json.dumps(handler({}, None), indent=2))"
```

Requires AWS credentials with the permissions listed above.

## Build and package

```bash
RELEASES_BUCKET=my-bucket ./package.sh
```

---

## Contributing

Pull requests welcome. By submitting a PR you agree to license your contribution under the Apache 2.0 license and assign copyright to Basavytix.

## License

Apache 2.0 — see [LICENSE](LICENSE).

The agent (this repo) is Apache 2.0. The hosted API, dashboard, and detection logic are proprietary.

Built by [Basavytix](https://basavytix.com), Bengaluru, India.
