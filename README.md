# Netway Agent

The open-source AWS Lambda agent that powers [Netway](https://getnetway.dev) — the VPC flow log analyser that finds and fixes hidden AWS network costs.

---

## What it does

Netway Agent runs inside **your own AWS account**. It:

1. Queries VPC flow logs stored in S3 using Athena
2. Enriches each flow with resource metadata — instance IDs, VPC IDs, AZ, NAT gateway IDs
3. Classifies traffic patterns (S3 via NAT, cross-AZ, cross-region, internet egress, etc.)
4. Aggregates millions of flow records into compact summaries (~99% size reduction)
5. Ships the aggregated summaries to the Netway API for server-side cost detection

Detection logic runs server-side. The agent only ships aggregated summaries — never raw flow logs, never credentials, never application data.

---

## What it does NOT send

| Data | Sent? |
|---|---|
| Raw VPC flow log lines | ❌ No |
| Application payload / packet contents | ❌ No |
| IAM credentials or secrets | ❌ No |
| EC2 user data or environment variables | ❌ No |
| Aggregated traffic summaries (bytes, flow counts, resource IDs) | ✅ Yes |

You can audit exactly what is sent by reading [`lambda_handler.py`](lambda_handler.py) — specifically the `aggregate_flows()` and `_post_flows_to_api()` functions.

---

## Architecture

```
Your AWS Account
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   VPC Flow Logs → S3 → Athena                               │
│                           │                                 │
│               netway-analyzer (this Lambda)                 │
│                           │                                 │
│   1. Query & enrich flows  │                                 │
│   2. Classify traffic      │                                 │
│   3. Aggregate summaries   │                                 │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │  HTTPS  (gzip + HMAC-SHA256)
                            ▼
                  api.getnetway.dev
                  14 cost detectors
                  Dashboard + alerts
```

---

## Deploy

The recommended way to deploy is via the CloudFormation template — it creates the Lambda, Athena workgroup, S3 bucket, IAM role, and EventBridge schedule in one step.

**Prerequisites:**
- AWS CLI configured (`aws sts get-caller-identity` works)
- A Netway API key — register free at [getnetway.dev](https://getnetway.dev)

```bash
aws cloudformation create-stack \
  --stack-name netway-v1 \
  --template-url https://netway-public-releases.s3.ap-south-1.amazonaws.com/cloudformation/netway-deploy.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=NetwayApiKey,ParameterValue=<your-api-key> \
    ParameterKey=NetwayApiUrl,ParameterValue=https://api.getnetway.dev \
    ParameterKey=VpcIds,ParameterValue=<vpc-id>

aws cloudformation wait stack-create-complete --stack-name netway-v1
```

The stack takes ~5 minutes. Once deployed, trigger a manual scan:

```bash
aws lambda invoke \
  --function-name netway-analyzer \
  --region <your-region> \
  --cli-read-timeout 900 \
  /tmp/result.json && cat /tmp/result.json
```

Then open [getnetway.dev/dashboard](https://getnetway.dev/dashboard) to see findings.

---

## IAM permissions

The Lambda requires the following permissions in your account:

| Permission | Purpose |
|---|---|
| `ec2:Describe*` | Enrich IPs with instance/VPC/subnet metadata |
| `s3:GetObject`, `s3:ListBucket` | Read VPC flow logs from S3 |
| `s3:PutObject` | Write Athena query results |
| `athena:StartQueryExecution`, `athena:GetQueryResults` | Query flow logs |
| `logs:CreateLogGroup`, `logs:PutLogEvents` | Lambda execution logs |

Full policy is in [`cloudformation/netway-deploy.yml`](cloudformation/netway-deploy.yml).

---

## Local development

```bash
# Clone
git clone https://github.com/getnetway/netway_lambda
cd netway_lambda

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — set NETWAY_API_KEY and FLOW_LOGS_S3_BUCKET

# Run locally (requires AWS credentials)
python -c "
import json
from lambda_handler import handler
result = handler({}, None)
print(json.dumps(result, indent=2))
"
```

---

## Build and package

Use `package.sh` to build the Lambda zip locally and upload it to your own S3 bucket:

```bash
RELEASES_BUCKET=my-bucket ./package.sh
```

This installs dependencies, strips Lambda-provided packages (boto3/botocore), zips the source, and uploads to `s3://my-bucket/lambda/latest.zip`.

---

## Project structure

```
netway_lambda/
  lambda_handler.py          Entry point — Athena setup, aggregation, API POST
  netway/
    config.py                Environment variable validation
    runner.py                Orchestration logic
    audit.py                 Audit trail helpers
    flow/
      query.py               Athena query builder and executor
      mapper.py              IP → resource enrichment (EC2, NAT GW, subnets)
      classifier.py          Traffic type classification (via_nat_to_s3, cross_az, etc.)
    providers/
      base.py                Abstract cloud provider interface
      aws.py                 AWS implementation (EC2, S3, VPC endpoints)
      gcp.py                 GCP implementation (VM, GCS)
  netway_common/
    models.py                Shared FlowRecord wire format
  cloudformation/
    netway-deploy.yml        CloudFormation template (Lambda + Athena + S3 + IAM)
```

---

## Contributing

Pull requests are welcome. By submitting a PR you agree to license your contribution under the Apache 2.0 license and assign copyright to Netlytix.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built and maintained by [Netlytix](https://getnetway.dev), Bengaluru, India.
