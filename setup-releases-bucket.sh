#!/bin/bash
# setup-releases-bucket.sh — one-time bucket hardening for netway-public-releases.
#
# Run this ONCE when the bucket is first created, or to restore correct settings
# after an accidental lockout.  Do NOT run this on every publish.
#
# What this does:
#   1. Allows public bucket *policies* (needed so customers can GET the Lambda zip)
#      but blocks public ACLs (no object-level public ACL grants allowed)
#   2. Sets a bucket policy that:
#      - Allows public s3:GetObject on the known customer-facing paths
#      - Denies all write / policy-change actions to anyone except dgunjetti-dev
#
# Usage:
#   ./setup-releases-bucket.sh
set -euo pipefail

BUCKET="netway-public-releases"
REGION="ap-south-1"
ACCOUNT_ID="612962922800"
ADMIN_USER="dgunjetti-dev"

echo "==> Configuring Block Public Access (allow public policy, block ACLs)..."
aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --region "${REGION}" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false"

echo "==> Applying bucket policy..."
aws s3api put-bucket-policy \
  --bucket "${BUCKET}" \
  --region "${REGION}" \
  --policy "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadLambdaZip",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::${BUCKET}/lambda/latest.zip",
        "arn:aws:s3:::${BUCKET}/cloudformation/netway-deploy.yml"
      ]
    },
    {
      "Sid": "PublicReadDemo",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::${BUCKET}/demo/run_demo.sh",
        "arn:aws:s3:::${BUCKET}/demo/infra/demo-vpc.yml"
      ]
    },
    {
      "Sid": "NetwayCustomerLambdaRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET}/lambda/*"
    },
    {
      "Sid": "DenyWritesToNonAdmin",
      "Effect": "Deny",
      "NotPrincipal": {
        "AWS": [
          "arn:aws:iam::${ACCOUNT_ID}:user/${ADMIN_USER}",
          "arn:aws:iam::${ACCOUNT_ID}:root"
        ]
      },
      "Action": [
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock"
      ],
      "Resource": [
        "arn:aws:s3:::${BUCKET}",
        "arn:aws:s3:::${BUCKET}/*"
      ]
    }
  ]
}
EOF
)"

echo ""
echo "Bucket ${BUCKET} configured:"
echo "  Public read : lambda/latest.zip, cloudformation/netway-deploy.yml, demo/*"
echo "  Write access: arn:aws:iam::${ACCOUNT_ID}:user/${ADMIN_USER} only"
echo ""
echo "Run ./publish.sh to cut a release."
