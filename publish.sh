#!/bin/bash
# publish.sh — build Lambda zip, upload zip + CFN template to public releases bucket.
# Run this from netway_lambda/ every time you cut a release.
# Customers pull directly from this bucket; no download step required.
set -e

PUBLIC_BUCKET="netway-public-releases"
REGION="ap-south-1"

echo "==> Blocking all public access on releases bucket..."
aws s3api put-public-access-block \
  --bucket "${PUBLIC_BUCKET}" \
  --region "${REGION}" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "==> Removing public-read policy statement (preserving per-customer grants)..."
CURRENT_POLICY=$(aws s3api get-bucket-policy --bucket "${PUBLIC_BUCKET}" --region "${REGION}" \
  --query Policy --output text 2>/dev/null || echo "{\"Version\":\"2012-10-17\",\"Statement\":[]}")
CLEANED_POLICY=$(echo "${CURRENT_POLICY}" | python3 -c "
import json, sys
policy = json.load(sys.stdin)
policy['Statement'] = [s for s in policy['Statement'] if s.get('Sid') != 'PublicRead']
print(json.dumps(policy))
")
aws s3api put-bucket-policy \
  --bucket "${PUBLIC_BUCKET}" \
  --region "${REGION}" \
  --policy "${CLEANED_POLICY}"

echo "==> Building Lambda package..."
RELEASES_BUCKET=${PUBLIC_BUCKET} REGION=${REGION} ./package.sh

echo "==> Uploading CloudFormation template..."
aws s3 cp cloudformation/netway-deploy.yml \
  "s3://${PUBLIC_BUCKET}/cloudformation/netway-deploy.yml" \
  --region "${REGION}"

echo ""
echo "Release published."
echo "  Lambda zip : https://${PUBLIC_BUCKET}.s3.${REGION}.amazonaws.com/lambda/latest.zip"
echo "  CFN template: https://${PUBLIC_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation/netway-deploy.yml"
echo ""
echo "Customers run:"
echo "  curl https://api.getnetway.dev/api/v1/install -H 'x-api-key: <key>'"
