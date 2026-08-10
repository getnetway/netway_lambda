#!/bin/bash
# package.sh — build and upload the Lambda zip. Run from netway_lambda/
set -e

RELEASES_BUCKET="${RELEASES_BUCKET:-}"
REGION="${REGION:-ap-south-1}"
SKIP_UPLOAD="${SKIP_UPLOAD:-false}"   # set to "true" to build zip only, no S3 upload

if [ -z "$RELEASES_BUCKET" ] && [ "$SKIP_UPLOAD" != "true" ]; then
  echo "Error: RELEASES_BUCKET env var is required (or set SKIP_UPLOAD=true to build zip only)"
  echo "Usage: RELEASES_BUCKET=my-bucket ./package.sh"
  exit 1
fi

echo "Cleaning previous build..."
rm -rf build/ dist/ netway-lambda.zip
mkdir -p build/package

echo "Installing dependencies..."
python3.10 -m pip install \
  -r requirements.txt \
  -t build/package \
  --quiet \
  --platform manylinux2014_x86_64 \
  --only-binary=:all: \
  --python-version 3.11

# Remove boto3/botocore — the Lambda Python 3.11 runtime provides them.
# Bundling them would add ~30 MB unzipped and push us over the 250 MB limit.
echo "Stripping Lambda-provided packages..."
rm -rf build/package/boto3 build/package/botocore \
       build/package/boto3-*.dist-info build/package/botocore-*.dist-info

echo "Copying source..."
cp -r lambda_handler.py netway build/package/
# netway_common is the shared wire format — Lambda imports FlowRecord from it
cp -r ../netway_common build/package/

echo "Creating zip..."
cd build/package
zip -r ../../netway-lambda.zip . -q
cd ../..

echo "Size: $(du -sh netway-lambda.zip | cut -f1)"

if [ "$SKIP_UPLOAD" == "true" ]; then
  echo "Done. Zip built locally (SKIP_UPLOAD=true — skipping S3 upload)."
  exit 0
fi

echo "Uploading to S3..."
aws s3 cp netway-lambda.zip \
  "s3://${RELEASES_BUCKET}/lambda/latest.zip" \
  --region "${REGION}"

echo "Done. Lambda zip uploaded to s3://${RELEASES_BUCKET}/lambda/latest.zip"
