#!/usr/bin/env bash
# netway-deploy.sh — multi-region deploy/status/update/scan/delete lifecycle tool
# Requires: bash 4+, aws CLI configured, curl
# Usage: ./netway-deploy.sh <command> [options]

set -euo pipefail

# ── Bash version guard (macOS ships bash 3.2) ─────────────────────────────────
if (( BASH_VERSINFO[0] < 4 )); then
  echo "ERROR: bash 4+ required (you have $BASH_VERSION)." >&2
  echo "  macOS: brew install bash && exec /usr/local/bin/bash $0 $*" >&2
  exit 1
fi

# ── Constants ─────────────────────────────────────────────────────────────────
RELEASES_URL="https://netway-public-releases.s3.ap-south-1.amazonaws.com"
TEMPLATE_URL="${RELEASES_URL}/netway-deploy.yml"
API_URL="https://api.basavytix.com/netway"
STATE_DIR="$HOME/.netway"
DEFAULT_STACK="netway-v1"
LAMBDA_NAME="netway-analyzer"
DEFAULT_PARALLEL=5
SCAN_WAIT_TIMEOUT=1200   # 20 minutes

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'
BOLD='\033[1m'
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*" >&2; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
info() { echo -e "  $*"; }

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
Usage:
  netway-deploy.sh deploy   --api-key <key> --regions <r1,r2,...> [--vpcs <ids|ALL>] [--stack-name <name>] [--api-url <url>]
  netway-deploy.sh status   [--regions <r1,r2,...>] [--stack-name <name>] [--json]
  netway-deploy.sh outputs  [--regions <r1,r2,...>] [--stack-name <name>] [--json]
  netway-deploy.sh update   [--regions <r1,r2,...>] [--stack-name <name>] [--yes]
  netway-deploy.sh upgrade  [--regions <r1,r2,...>] [--stack-name <name>] [--yes]
  netway-deploy.sh scan     [--regions <r1,r2,...>] [--stack-name <name>] [--wait]
  netway-deploy.sh delete   [--regions <r1,r2,...>] [--stack-name <name>] [--yes]

Options:
  --api-key     Netway API key (required on first deploy; saved to ~/.netway/ afterwards)
  --api-url     Netway API base URL (default: https://api.basavytix.com/netway)
  --regions     Comma-separated AWS regions, e.g. us-east-1,eu-west-1,ap-south-1
                Omit to use saved regions; new regions are merged with saved ones
  --vpcs        VPC IDs to monitor, comma-separated, or ALL (default: ALL)
  --stack-name  CloudFormation stack name (default: netway-v1)
  --template    Path to netway-deploy.yml (update only; upgrade always downloads from S3)
  --parallel    Max parallel deployments (default: 5)
  --wait        [scan] Wait for results and print per-region findings count
  --yes         Skip confirmation prompts
  --json        [status/outputs] Emit machine-readable JSON

EOF
  exit "${1:-0}"
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
CMD="${1:-}"; shift || true
[[ -z "$CMD" ]] && usage 1

API_KEY="" REGIONS="" VPCS="ALL" STACK_NAME="$DEFAULT_STACK"
TEMPLATE="" PARALLEL=$DEFAULT_PARALLEL WAIT=0 YES=0 JSON=0
PROFILES=()   # --profile values (multi-account scan)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-key)    API_KEY="$2";              shift 2 ;;
    --api-url)    API_URL="$2";              shift 2 ;;
    --regions)    shift; REGIONS=""
                  while [[ $# -gt 0 && "$1" != --* ]]; do
                    REGIONS+="${1//[, ]/,}"; shift
                  done
                  REGIONS="${REGIONS%,}" ;;
    --vpcs)       VPCS="$2";                 shift 2 ;;
    --stack-name) STACK_NAME="$2";           shift 2 ;;
    --template)   TEMPLATE="$2";            shift 2 ;;
    --parallel)   PARALLEL="$2";            shift 2 ;;
    --wait)       WAIT=1;                    shift   ;;
    --yes)        YES=1;                     shift   ;;
    --json)       JSON=1;                    shift   ;;
    --profile)    PROFILES+=("$2");          shift 2 ;;
    -h|--help)    usage ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

# ── State file helpers ─────────────────────────────────────────────────────────
# One state file per AWS profile: ~/.netway/state.default or ~/.netway/state.<profile>
# Regions are accumulated (union) — never overwritten — so deploying to a new region
# adds it to the saved list rather than replacing it.

_state_file() {
  local profile="${1:-${PROFILES[0]:-}}"
  local key="${profile:-default}"
  echo "$STATE_DIR/state.${key}"
}

_load_state() {
  local sf; sf=$(_state_file)
  # Fall back to legacy single-file if per-profile file doesn't exist yet
  local legacy="$STATE_DIR/regions"
  [[ ! -f "$sf" && -f "$legacy" ]] && sf="$legacy"
  if [[ -f "$sf" ]]; then
    # shellcheck disable=SC1090
    source "$sf"
    # Load API key from state only if not supplied on CLI
    [[ -z "$API_KEY" ]] && API_KEY="${SAVED_API_KEY:-}"
    # Load regions from state only if not supplied on CLI
    [[ -z "$REGIONS" ]] && REGIONS="${SAVED_REGIONS:-${REGIONS:-}}"
    STACK_NAME="${STACK_NAME:-$DEFAULT_STACK}"
  fi
}

_save_state() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  local sf; sf=$(_state_file)

  # Merge CLI regions with any previously saved regions for this profile
  local merged="$REGIONS"
  if [[ -f "$sf" ]]; then
    # shellcheck disable=SC1090
    local prev_regions; prev_regions=$(source "$sf" 2>/dev/null; echo "${SAVED_REGIONS:-}")
    if [[ -n "$prev_regions" ]]; then
      # Union: combine both lists, deduplicate, sort
      merged=$(echo "${prev_regions},${REGIONS}" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
  fi

  # Use CLI api key or fall back to whatever was already saved
  local save_key="$API_KEY"
  if [[ -z "$save_key" && -f "$sf" ]]; then
    save_key=$(source "$sf" 2>/dev/null; echo "${SAVED_API_KEY:-}")
  fi

  cat > "$sf" <<EOF
SAVED_API_KEY=$save_key
SAVED_REGIONS=$merged
STACK_NAME=$STACK_NAME
VPCS=$VPCS
EOF
  chmod 600 "$sf"
  # Update REGIONS so the rest of the current run sees the merged set
  REGIONS="$merged"
}

# ── Region list ────────────────────────────────────────────────────────────────
_require_regions() {
  _load_state
  if [[ -z "$REGIONS" ]]; then
    echo "ERROR: --regions required (or run 'deploy' first to save them)." >&2
    exit 1
  fi
}

_region_list() {
  IFS=',' read -ra REGION_ARR <<< "$REGIONS"
  echo "${REGION_ARR[@]}"
}

# ── AWS account ID ────────────────────────────────────────────────────────────
_aws_account_id() {
  local profile="${1:-}"
  local flags=()
  [[ -n "$profile" ]] && flags=(--profile "$profile")
  aws "${flags[@]}" sts get-caller-identity --query Account --output text 2>/dev/null || {
    echo "ERROR: aws CLI not configured or no credentials." >&2
    exit 1
  }
}

# ── Template download ─────────────────────────────────────────────────────────
_ensure_template() {
  if [[ -n "$TEMPLATE" ]]; then
    [[ -f "$TEMPLATE" ]] || { echo "ERROR: template not found: $TEMPLATE" >&2; exit 1; }
    return
  fi
  # 1. Same directory as this script (works in the repo and when downloaded alongside it)
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/netway-deploy.yml" ]]; then
    TEMPLATE="$script_dir/netway-deploy.yml"
    return
  fi
  # 2. Repo layout: netway_lambda/cloudformation/netway-deploy.yml
  if [[ -f "$script_dir/netway_lambda/cloudformation/netway-deploy.yml" ]]; then
    TEMPLATE="$script_dir/netway_lambda/cloudformation/netway-deploy.yml"
    return
  fi
  # 3. Current directory
  if [[ -f "./netway-deploy.yml" ]]; then
    TEMPLATE="./netway-deploy.yml"
    return
  fi
  # 4. Download from S3 releases bucket
  TEMPLATE="./netway-deploy.yml"
  echo -e "\nDownloading latest netway-deploy.yml..."
  if ! curl -fsSL "$TEMPLATE_URL" -o "$TEMPLATE" 2>/dev/null; then
    echo "ERROR: Could not download template from $TEMPLATE_URL" >&2
    echo "  Pass --template /path/to/netway-deploy.yml to use a local copy." >&2
    exit 1
  fi
  echo -e "Downloaded to $TEMPLATE\n"
}

_latest_template_version() {
  # Version is embedded as a comment "# Version: X.Y.Z" in the template
  grep -m1 "^# Version:" "$TEMPLATE" 2>/dev/null | awk '{print $3}' || echo "unknown"
}

# ── Parallel runner ────────────────────────────────────────────────────────────
# Runs _worker_fn <region> for each region in parallel (up to $PARALLEL at once).
# Output per region is buffered and printed atomically on completion.
# Returns 0 only if all regions succeeded.
_run_parallel() {
  local worker_fn="$1"
  local -a regions=("${@:2}")
  local tmpdir
  tmpdir=$(mktemp -d)
  local -a pids=()
  local -a out_files=()
  local slot=0

  for region in "${regions[@]}"; do
    local out="$tmpdir/$region"
    out_files+=("$out")
    (
      # Capture all stdout/stderr to buffer
      "$worker_fn" "$region" > "$out" 2>&1
      echo $? > "$out.rc"
    ) &
    pids+=($!)
    (( ++slot % PARALLEL == 0 )) && wait "${pids[@]}" 2>/dev/null || true
  done

  # Wait for any remaining
  wait "${pids[@]}" 2>/dev/null || true

  local all_ok=0
  for i in "${!regions[@]}"; do
    local region="${regions[$i]}"
    local out="${out_files[$i]}"
    local rc=0
    [[ -f "$out.rc" ]] && rc=$(cat "$out.rc")
    cat "$out"
    (( rc != 0 )) && all_ok=1
  done
  rm -rf "$tmpdir"
  return $all_ok
}

# ── Grant releases access via API ─────────────────────────────────────────────
_grant_releases_access() {
  local region="$1"
  local profile="${2:-}"
  local account_id
  account_id=$(_aws_account_id "$profile")
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/v1/grant-releases-access" \
    -H "X-Api-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"aws_account_id\": \"$account_id\", \"region\": \"$region\"}")
  if [[ "$resp" != "200" ]]; then
    echo "  [${region}]  WARN: grant-releases-access returned HTTP $resp (continuing)"
  fi
}

# ── Stack output helpers ───────────────────────────────────────────────────────
# Returns a single output value from a CFN stack, or "" if not found.
_stack_output() {
  local region="$1" stack="$2" key="$3"
  local profile="${4:-}"
  local flags=()
  [[ -n "$profile" ]] && flags=(--profile "$profile")
  aws "${flags[@]}" cloudformation describe-stacks \
    --region "$region" --stack-name "$stack" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue" \
    --output text 2>/dev/null || true
}

# Returns the Lambda function name for a given stack — first tries stack outputs,
# falls back to the hardcoded default so single-stack users are unaffected.
_lambda_name_for_stack() {
  local region="$1" stack="$2" profile="${3:-}"
  local name
  name=$(_stack_output "$region" "$stack" "LambdaFunctionName" "$profile")
  echo "${name:-$LAMBDA_NAME}"
}

# ── Extract the first failure reason from CloudFormation stack events ──────────
_cfn_failure_reason() {
  local region="$1" stack="$2" profile="${3:-}"
  local flags=(); [[ -n "$profile" ]] && flags=(--profile "$profile")
  aws "${flags[@]}" cloudformation describe-stack-events \
    --region "$region" --stack-name "$stack" \
    --query "StackEvents[?contains('CREATE_FAILED UPDATE_FAILED', ResourceStatus)].{R:LogicalResourceId,M:ResourceStatusReason}" \
    --output text 2>/dev/null | grep -v "^None" | head -3
}

# ── Purge stacks stuck in ROLLBACK_COMPLETE or DELETE_FAILED ──────────────────
_cfn_purge_if_rolled_back() {
  local region="$1" stack="$2" profile="${3:-}"
  local flags=()
  [[ -n "$profile" ]] && flags=(--profile "$profile")

  local status
  status=$(aws "${flags[@]}" cloudformation describe-stacks \
    --region "$region" --stack-name "$stack" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "DOES_NOT_EXIST")

  case "$status" in
    ROLLBACK_COMPLETE|DELETE_FAILED)
      warn "[${region}]  Stack is in ${status} — deleting before fresh deploy..."
      aws "${flags[@]}" cloudformation delete-stack \
        --region "$region" --stack-name "$stack"
      aws "${flags[@]}" cloudformation wait stack-delete-complete \
        --region "$region" --stack-name "$stack" 2>/dev/null || true
      ok "[${region}]  Stale stack removed — proceeding with fresh deploy."
      ;;
  esac
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: deploy
# ──────────────────────────────────────────────────────────────────────────────
cmd_deploy() {
  [[ -z "$API_KEY" ]] && { echo "ERROR: --api-key required for deploy." >&2; exit 1; }
  [[ -z "$REGIONS" ]] && { echo "ERROR: --regions required for deploy." >&2; exit 1; }

  _ensure_template

  # For deploy, use the first --profile if supplied (deploy targets one account at a time)
  local deploy_profile="${PROFILES[0]:-}"
  local AWS_PROFILE_FLAG=()
  [[ -n "$deploy_profile" ]] && AWS_PROFILE_FLAG=(--profile "$deploy_profile")

  local -a regions
  read -ra regions <<< "$(_region_list)"
  local n="${#regions[@]}"

  echo -e "\n${BOLD}Deploying Netway to $n region(s) (parallel)...${RESET}\n"
  [[ -n "$deploy_profile" ]] && echo "  Using AWS profile: ${deploy_profile}"

  _worker_deploy() {
    local region="$1"
    local t0
    t0=$(date +%s)
    echo "  [${region}]  Granting releases access..."
    _grant_releases_access "$region" "$deploy_profile"
    echo "  [${region}]  Granting releases access... done"

    # Pre-seed bootstrap bucket so CloudFormation EarlyValidation passes on first deploy.
    # On stack updates the bucket already exists; this is a no-op in that case.
    local account_id
    account_id=$(_aws_account_id "$deploy_profile")
    local bootstrap_bucket="netway-bootstrap-${account_id}-${region}"
    if ! aws "${AWS_PROFILE_FLAG[@]}" s3 ls "s3://${bootstrap_bucket}/lambda/latest.zip" --region "$region" >/dev/null 2>&1; then
      echo "  [${region}]  Seeding Lambda zip into bootstrap bucket..."
      aws "${AWS_PROFILE_FLAG[@]}" s3 mb "s3://${bootstrap_bucket}" --region "$region" 2>/dev/null || true

      # Try cross-account S3 copy first (fast); fall back to HTTPS download+upload if it fails.
      local zip_src="https://netway-public-releases.s3.ap-south-1.amazonaws.com/lambda/latest.zip"
      if ! aws "${AWS_PROFILE_FLAG[@]}" s3 cp \
            "s3://netway-public-releases/lambda/latest.zip" \
            "s3://${bootstrap_bucket}/lambda/latest.zip" \
            --source-region ap-south-1 --region "$region" >/dev/null 2>&1; then
        echo "  [${region}]  Cross-account S3 copy failed — downloading via HTTPS..."
        local tmp_zip; tmp_zip=$(mktemp /tmp/netway-lambda-XXXXXX.zip)
        if curl -fsSL "$zip_src" -o "$tmp_zip"; then
          aws "${AWS_PROFILE_FLAG[@]}" s3 cp "$tmp_zip" \
            "s3://${bootstrap_bucket}/lambda/latest.zip" --region "$region" >/dev/null
          rm -f "$tmp_zip"
        else
          rm -f "$tmp_zip"
          echo "  [${region}]  ERROR: Could not download Lambda zip from $zip_src" >&2
          return 1
        fi
      fi

      # Verify the zip is present before handing off to CloudFormation.
      if ! aws "${AWS_PROFILE_FLAG[@]}" s3 ls "s3://${bootstrap_bucket}/lambda/latest.zip" --region "$region" >/dev/null 2>&1; then
        echo "  [${region}]  ERROR: Lambda zip still missing from bootstrap bucket after upload." >&2
        return 1
      fi
      echo "  [${region}]  Lambda zip ready in bootstrap bucket."
    fi

    _cfn_purge_if_rolled_back "$region" "$STACK_NAME" "$deploy_profile"
    echo "  [${region}]  Stack create/update in progress..."

    local params="NetwayApiKey=$API_KEY"
    [[ "$VPCS" != "ALL" ]] && params="$params VpcIds=$VPCS"

    # Pass ExistingBucketName if the data bucket already exists so CloudFormation
    # doesn't try to CREATE it (prevents EarlyValidation conflict error).
    local data_bucket="netway-${account_id}-${region}"
    if aws "${AWS_PROFILE_FLAG[@]}" s3api head-bucket --bucket "$data_bucket" --region "$region" >/dev/null 2>&1; then
      params="$params ExistingBucketName=$data_bucket"
    fi

    aws "${AWS_PROFILE_FLAG[@]}" cloudformation deploy \
      --region "$region" \
      --stack-name "$STACK_NAME" \
      --template-file "$TEMPLATE" \
      --parameter-overrides $params \
      --capabilities CAPABILITY_NAMED_IAM \
      --no-fail-on-empty-changeset 2>&1 | tail -1

    local t1
    t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))
    local status
    status=$(aws "${AWS_PROFILE_FLAG[@]}" cloudformation describe-stacks \
      --region "$region" \
      --stack-name "$STACK_NAME" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "UNKNOWN")

    if [[ "$status" == "CREATE_COMPLETE" || "$status" == "UPDATE_COMPLETE" || "$status" == "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS" ]]; then
      echo "  [${region}]  ✓ $status ($(( elapsed/60 ))m $(( elapsed%60 ))s)"
    else
      # Show root cause before giving up
      local reason
      reason=$(_cfn_failure_reason "$region" "$STACK_NAME" "$deploy_profile")
      echo "  [${region}]  ✗ $status ($(( elapsed/60 ))m $(( elapsed%60 ))s)" >&2
      [[ -n "$reason" ]] && echo "  [${region}]  Failure reason: $reason" >&2

      # Auto-retry once: purge the rolled-back stack and redeploy
      if [[ "$status" == "ROLLBACK_COMPLETE" || "$status" == "ROLLBACK_FAILED" ]]; then
        warn "[${region}]  Auto-retrying: purging rolled-back stack and redeploying..."
        aws "${AWS_PROFILE_FLAG[@]}" cloudformation delete-stack \
          --region "$region" --stack-name "$STACK_NAME"
        aws "${AWS_PROFILE_FLAG[@]}" cloudformation wait stack-delete-complete \
          --region "$region" --stack-name "$STACK_NAME" 2>/dev/null || true
        ok "[${region}]  Stale stack removed — retrying deploy..."
        local t2; t2=$(date +%s)
        aws "${AWS_PROFILE_FLAG[@]}" cloudformation deploy \
          --region "$region" \
          --stack-name "$STACK_NAME" \
          --template-file "$TEMPLATE" \
          --parameter-overrides $params \
          --capabilities CAPABILITY_NAMED_IAM \
          --no-fail-on-empty-changeset 2>&1 | tail -1
        local t3; t3=$(date +%s)
        local elapsed2=$(( t3 - t2 ))
        status=$(aws "${AWS_PROFILE_FLAG[@]}" cloudformation describe-stacks \
          --region "$region" --stack-name "$STACK_NAME" \
          --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "UNKNOWN")
        if [[ "$status" == "CREATE_COMPLETE" || "$status" == "UPDATE_COMPLETE" || "$status" == "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS" ]]; then
          ok "[${region}]  ✓ $status on retry ($(( elapsed2/60 ))m $(( elapsed2%60 ))s)"
          return 0
        else
          reason=$(_cfn_failure_reason "$region" "$STACK_NAME" "$deploy_profile")
          echo "  [${region}]  ✗ Retry also failed: $status" >&2
          [[ -n "$reason" ]] && echo "  [${region}]  Failure reason: $reason" >&2
        fi
      fi
      return 1
    fi
  }

  if _run_parallel "_worker_deploy" "${regions[@]}"; then
    echo -e "\n${GREEN}All $n region(s) deployed successfully.${RESET}"
    _save_state
    echo "  Config saved to $(_state_file)"
    echo -e "\nNext — trigger your first scan across all regions:"
    echo "  ./netway-deploy.sh scan --wait"
    echo ""
  else
    echo -e "\n${RED}One or more regions failed. See output above.${RESET}" >&2
    exit 1
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: status
# ──────────────────────────────────────────────────────────────────────────────
cmd_status() {
  _require_regions
  local -a regions
  read -ra regions <<< "$(_region_list)"

  echo -e "\n${BOLD}Checking Netway stack status across ${#regions[@]} region(s)...${RESET}\n"

  printf "  %-18s %-20s %-25s %s\n" "Region" "Stack" "Status" "Last Updated"
  printf "  %-18s %-20s %-25s %s\n" "──────────────────" "────────────────────" \
    "─────────────────────────" "────────────────────"

  _worker_status() {
    local region="$1"
    local row
    row=$(aws cloudformation describe-stacks \
      --region "$region" \
      --stack-name "$STACK_NAME" \
      --query 'Stacks[0].[StackStatus,LastUpdatedTime,CreationTime]' \
      --output text 2>/dev/null) || {
      printf "  %-18s %-20s %-25s %s\n" "$region" "$STACK_NAME" "NOT_DEPLOYED" "-"
      return 0
    }
    local status updated creation
    status=$(echo "$row" | awk '{print $1}')
    updated=$(echo "$row" | awk '{print $2}')
    [[ -z "$updated" || "$updated" == "None" ]] && updated=$(echo "$row" | awk '{print $3}')
    updated=$(echo "$updated" | cut -c1-16 | tr 'T' ' ')
    printf "  %-18s %-20s %-25s %s\n" "$region" "$STACK_NAME" "$status" "$updated UTC"
  }

  _run_parallel "_worker_status" "${regions[@]}"
  echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: update
# ──────────────────────────────────────────────────────────────────────────────
cmd_update() {
  _require_regions

  # Use local template if available; only download from S3 when --template not given
  # and no local copy can be found (production customer scenario).
  _ensure_template

  local version
  version=$(_latest_template_version)
  echo "  Template version: $version"

  local -a regions
  read -ra regions <<< "$(_region_list)"
  local n="${#regions[@]}"

  local region_list_str; region_list_str=$(IFS=,; echo "${regions[*]}")
  if [[ "$YES" -eq 0 ]]; then
    read -rp $'\nUpdate Netway in '"$region_list_str"' to '"$version"'? [y/N] ' ans
    [[ "${ans,,}" != "y" ]] && { echo "Aborted."; exit 0; }
  fi

  echo -e "\n${BOLD}Updating Netway in $n region(s) (parallel)...${RESET}\n"

  _worker_update() {
    local region="$1"
    local t0; t0=$(date +%s)
    echo "  [${region}]  Update in progress..."
    aws cloudformation deploy \
      --region "$region" \
      --stack-name "$STACK_NAME" \
      --template-file "$TEMPLATE" \
      --capabilities CAPABILITY_NAMED_IAM \
      --no-fail-on-empty-changeset 2>&1 | tail -1
    local t1; t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))
    local status
    status=$(aws cloudformation describe-stacks \
      --region "$region" --stack-name "$STACK_NAME" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "UNKNOWN")
    if [[ "$status" == "CREATE_COMPLETE" || "$status" == "UPDATE_COMPLETE" || "$status" == "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS" ]]; then
      echo "  [${region}]  ✓ $status ($(( elapsed/60 ))m $(( elapsed%60 ))s)"
    else
      echo "  [${region}]  ✗ $status" >&2; return 1
    fi
  }

  if _run_parallel "_worker_update" "${regions[@]}"; then
    echo -e "\n${GREEN}All $n region(s) updated to $version.${RESET}\n"
  else
    echo -e "\n${RED}One or more regions failed.${RESET}" >&2; exit 1
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: upgrade  (force-download template from S3, then update)
# ──────────────────────────────────────────────────────────────────────────────
cmd_upgrade() {
  _require_regions

  # Always download the latest template from S3 regardless of local copies.
  TEMPLATE="./netway-deploy.yml"
  echo -e "\nDownloading latest netway-deploy.yml from S3..."
  if ! curl -fsSL "$TEMPLATE_URL" -o "$TEMPLATE" 2>/dev/null; then
    echo "ERROR: Could not download template from $TEMPLATE_URL" >&2
    exit 1
  fi
  echo "  Downloaded to $TEMPLATE"

  local version
  version=$(_latest_template_version)
  echo "  Template version: $version"

  local -a regions
  read -ra regions <<< "$(_region_list)"
  local n="${#regions[@]}"

  local region_list_str; region_list_str=$(IFS=,; echo "${regions[*]}")
  if [[ "$YES" -eq 0 ]]; then
    read -rp $'\nUpgrade Netway in '"$region_list_str"' to '"$version"'? [y/N] ' ans
    [[ "${ans,,}" != "y" ]] && { echo "Aborted."; exit 0; }
  fi

  echo -e "\n${BOLD}Upgrading Netway in $n region(s) (parallel)...${RESET}\n"

  _worker_upgrade() {
    local region="$1"
    local t0; t0=$(date +%s)
    echo "  [${region}]  Upgrade in progress..."
    aws cloudformation deploy \
      --region "$region" \
      --stack-name "$STACK_NAME" \
      --template-file "$TEMPLATE" \
      --capabilities CAPABILITY_NAMED_IAM \
      --no-fail-on-empty-changeset 2>&1 | tail -1
    local t1; t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))
    local status
    status=$(aws cloudformation describe-stacks \
      --region "$region" --stack-name "$STACK_NAME" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "UNKNOWN")
    if [[ "$status" == "CREATE_COMPLETE" || "$status" == "UPDATE_COMPLETE" || "$status" == "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS" ]]; then
      echo "  [${region}]  ✓ $status ($(( elapsed/60 ))m $(( elapsed%60 ))s)"
    else
      echo "  [${region}]  ✗ $status" >&2; return 1
    fi
  }

  if _run_parallel "_worker_upgrade" "${regions[@]}"; then
    echo -e "\n${GREEN}All $n region(s) upgraded to $version.${RESET}\n"
  else
    echo -e "\n${RED}One or more regions failed.${RESET}" >&2; exit 1
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: scan
# ──────────────────────────────────────────────────────────────────────────────
cmd_scan() {
  _require_regions
  local -a regions
  read -ra regions <<< "$(_region_list)"

  # Build (profile, region) work units. If no --profile given, use the default profile.
  local -a profiles
  if [[ "${#PROFILES[@]}" -gt 0 ]]; then
    profiles=("${PROFILES[@]}")
  else
    profiles=("default")
  fi

  # Expand into "profile:region" pairs
  local -a work_units=()
  for p in "${profiles[@]}"; do
    for r in "${regions[@]}"; do
      work_units+=("${p}:${r}")
    done
  done
  local n="${#work_units[@]}"

  echo -e "\n${BOLD}Triggering scan in $n region/account pair(s) (parallel)...${RESET}\n"

  # Capture wall-clock start and pre-scan timestamps (for --wait polling)
  local scan_started_at; scan_started_at=$(date +%s)
  declare -A PRE_SCAN_TS
  if [[ "$WAIT" -eq 1 && -n "$API_KEY" ]]; then
    local acct
    acct=$(curl -s "$API_URL/v1/account" -H "X-Api-Key: $API_KEY")
    for region in "${regions[@]}"; do
      local ts
      ts=$(echo "$acct" | python3 -c "
import sys,json,datetime,calendar
data=json.load(sys.stdin)
regions=data.get('deployed_regions',[])
match=next((r for r in regions if r['region']==sys.argv[1] or r['region']=='all'),None)
if match:
    v=match.get('last_scan_at') or 0
    if isinstance(v,str):
        try:
            dt=datetime.datetime.fromisoformat(v.replace('Z','+00:00'))
            v=int(calendar.timegm(dt.utctimetuple()))
        except: v=0
    print(v)
else:
    print(0)
" "$region" 2>/dev/null || echo 0)
      PRE_SCAN_TS["$region"]="$ts"
    done
  fi

  _worker_scan() {
    local unit="$1"
    local profile="${unit%%:*}"
    local region="${unit##*:}"
    local label="${region}"
    [[ "$profile" != "default" ]] && label="${profile}/${region}"
    local out="/tmp/netway-scan-${profile}-${region}.json"
    local t0; t0=$(date +%s)
    echo "  [${label}]  Invoking Lambda..."

    local aws_profile_flag=()
    [[ "$profile" != "default" ]] && aws_profile_flag=(--profile "$profile")

    local fn_name
    fn_name=$(_lambda_name_for_stack "$region" "$STACK_NAME" "$profile")

    local rc=0
    aws "${aws_profile_flag[@]}" lambda invoke \
      --region "$region" \
      --function-name "$fn_name" \
      --invocation-type Event \
      --payload '{}' \
      --cli-binary-format raw-in-base64-out \
      "$out" > /dev/null 2>&1 || rc=$?

    local t1; t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))

    rm -f "$out"

    if [[ $rc -ne 0 ]]; then
      if aws "${aws_profile_flag[@]}" lambda get-function --function-name "$fn_name" --region "$region" >/dev/null 2>&1; then
        echo "  [${label}]  ✗ Lambda invocation failed — check CloudWatch logs"
      else
        echo "  [${label}]  ✗ Lambda not found — is Netway deployed in this region?"
        echo "               Run: ./netway-deploy.sh deploy --regions $region"
      fi
      return 1
    fi

    if [[ "$WAIT" -eq 1 ]]; then
      echo "  [${label}]  ✓ Invoked — waiting for results..."
    else
      echo "  [${label}]  ✓ Scan triggered (async)  (${elapsed}s)"
    fi
  }

  _run_parallel "_worker_scan" "${work_units[@]}" || { echo -e "\n${RED}One or more scans failed.${RESET}" >&2; exit 1; }

  # Persist config for next invocation
  _save_state

  if [[ "$WAIT" -eq 0 ]]; then
    echo -e "\n${GREEN}All $n scan(s) triggered successfully.${RESET}"
    echo "  Findings will appear in your dashboard within a few minutes."
    echo ""
    return
  fi

  # ── --wait: poll until each region's last_scan_at advances ──────────────────
  if [[ -z "$API_KEY" ]]; then
    warn "--wait requires --api-key to poll for results. Exiting without waiting."
    exit 0
  fi

  local invoked_at="${scan_started_at}"
  local deadline=$(( invoked_at + SCAN_WAIT_TIMEOUT ))
  declare -A DONE
  for r in "${regions[@]}"; do DONE["$r"]=0; done

  while true; do
    local now; now=$(date +%s)
    if (( now > deadline )); then
      warn "Timeout (${SCAN_WAIT_TIMEOUT}s) — some regions may still be scanning."
      break
    fi

    local acct acct_http
    acct=$(curl -s -w "\n%{http_code}" "$API_URL/v1/account" -H "X-Api-Key: $API_KEY")
    acct_http=$(echo "$acct" | tail -1)
    acct=$(echo "$acct" | head -n -1)
    if [[ "$acct_http" != "200" ]]; then
      warn "[wait] /v1/account returned HTTP $acct_http — retrying in 15s..."
      sleep 15; continue
    fi
    local all_done=1

    for region in "${regions[@]}"; do
      [[ "${DONE[$region]}" -eq 1 ]] && continue
      local ts
      ts=$(echo "$acct" | python3 -c "
import sys,json,datetime
data=json.load(sys.stdin)
regions=data.get('deployed_regions',[])
# Match exact region or 'all' (Lambda may report all regions as a single entry)
match=next((r for r in regions if r['region']==sys.argv[1] or r['region']=='all'),None)
if match:
    v=match.get('last_scan_at') or 0
    if isinstance(v,str):
        try:
            import calendar
            dt=datetime.datetime.fromisoformat(v.replace('Z','+00:00'))
            v=int(calendar.timegm(dt.utctimetuple()))
        except: v=0
    print(v)
else:
    print(0)
" "$region" 2>/dev/null || echo 0)

      local pre="${PRE_SCAN_TS[$region]:-0}"
      if (( ts > pre )); then
        # Fetch findings count
        local vpc_count
        vpc_count=$(echo "$acct" | python3 -c "
import sys,json
data=json.load(sys.stdin)
regions=data.get('deployed_regions',[])
match=next((r for r in regions if r['region']==sys.argv[1] or r['region']=='all'),None)
print(match.get('vpc_count',0) if match else 0)
" "$region" 2>/dev/null || echo "0")
        local elapsed=$(( now - invoked_at ))
        ok "[${region}]  Scan complete — ${vpc_count} VPC(s) mapped  ($(( elapsed/60 ))m $(( elapsed%60 ))s)"
        DONE["$region"]=1
      else
        all_done=0
      fi
    done

    [[ "$all_done" -eq 1 ]] && break
    sleep 15
  done

  echo -e "\n${GREEN}All regions scanned.${RESET}  View results at https://app.basavytix.com/netway/dashboard\n"
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: delete
# ──────────────────────────────────────────────────────────────────────────────
cmd_delete() {
  _require_regions
  local deploy_profile="${PROFILES[0]:-}"
  local AWS_PROFILE_FLAG=()
  [[ -n "$deploy_profile" ]] && AWS_PROFILE_FLAG=(--profile "$deploy_profile")

  local -a regions
  read -ra regions <<< "$(_region_list)"
  local n="${#regions[@]}"

  echo -e "\n${BOLD}${RED}This will DELETE the Netway stack from $n region(s):${RESET}"
  for r in "${regions[@]}"; do echo "  - $r"; done
  echo ""
  echo "  All Netway resources (Lambda, S3 bucket, Athena workgroup, VPC Flow Logs,"
  echo "  IAM role, EventBridge rules) will be removed."
  echo "  Flow logs that existed before Netway are untouched."
  echo "  Findings for these regions remain in your Netway dashboard."
  echo ""

  if [[ "$YES" -eq 0 ]]; then
    read -rp 'Type "delete" to confirm: ' ans
    [[ "$ans" != "delete" ]] && { echo "Aborted."; exit 0; }
  fi

  echo ""

  _worker_delete() {
    local region="$1"
    local t0; t0=$(date +%s)
    echo "  [${region}]  Deleting stack..."
    aws "${AWS_PROFILE_FLAG[@]}" cloudformation delete-stack \
      --region "$region" \
      --stack-name "$STACK_NAME"
    aws "${AWS_PROFILE_FLAG[@]}" cloudformation wait stack-delete-complete \
      --region "$region" \
      --stack-name "$STACK_NAME" 2>/dev/null || true
    local t1; t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))
    echo "  [${region}]  ✓ DELETE_COMPLETE ($(( elapsed/60 ))m $(( elapsed%60 ))s)"
  }

  _run_parallel "_worker_delete" "${regions[@]}"
  echo -e "\n${GREEN}Done.${RESET}\n"
}

# ──────────────────────────────────────────────────────────────────────────────
# COMMAND: outputs
# ──────────────────────────────────────────────────────────────────────────────
cmd_outputs() {
  _require_regions
  local -a regions
  read -ra regions <<< "$(_region_list)"

  local profile="${PROFILES[0]:-}"
  local profile_flag=()
  [[ -n "$profile" ]] && profile_flag=(--profile "$profile")

  if [[ "$JSON" -eq 1 ]]; then
    local all='{}'
    for region in "${regions[@]}"; do
      local raw
      raw=$(aws "${profile_flag[@]}" cloudformation describe-stacks \
        --region "$region" --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs' --output json 2>/dev/null || echo "null")
      all=$(echo "$all" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['$region'] = json.loads('''${raw}'''.replace(\"'\", '\"'))
print(json.dumps(d, indent=2))
" 2>/dev/null || echo "$all")
    done
    echo "$all"
    return
  fi

  echo -e "\n${BOLD}Stack outputs for ${STACK_NAME}${RESET}\n"
  for region in "${regions[@]}"; do
    echo "  ${BOLD}[${region}]${RESET}"
    local raw
    raw=$(aws "${profile_flag[@]}" cloudformation describe-stacks \
      --region "$region" --stack-name "$STACK_NAME" \
      --query 'Stacks[0].Outputs' --output json 2>/dev/null || echo "null")
    if [[ "$raw" == "null" || -z "$raw" ]]; then
      echo "    (stack not found or no outputs)"
    else
      echo "$raw" | python3 -c "
import sys, json
outputs = json.load(sys.stdin) or []
for o in outputs:
    k = o.get('OutputKey','')
    v = o.get('OutputValue','')
    desc = o.get('Description','')
    label = f'({desc})' if desc else ''
    print(f'    {k:<35} {v}  {label}')
" 2>/dev/null || echo "    (error reading outputs)"
    fi
    echo ""
  done
}


# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$CMD" in
  deploy)   cmd_deploy   ;;
  status)   cmd_status   ;;
  update)   cmd_update   ;;
  upgrade)  cmd_upgrade  ;;
  scan)     cmd_scan     ;;
  delete)   cmd_delete   ;;
  outputs)  cmd_outputs  ;;
  help|-h|--help) usage ;;
  *) echo "Unknown command: $CMD" >&2; usage 1 ;;
esac
