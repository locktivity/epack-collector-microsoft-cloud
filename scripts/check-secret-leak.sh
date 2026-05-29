#!/usr/bin/env bash
set -euo pipefail

bin="${1:-./epack-collector-microsoft-cloud}"
stdout_file="$(mktemp)"
stderr_file="$(mktemp)"
config_file="$(mktemp)"
trap 'rm -f "$stdout_file" "$stderr_file" "$config_file"' EXIT

cat > "$config_file" <<'JSON'
{
  "tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "client_id": "11111111-2222-3333-4444-555555555555",
  "auth_mode": "client_secret",
  "subscription_ids": ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
}
JSON

set +e
EPACK_COLLECTOR_CONFIG="$config_file" \
AZURE_CLIENT_SECRET="ms_CANARY_LEAK_SECRET" \
ACTIONS_ID_TOKEN_REQUEST_TOKEN="ms_CANARY_LEAK_TOKEN" \
ACTIONS_ID_TOKEN_REQUEST_URL="https://example.invalid/oidc" \
"$bin" --capabilities >"$stdout_file" 2>"$stderr_file"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  echo "collector metadata command failed unexpectedly" >&2
  cat "$stderr_file" >&2
  exit "$status"
fi

if rg -n 'ms_CANARY_LEAK_SECRET|ms_CANARY_LEAK_TOKEN' "$stdout_file" "$stderr_file"; then
  echo "canary secret leaked to collector output" >&2
  exit 1
fi
