#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

if rg -n 'graph\.microsoft\.com/beta' "$root" --glob '*.go'; then
  echo "Graph beta base URL is not allowed" >&2
  exit 1
fi

if rg -n '"[^"]*/beta/[^"]*"' "$root" --glob '*.go'; then
  echo "Graph /beta/ route segment is not allowed" >&2
  exit 1
fi
