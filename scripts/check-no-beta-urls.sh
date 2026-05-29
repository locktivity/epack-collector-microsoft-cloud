#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

if command -v rg >/dev/null 2>&1; then
  search() {
    rg -n "$1" "$root" --glob '*.go'
  }
else
  search() {
    git -C "$root" grep -n -E "$1" -- '*.go'
  }
fi

if search 'graph\.microsoft\.com/beta'; then
  echo "Graph beta base URL is not allowed" >&2
  exit 1
fi

if search '"[^"]*/beta/[^"]*"'; then
  echo "Graph /beta/ route segment is not allowed" >&2
  exit 1
fi
