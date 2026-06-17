#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://127.0.0.1:8080}"
deadline=$((SECONDS + 180))

required_families=(
  "ipv4/unicast"
  "ipv6/unicast"
  "ipv4/labeled-unicast"
  "vpnv4"
  "vpnv6"
)

while (( SECONDS < deadline )); do
  session="$(curl -fsS "$API/v1/session" 2>/dev/null || true)"

  if jq -e '.state == "established"' >/dev/null 2>&1 <<<"$session"; then
    missing=0
    for family in "${required_families[@]}"; do
      if ! jq -e --arg family "$family" '.negotiated_families // [] | index($family)' >/dev/null <<<"$session"; then
        missing=1
        break
      fi
    done

    if (( missing == 0 )); then
      echo "bgpinjector session is established and required AFI/SAFI are negotiated"
      exit 0
    fi
  fi

  sleep 2
done

echo "bgpinjector did not become ready in time"
curl -s "$API/v1/session" || true
exit 1