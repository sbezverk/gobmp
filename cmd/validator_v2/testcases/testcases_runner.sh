#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR_BIN="${VALIDATOR_BIN:-${SCRIPT_DIR}/validator}"
API_SRV="${API_SRV:-http://127.0.0.1:8080}"
KAFKA_SRV="${KAFKA_SRV:-127.0.0.1:9092}"
VALIDATOR_VERBOSITY="${VALIDATOR_VERBOSITY:-3}"

echo "Running validator test cases found in ${SCRIPT_DIR} folder"
echo "Using validator binary: ${VALIDATOR_BIN}"

total=0
passed=0
failed=0

while IFS= read -r file; do
  total=$((total + 1))
  echo "Running test case: $file"
  if "${VALIDATOR_BIN}" --api-srv="${API_SRV}" --kafka-srv="${KAFKA_SRV}" --test-file="$file" --v="${VALIDATOR_VERBOSITY}"; then
    passed=$((passed + 1))
    echo "Test case $file passed"
  else
    rc=$?
    failed=$((failed + 1))
    echo "Test case $file failed with exit code $rc"
  fi
done < <(find "${SCRIPT_DIR}" -name "*.json" -type f | sort)

echo "Validator test case summary: total=$total passed=$passed failed=$failed"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
