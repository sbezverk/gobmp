#!/bin/bash
set -euo pipefail

echo "Running validator test cases found in $PWD folder"

total=0
passed=0
failed=0

while IFS= read -r file; do
  total=$((total + 1))
  echo "Running test case: $file"
  if ./validator --api-srv=http://127.0.0.1:8080 --kafka-srv=127.0.0.1:9092 --test-file="$file" --v=3; then
    passed=$((passed + 1))
    echo "Test case $file passed"
  else
    rc=$?
    failed=$((failed + 1))
    echo "Test case $file failed with exit code $rc"
  fi
done < <(find . -name "*.json" -type f | sort)

echo "Validator test case summary: total=$total passed=$passed failed=$failed"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
