#!/bin/bash
set -euo pipefail

echo "Running validator test cases found in $PWD folder"

for file in $(find . -name "*\.json" -type f); do
  echo "Running test case: $file"
  ./validator --api-srv=http://127.0.0.1:8080 --kafka-srv=127.0.0.1:9092 --test-file="$file" --v=3
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "Test case $file failed with exit code $rc"
  else
    echo "Test case $file passed"
  fi
done