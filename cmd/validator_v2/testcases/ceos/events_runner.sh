#!/usr/bin/env bash
#
# Run validator_v2 cases whose message is caused by a cEOS configuration change.
# A CASE.json may have a sibling CASE.eos holding the configuration lines to
# apply once the validator is waiting for the message. Cases run in name order.
#
# Usage: events_runner.sh
# Environment: VALIDATOR_BIN, TESTCASE_DIR, API_SRV, KAFKA_SRV,
#   VALIDATOR_VERBOSITY (3 or higher), CEOS_CONTAINER
# Requires: docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly VALIDATOR_BIN="${VALIDATOR_BIN:-${SCRIPT_DIR}/validator}"
readonly TESTCASE_DIR="${TESTCASE_DIR:-${SCRIPT_DIR}/events}"
readonly API_SRV="${API_SRV:-http://127.0.0.1:8080}"
readonly KAFKA_SRV="${KAFKA_SRV:-127.0.0.1:9092}"
readonly VALIDATOR_VERBOSITY="${VALIDATOR_VERBOSITY:-3}"
readonly CEOS_CONTAINER="${CEOS_CONTAINER:-ceos-1}"
# validator_v2 logs this once its Kafka consumer runs and the update is sent.
readonly INJECT_MARKER="Injected update queued"
readonly INJECT_WAIT_SECONDS=60

#######################################
# Wait until the validator reports that it injected its update.
# Arguments:
#   Validator log file.
#   Validator process ID.
# Returns:
#   1 if the validator exits or the wait times out first.
#######################################
waitForInjection() {
  local logFile="$1"
  local validatorPid="$2"
  local second

  for ((second = 0; second < INJECT_WAIT_SECONDS; second += 1)); do
    if grep -q "${INJECT_MARKER}" "${logFile}"; then
      return 0
    fi
    kill -0 "${validatorPid}" 2>/dev/null || return 1
    sleep 1
  done
  return 1
}

#######################################
# Apply configuration lines to the cEOS container.
# Arguments:
#   File with the configuration lines.
#######################################
applyTrigger() {
  local triggerFile="$1"

  {
    echo "configure"
    cat -- "${triggerFile}"
    echo "end"
  } | docker exec -i "${CEOS_CONTAINER}" FastCli -p 15
}

#######################################
# Run one test case and its trigger, if it has one.
# Arguments:
#   Test case JSON file.
#   File that receives the validator log.
# Returns:
#   0 if the case passed.
#######################################
runCase() {
  local testFile="$1"
  local logFile="$2"
  local triggerFile="${testFile%.json}.eos"
  local validatorPid
  local status=0

  "${VALIDATOR_BIN}" --api-srv="${API_SRV}" --kafka-srv="${KAFKA_SRV}" \
    --test-file="${testFile}" --v="${VALIDATOR_VERBOSITY}" >"${logFile}" 2>&1 &
  validatorPid=$!

  if [[ -f "${triggerFile}" ]]; then
    if ! waitForInjection "${logFile}" "${validatorPid}" || ! applyTrigger "${triggerFile}"; then
      echo "error: trigger not applied: ${triggerFile}" >&2
      status=1
      kill "${validatorPid}" 2>/dev/null || true
    fi
  fi

  wait "${validatorPid}" || status=1
  cat -- "${logFile}"
  return "${status}"
}

main() {
  local logFile
  local testFile
  local total=0
  local passed=0
  local failed=0

  logFile="$(mktemp)"
  # shellcheck disable=SC2064  # expanding now is intended
  trap "rm -f -- '${logFile}'" EXIT

  for testFile in "${TESTCASE_DIR}"/*.json; do
    [[ -f "${testFile}" ]] || continue
    total=$((total + 1))
    echo "Running test case: ${testFile}"
    if runCase "${testFile}" "${logFile}"; then
      passed=$((passed + 1))
      echo "Test case ${testFile} passed"
    else
      failed=$((failed + 1))
      echo "Test case ${testFile} failed"
    fi
  done

  echo "Validator test case summary: total=${total} passed=${passed} failed=${failed}"
  ((failed == 0))
}

main "$@"
