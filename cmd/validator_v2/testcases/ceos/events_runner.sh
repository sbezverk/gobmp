#!/usr/bin/env bash
#
# Run validator_v2 cases whose message is caused by a change made outside the
# validator. A CASE.json may have a sibling trigger file that is applied once
# the validator is waiting for the message:
#   CASE.eos    cEOS configuration lines.
#   CASE.gobgp  gobgp CLI commands, one per line, run in the GoBGP container.
# Cases run in name order.
#
# Usage: events_runner.sh
# Environment: VALIDATOR_BIN, TESTCASE_DIR, API_SRV, KAFKA_SRV,
#   VALIDATOR_VERBOSITY (3 or higher), CEOS_CONTAINER, GOBGP_CONTAINER
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
readonly GOBGP_CONTAINER="${GOBGP_CONTAINER:-gobgp-flowspec}"
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
# Returns:
#   1 if FastCli fails or EOS rejects a line. EOS prints an error starting
#   with "% "; the "% " check does not rely on the FastCli exit status.
#######################################
applyEosTrigger() {
  local triggerFile="$1"
  local output
  local status=0

  output="$({
    echo "configure"
    cat -- "${triggerFile}"
    echo "end"
  } | docker exec -i "${CEOS_CONTAINER}" FastCli -p 15 2>&1)" || status=1
  printf '%s\n' "${output}"
  ((status == 0)) && ! grep -q '^% ' <<<"${output}"
}

#######################################
# Run gobgp CLI commands in the GoBGP container, one command per line. Blank
# lines and lines starting with "#" are skipped.
# Arguments:
#   File with the commands.
# Returns:
#   1 if a command fails.
#######################################
applyGobgpTrigger() {
  local triggerFile="$1"
  local line
  local -a args

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    read -r -a args <<<"${line}"
    echo "gobgp ${line}"
    docker exec "${GOBGP_CONTAINER}" gobgp "${args[@]}" || return 1
  done <"${triggerFile}"
}

#######################################
# Find the trigger file of a test case.
# Arguments:
#   Test case JSON file.
# Outputs:
#   The trigger file path, or nothing if the case has none.
#######################################
findTrigger() {
  local base="${1%.json}"
  local extension

  for extension in eos gobgp; do
    if [[ -f "${base}.${extension}" ]]; then
      echo "${base}.${extension}"
      return
    fi
  done
}

#######################################
# Apply a trigger file by its extension.
# Arguments:
#   Trigger file.
# Returns:
#   1 if the trigger fails.
#######################################
applyTrigger() {
  local triggerFile="$1"

  case "${triggerFile}" in
    *.eos) applyEosTrigger "${triggerFile}" ;;
    *.gobgp) applyGobgpTrigger "${triggerFile}" ;;
  esac
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
  local triggerFile
  local validatorPid
  local status=0

  triggerFile="$(findTrigger "${testFile}")"
  "${VALIDATOR_BIN}" --api-srv="${API_SRV}" --kafka-srv="${KAFKA_SRV}" \
    --test-file="${testFile}" --v="${VALIDATOR_VERBOSITY}" >"${logFile}" 2>&1 &
  validatorPid=$!

  if [[ -n "${triggerFile}" ]]; then
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
