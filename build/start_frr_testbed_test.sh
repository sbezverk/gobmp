#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"

# Replace only the Docker CLI boundary. The startup script, readiness parsing,
# timeout process and jq all execute normally.
cat > "$scratch/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_STATE/commands.log"

case "$1" in
    compose)
        case " $* " in
            *" ps "*)
                if [[ "$FAKE_DOCKER_CASE" == existing_collector || -e "$FAKE_DOCKER_STATE/collector" ]]; then
                    echo collector-id
                fi
                ;;
            *" up "*)
                case " $* " in
                    *" frr-1 "*)
                        # Actual Compose has FRR -> gobmp dependency edges.
                        case " $* " in
                            *" --no-deps "*) ;;
                            *) touch "$FAKE_DOCKER_STATE/collector" ;;
                        esac
                        ;;
                    *" gobmp "*)
                        touch "$FAKE_DOCKER_STATE/collector"
                        ;;
                esac
                ;;
            *) exit 2 ;;
        esac
        ;;
    exec)
        if [[ "$FAKE_DOCKER_CASE" == command_error ]]; then
            echo "simulated live command failure" >&2
            exit 1
        fi
        if [[ "$FAKE_DOCKER_CASE" == blocked_query ]]; then
            sleep 20
        fi
        case "$5" in
            "show watchfrr")
                if [[ "$FAKE_DOCKER_CASE" == startup_phase ]]; then
                    echo "watchfrr global phase: Startup"
                else
                    echo "watchfrr global phase: Idle"
                fi
                if [[ "$FAKE_DOCKER_CASE" == missing_daemon && "$2" == frr-1 ]]; then
                    echo "  zebra Down"
                elif [[ "$FAKE_DOCKER_CASE" == second_router_down && "$2" == frr-2 ]]; then
                    echo "  zebra Down"
                elif [[ "$FAKE_DOCKER_CASE" == stale_logs_live_down ]]; then
                    echo "  zebra Down"
                else
                    echo "  zebra Up"
                fi
                echo "  bgpd Up"
                if [[ "$FAKE_DOCKER_CASE" != absent_daemon ]]; then
                    echo "  staticd Up"
                fi
                if [[ "$FAKE_DOCKER_CASE" == restart_pending ]]; then
                    echo "    global restart running, pid 46"
                fi
                ;;
            "show bgp ipv4 unicast summary json")
                if [[ "$FAKE_DOCKER_CASE" == parse_error ]]; then
                    echo "not-json"
                else
                    peer=192.168.100.12
                    [[ "$2" != frr-2 ]] || peer=192.168.100.11
                    state=Established
                    if [[ "$FAKE_DOCKER_CASE" == second_bgp_down && "$2" == frr-2 ]]; then
                        state=Active
                    fi
                    printf '{"peers":{"%s":{"state":"%s"}}}\n' "$peer" "$state"
                fi
                ;;
            *) exit 2 ;;
        esac
        ;;
    inspect)
        count=0
        [[ ! -e "$FAKE_DOCKER_STATE/inspects" ]] || read -r count < "$FAKE_DOCKER_STATE/inspects"
        count=$((count + 1))
        echo "$count" > "$FAKE_DOCKER_STATE/inspects"
        first=frr-1-id
        if [[ "$FAKE_DOCKER_CASE" == identity_changed && "$count" == 2 ]]; then
            first=recreated-frr-1-id
        fi
        printf '%s 2026-10-31T09:00:00Z 0\n' "$first" frr-2-id
        ;;
    logs)
        # Old readiness used historical logs. They can look healthy while live
        # daemon state is Down, and must never allow phase 2.
        printf '%s\n' \
            "Kafka publisher has been successfully initialized" \
            "client 10.1.1.3 connected" \
            "watchfrr global phase: Idle" \
            "  zebra Up" "  bgpd Up" "  staticd Up"
        ;;
    *) exit 2 ;;
esac
DOCKER
chmod +x "$scratch/bin/docker"

run_case() {
    local name=$1 limit=$2 program=$3 result
    mkdir "$scratch/$name"
    set +e
    FAKE_DOCKER_STATE="$scratch/$name" FAKE_DOCKER_CASE="$name" \
        PATH="$scratch/bin:$PATH" timeout "$limit" bash "$program" \
        > "$scratch/$name/output.log" 2>&1
    result=$?
    set -e
    echo "$result" > "$scratch/$name/exit"
}

run_case healthy 10s build/start_frr_testbed.sh
if [[ $(cat "$scratch/healthy/exit") != 0 || ! -e "$scratch/healthy/collector" ]]; then
    cat "$scratch/healthy/output.log" >&2
    echo "healthy startup did not start the collector" >&2
    exit 1
fi
grep -Fq -- "up --detach --no-deps zoo kafka frr-1 frr-2" "$scratch/healthy/commands.log"
grep -Fq -- "up --detach --no-deps --no-recreate gobmp" "$scratch/healthy/commands.log"
[[ $(cat "$scratch/healthy/inspects") == 2 ]]

for name in missing_daemon absent_daemon second_router_down stale_logs_live_down startup_phase restart_pending second_bgp_down command_error parse_error blocked_query; do
    run_case "$name" 1s build/start_frr_testbed.sh
    if [[ $(cat "$scratch/$name/exit") != 124 || -e "$scratch/$name/collector" ]]; then
        cat "$scratch/$name/output.log" >&2
        echo "$name incorrectly allowed collector startup" >&2
        exit 1
    fi
done

run_case existing_collector 10s build/start_frr_testbed.sh
[[ $(cat "$scratch/existing_collector/exit") != 0 ]]
! grep -q -- " up " "$scratch/existing_collector/commands.log"

run_case identity_changed 10s build/start_frr_testbed.sh
[[ $(cat "$scratch/identity_changed/exit") != 0 ]]
grep -Fq "FRR container identity changed" "$scratch/identity_changed/output.log"

# Behavioral negative control: removing phase 1's --no-deps follows the actual
# dependency edge into gobmp; the real absence guard must catch the early start.
sed 's/--detach --no-deps zoo/--detach zoo/' build/start_frr_testbed.sh > "$scratch/without-no-deps.sh"
run_case without_no_deps 10s "$scratch/without-no-deps.sh"
[[ $(cat "$scratch/without_no_deps/exit") != 0 ]]
[[ -e "$scratch/without_no_deps/collector" ]]
grep -Fq "gobmp exists before FRR readiness" "$scratch/without_no_deps/output.log"

echo "PASS: healthy phased startup, readiness failures, stale logs, identity guard and dependency negative control"
