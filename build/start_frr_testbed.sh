#!/usr/bin/env bash
set -euo pipefail

compose_file=./build/unicastv4-bgp/test_bed_single_kafka_frr.yaml

assert_collector_absent() {
    local collector
    collector=$(docker compose -f "$compose_file" ps --all --quiet gobmp)
    if [[ -n "$collector" ]]; then
        echo "gobmp exists before FRR readiness; refusing an early BMP connection" >&2
        return 1
    fi
}

assert_collector_absent
# FRR depends_on gobmp in this Compose file. Explicit prerequisites and
# --no-deps are required to keep BMP disconnected until both routers are ready.
docker compose -f "$compose_file" up --detach --no-deps zoo kafka frr-1 frr-2
assert_collector_absent

# The outer timeout owns the complete readiness budget, including blocked CLI
# calls. Foreground mode keeps queries in the caller's cancellation process group.
if timeout --foreground 120s bash -s <<'READY'
set -euo pipefail

router_ready() {
    local router=$1 peer=$2 status summary
    if ! status=$(timeout --foreground 5s docker exec "$router" vtysh -c 'show watchfrr'); then
        echo "Failed to query current watchfrr status on $router" >&2
        return 1
    fi
    if ! awk '
        { sub(/\r$/, "") }
        /^watchfrr global phase: Idle$/ { idle = 1 }
        $1 == "zebra" || $1 == "bgpd" || $1 == "staticd" {
            if (NF == 2 && $2 == "Up") up[$1] = 1
            else bad = 1
        }
        /restart running|restarting in/ { bad = 1 }
        END { exit !(idle && up["zebra"] && up["bgpd"] && up["staticd"] && !bad) }
    ' <<< "$status"; then
        printf 'FRR daemons not ready on %s:\n%s\n' "$router" "$status" >&2
        return 1
    fi
    if ! summary=$(timeout --foreground 5s docker exec "$router" vtysh -c 'show bgp ipv4 unicast summary json'); then
        echo "Failed to query current BGP status on $router" >&2
        return 1
    fi
    if ! jq -e --arg peer "$peer" '.peers[$peer].state == "Established"' <<< "$summary" > /dev/null; then
        printf 'BGP adjacency not ready on %s:\n%s\n' "$router" "$summary" >&2
        return 1
    fi
}

until router_ready frr-1 192.168.100.12 && router_ready frr-2 192.168.100.11; do
    sleep 2
done
READY
then
    echo "Both FRR routers and BGP adjacencies are ready"
else
    status=$?
    echo "FRR readiness failed; gobmp has not been started" >&2
    exit "$status"
fi

before=$(docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.RestartCount}}' frr-1 frr-2)
if ! awk 'NF != 3 { bad = 1 } END { exit bad || NR != 2 }' <<< "$before"; then
    echo "Invalid FRR container identity snapshot" >&2
    exit 1
fi

docker compose -f "$compose_file" up --detach --no-deps --no-recreate gobmp

after=$(docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.RestartCount}}' frr-1 frr-2)
if [[ "$before" != "$after" ]]; then
    printf 'FRR container identity changed while starting gobmp:\nbefore:\n%s\nafter:\n%s\n' "$before" "$after" >&2
    exit 1
fi
echo "gobmp started without recreating or restarting the FRR containers"
