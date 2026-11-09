#!/usr/bin/env bash
# Non-destructive isolation audit. Run on the Docker host after starting a
# challenge. Exits non-zero if a check fails.
set -uo pipefail

fail=0
ok()   { printf '  [ok]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=1; }
note() { printf '  [note] %s\n' "$1"; }

echo "== CyberLab isolation audit =="

echo
echo "-- dashboard listeners --"
ss -ltnp 2>/dev/null | grep -E ':(8443|443|80)\b' || note "no dashboard listener found"

echo
echo "-- managed containers --"
ids="$(docker ps -q --filter label=cyberlab.managed=true 2>/dev/null || true)"
if [ -z "$ids" ]; then
    note "no managed challenge containers are running"
else
    for id in $ids; do
        name="$(docker inspect -f '{{.Name}}' "$id")"
        role="$(docker inspect -f '{{index .Config.Labels "cyberlab.role"}}' "$id")"
        user="$(docker inspect -f '{{.Config.User}}' "$id")"
        ro="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id")"
        priv="$(docker inspect -f '{{.HostConfig.Privileged}}' "$id")"
        caps="$(docker inspect -f '{{.HostConfig.CapAdd}}' "$id")"
        net="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$id")"
        ports="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$id")"

        [ "$user" = "1000:1000" ] && ok "$name runs as $user" || bad "$name user=$user"
        [ "$ro" = "true" ] && ok "$name root filesystem is read-only" || bad "$name read-only=$ro"
        [ "$priv" = "false" ] && ok "$name is not privileged" || bad "$name privileged=$priv"
        [ "$caps" = "[]" ] && ok "$name has no added capabilities" || bad "$name caps=$caps"
        case "$ports" in
            *0.0.0.0*|*::*) bad "$name publishes on a wildcard address: $ports" ;;
            *) ok "$name port bindings are scoped: $ports" ;;
        esac
        if [ "$role" = "challenge" ]; then
            [ "$ports" = "{}" ] && ok "$name (challenge) has no published ports" \
                || bad "$name (challenge) has published ports: $ports"
            case " $net " in
                *" cyberlab_labs "*) ok "$name (challenge) is on the internal lab network" ;;
                *) bad "$name (challenge) is not on cyberlab_labs: $net" ;;
            esac
            case " $net " in
                *" cyberlab_edge "*) bad "$name (challenge) is on the edge network" ;;
                *) ok "$name (challenge) is not on the edge network" ;;
            esac
        elif [ "$role" = "forwarder" ]; then
            case " $net " in
                *" cyberlab_labs "*) ok "$name (relay) is on the internal lab network" ;;
                *) bad "$name (relay) is not on cyberlab_labs: $net" ;;
            esac
            case " $net " in
                *" cyberlab_edge "*) ok "$name (relay) is on the edge network" ;;
                *) bad "$name (relay) is not on cyberlab_edge: $net" ;;
            esac
        fi
        note "$name role=${role:-unknown} network(s): $net"
    done
fi

echo
echo "-- egress test (internal network) --"
network="${CYBERLAB_DOCKER_NETWORK:-cyberlab_labs}"
if docker network inspect "$network" >/dev/null 2>&1; then
    internal="$(docker network inspect -f '{{.Internal}}' "$network")"
    [ "$internal" = "true" ] && ok "$network is internal" || bad "$network internal=$internal"
    if docker run --rm --network "$network" alpine:3.21 \
        sh -c 'wget -T 3 -qO- https://example.com >/dev/null 2>&1 && exit 7 || exit 0' >/dev/null 2>&1; then
        ok "challenge network cannot reach the internet"
    else
        bad "challenge network can reach the internet"
    fi
else
    note "network $network does not exist"
fi

echo
echo "-- published host ports --"
ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | grep -vE '^(127\.|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
    && bad "some listeners are not loopback/private" \
    || ok "all listeners are loopback or private"

echo
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
