#!/usr/bin/env bash
# Record one cold trunk call. Run once per mode and trial.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:?Specify plain or secure}
trial=${2:?Specify trial number}
case "$mode" in plain|secure) ;; *) exit 2 ;; esac
[[ "$trial" =~ ^[1-9][0-9]*$ ]] || exit 2
out=${3:-experiment}
mkdir -p "$out/captures" "$out/logs"
stem="$mode-$trial"
capfile="$out/captures/$stem.pcap"
logfile="$out/logs/$stem.log"
[[ ! -e "$capfile" && ! -e "$logfile" ]] || { echo "Trial already exists. Choose a fresh output directory." >&2; exit 1; }
compose=(./lab compose)
stamp() { date -u '+%Y-%m-%dT%H:%M:%S.%NZ'; }
./lab up "$mode"
for node in pbx-a pbx-b; do
    "${compose[@]}" exec -T "$node" asterisk -rx 'dialplan set global AFTER_CHECK_SECONDS 60'
    "${compose[@]}" exec -T "$node" asterisk -rx 'dialplan show globals' | grep -E 'AFTER_CHECK_SECONDS=60([[:space:]]|$)'
done
./lab status > "$out/logs/$stem.status"
filter='ip and host 172.30.76.10 and host 172.30.76.11 and (tcp or udp)'
# A shell waiting on the capture process writes a completion marker after flush.
"${compose[@]}" exec -d pbx-a sh -c '
    tcpdump -p -n -i eth0 -s 0 -U -w /tmp/trunk.pcap "$1" 2>/tmp/trunk.stats &
    pid=$!
    echo "$pid" >/tmp/trunk.pid
    wait "$pid" && touch /tmp/trunk.done
' capture "$filter"
stop_capture() { "${compose[@]}" exec -T pbx-a sh -c 'kill -INT "$(cat /tmp/trunk.pid)"' >/dev/null; }
trap stop_capture EXIT
for ((i=0; i<60; i++)); do
    if "${compose[@]}" exec -T pbx-a grep -q 'listening on eth0' /tmp/trunk.stats; then break; fi
    sleep .2
done
"${compose[@]}" exec -T pbx-a grep 'listening on eth0' /tmp/trunk.stats
{
    echo "call_command_started_utc=$(stamp)"
    ./lab call
    echo "call_command_finished_utc=$(stamp)"
} | tee "$logfile"
sleep 1
stop_capture
trap - EXIT
for ((i=0; i<50; i++)); do
    if "${compose[@]}" exec -T pbx-a test -f /tmp/trunk.done; then break; fi
    sleep .2
done
"${compose[@]}" exec -T pbx-a test -f /tmp/trunk.done
"${compose[@]}" cp pbx-a:/tmp/trunk.pcap "$capfile"
"${compose[@]}" exec -T pbx-a cat /tmp/trunk.stats | tee "$out/logs/$stem.tcpdump"
grep -qx '0 packets dropped by kernel' "$out/logs/$stem.tcpdump"
