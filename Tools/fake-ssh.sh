#!/bin/bash
# A stand-in for /usr/bin/ssh, for Tools/connection-check.swift. Behaves
# according to the scenario in $FAKE_SSH_SCENARIO and counts its own runs in
# $FAKE_SSH_COUNTER, so a scenario can change behaviour between attempts.
for arg in "$@"; do [ "$arg" = "-G" ] && exit 0; done

n=$(( $(cat "$FAKE_SSH_COUNTER" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAKE_SSH_COUNTER"

hello='{"type":"hello","protocol":1,"agent":{"name":"rex-boing-agent","version":"0.1.0","os":"linux","arch":"amd64"},"host":{"hostname":"fake","logicalCores":2},"capabilities":["cpu"],"interval":1}'
sample() {
    printf '{"type":"sample","seq":%d,"t":%d,"interval":1,"detail":"vitals","resync":false,"cpu":{"total":0.5,"user":0.3,"system":0.2,"idle":0.5,"nice":0},"memory":{"total":100,"used":50}}\n' "$1" "$(( $(date +%s) * 1000 ))"
}
stream() {
    echo "$hello"
    for i in $(seq 1 "$1"); do sample "$i"; sleep 0.3; done
}

case "$FAKE_SSH_SCENARIO" in
    steady)
        stream 1000 ;;
    history)
        # An agent with a background agent behind it: the history line
        # comes between the hello and the first sample.
        echo "$hello"
        cat "$FAKE_SSH_HISTORY"
        echo
        for i in $(seq 1 1000); do sample "$i"; sleep 0.3; done ;;
    drop-then-recover)
        if [ "$n" -le 2 ]; then
            stream 2
            echo "Connection to fake closed by remote host." >&2
            exit 255
        fi
        stream 1000 ;;
    hang-then-recover)
        if [ "$n" -eq 1 ]; then
            stream 2
            sleep 600
        fi
        stream 1000 ;;
    refused)
        echo "rex@fake: Permission denied (publickey)." >&2
        exit 255 ;;
    host-key)
        echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" >&2
        echo "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @" >&2
        echo "Host key verification failed." >&2
        exit 255 ;;
    down-then-up)
        if [ "$n" -le 3 ]; then
            echo "ssh: connect to host fake port 22: Operation timed out" >&2
            exit 255
        fi
        stream 1000 ;;
esac
