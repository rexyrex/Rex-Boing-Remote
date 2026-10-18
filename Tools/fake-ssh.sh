#!/bin/bash
# A stand-in for /usr/bin/ssh, for Tools/connection-check.swift. Behaves
# according to the scenario in $FAKE_SSH_SCENARIO and counts its own runs in
# $FAKE_SSH_COUNTER, so a scenario can change behaviour between attempts.
# With $FAKE_SSH_LOG set, every run's arguments are appended to it, one line
# each; $FAKE_SSH_G_DELAY makes `ssh -G` take that many seconds.
[ -n "${FAKE_SSH_LOG:-}" ] && printf '%s\n' "$*" >> "$FAKE_SSH_LOG"
for arg in "$@"; do
    if [ "$arg" = "-G" ]; then
        [ -n "${FAKE_SSH_G_DELAY:-}" ] && sleep "$FAKE_SSH_G_DELAY"
        exit 0
    fi
done

n=$(( $(cat "$FAKE_SSH_COUNTER" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAKE_SSH_COUNTER"

hello='{"type":"hello","protocol":1,"agent":{"name":"rex-boing-agent","version":"0.1.0","os":"linux","arch":"amd64"},"host":{"hostname":"fake","logicalCores":2},"capabilities":["cpu"],"interval":1}'
# sample SEQ [T]: T in milliseconds, now if not given.
sample() {
    printf '{"type":"sample","seq":%d,"t":%d,"interval":1,"detail":"vitals","resync":false,"cpu":{"total":0.5,"user":0.3,"system":0.2,"idle":0.5,"nice":0},"memory":{"total":100,"used":50}}\n' "$1" "${2:-$(( $(date +%s) * 1000 ))}"
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
    history-after-drop)
        # The app saw a few samples two hours ago, then went away; when it
        # comes back, the background agent has kept the time between.
        if [ "$n" -eq 1 ]; then
            echo "$hello"
            then=$(( ($(date +%s) - 7200) * 1000 ))
            for i in 1 2 3 4; do sample "$i" $(( then + i * 2000 )); sleep 0.1; done
            echo "Connection to fake closed by remote host." >&2
            exit 255
        fi
        echo "$hello"
        cat "$FAKE_SSH_HISTORY"
        echo
        for i in $(seq 1 1000); do sample "$i"; sleep 0.3; done ;;
    noisy-drop)
        # A login that grumbles on every connect (a .zshenv sourcing a file
        # that isn't there), then a session that drops like any other.
        echo "/home/rex/.zshenv:3: no such file or directory: /opt/tool/env.sh" >&2
        if [ "$n" -eq 1 ]; then
            stream 3
            echo "Connection to fake closed by remote host." >&2
            exit 255
        fi
        stream 1000 ;;
    one-sample-crash)
        # An agent that dies right after its first sample, every time.
        echo "$hello"
        sample 1
        echo "rex-boing-agent: panic: runtime error" >&2
        exit 2 ;;
    old-protocol)
        echo '{"type":"hello","protocol":0,"agent":{"name":"rex-boing-agent","version":"0.0.1","os":"linux","arch":"amd64"}}'
        for i in $(seq 1 1000); do sample "$i"; sleep 0.3; done ;;
    notice-then-fixed)
        # The first session's agent has a problem to report; by the second,
        # it was fixed.
        if [ "$n" -eq 1 ]; then
            echo "$hello"
            sample 1
            echo '{"type":"notice","code":"rapl-denied","message":"CPU power needs read access to /sys/class/powercap."}'
            sample 2
            echo "Connection to fake closed by remote host." >&2
            exit 255
        fi
        stream 1000 ;;
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
            # exec, so the watchdog's signal ends the sleep too instead of
            # leaving it running on its own for ten minutes.
            exec sleep 600
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
