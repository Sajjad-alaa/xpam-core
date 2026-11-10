#!/bin/bash
# XPAM core: container entry point. `start web`, `start task`, `start all` (default), or `bash`/`sleep` for maintenance.
# Paths are relative to the image's working directory (the installation folder).

cleanup() {
    local pids
    pids=$(jobs -p)
    if [[ -n "${pids}" ]]; then
        kill ${pids} >/dev/null 2>&1
    fi
}

action="${1-start}"
service="${2-all}"

trap cleanup EXIT

rm -f tmp/*.pid

if [[ "$action" == "bash" || "$action" == "sh" ]]; then
    bash
elif [[ "$action" == "sleep" ]]; then
    echo "Sleep 365 days"
    sleep 365d
else
    which cron &>/dev/null && [[ ! -f /var/run/crond.pid ]] && cron || echo ""
    python xpam "${action}" "${service}"
fi
