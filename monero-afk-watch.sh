#!/bin/sh
set -eu

USER_NAME="john"
THRESHOLD_SEC=600
STOP_DELAY_SEC=120
SLEEP_SEC=15
SERVICES="monerod monero-wallet-rpc monero-alerter"

log() {
    printf '%s %s\n' "$(date -Is)" "$*"
}

session_id() {
    loginctl show-user "$USER_NAME" -p Display --value 2>/dev/null || true
}

idle_seconds() {
    sid="$(session_id)"
    [ -n "$sid" ] || return 1

    idle_hint="$(loginctl show-session "$sid" -p IdleHint --value 2>/dev/null || true)"
    [ "$idle_hint" = "yes" ] || return 2

    idle_since_us="$(loginctl show-session "$sid" -p IdleSinceHintMonotonic --value 2>/dev/null || true)"
    [ -n "$idle_since_us" ] || return 3

    now_us="$(awk '{printf "%.0f", $1 * 1000000}' /proc/uptime)"
    awk -v now="$now_us" -v then="$idle_since_us" 'BEGIN { diff = (now - then) / 1000000; if (diff < 0) diff = 0; printf "%.0f", diff }'
}

services_active() {
    systemctl is-active --quiet $SERVICES
}

start_services() {
    log "starting Monero services"
    systemctl start $SERVICES
}

stop_services() {
    log "stopping Monero services"
    systemctl stop $SERVICES
}

active_since=0

while true; do
    if idle_sec="$(idle_seconds 2>/dev/null)"; then
        if [ "$idle_sec" -ge "$THRESHOLD_SEC" ]; then
            active_since=0
            if ! services_active; then
                log "idle for ${idle_sec}s, starting services"
                start_services
            fi
        else
            if services_active; then
                if [ "$active_since" -eq 0 ]; then
                    active_since="$(date +%s)"
                fi
                now="$(date +%s)"
                active_for=$((now - active_since))
                if [ "$active_for" -ge "$STOP_DELAY_SEC" ]; then
                    log "activity sustained for ${active_for}s, stopping services"
                    active_since=0
                    stop_services
                fi
            else
                active_since=0
            fi
        fi
    else
        active_since=0
    fi
    sleep "$SLEEP_SEC"
done
