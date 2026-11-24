#!/usr/bin/env bash
# End-to-end check of install.sh on this machine: install, service user, capabilities and hardening, folders and
# permissions, wafctl, upgrade, uninstall and purge. Changes the machine while it runs and removes everything again
# at the end (data included): use it on CI runners, containers, test machines or a test Raspberry Pi only.
#
#   sudo deploy/linux/test-install.sh artifacts/linux/wafgateway-linux-arm64
set -uo pipefail

PACKAGE="$(cd "${1:?usage: test-install.sh <package folder>}" && pwd)"
INSTALLER="$PACKAGE/install.sh"
failures=0

check() {
    local description="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '  [ok]   %s\n' "$description"
    else
        printf '  [FAIL] %s\n' "$description"
        failures=$((failures + 1))
    fi
}

run_installer() {
    printf -- '--- install.sh %s\n' "$*"
    bash "$INSTALLER" "$@"
}

status_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1" || true; }
main_pid() { systemctl show -p MainPID --value wafgateway; }
proc_field() { awk -v key="$1:" '$1 == key { print $2 }' "/proc/$(main_pid)/status"; }
mode_owner() { stat -c '%a %U:%G' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is needed for the checks." >&2; exit 2; }
printf '=== %s, %s\n' "$(. /etc/os-release && echo "$PRETTY_NAME")" "$(uname -m)"

echo '=== Install'
run_installer || failures=$((failures + 1))

check 'the service is active' systemctl is-active --quiet wafgateway
check 'it starts at boot' systemctl is-enabled --quiet wafgateway
check 'the user wafgateway is a system user without login' sh -c '[ "$(getent passwd wafgateway | cut -d: -f7)" = /usr/sbin/nologin ] && [ "$(id -u wafgateway)" -lt 1000 ]'
check 'the gateway runs as wafgateway, not root' sh -c "[ \"\$(ps -o user= -p $(main_pid))\" = wafgateway ]"
# CAP_NET_BIND_SERVICE is bit 10: 0x400. Effective, permitted and bounding sets hold nothing else.
check 'its only capability is CAP_NET_BIND_SERVICE' sh -c "[ \"$(proc_field CapEff)\" = 0000000000000400 ] && [ \"$(proc_field CapBnd)\" = 0000000000000400 ]"
check 'it cannot gain privileges (NoNewPrivileges)' sh -c "[ \"$(proc_field NoNewPrivs)\" = 1 ]"
check 'the admin UI answers on 127.0.0.1:8900' sh -c "[ \"$(status_code http://127.0.0.1:8900/healthz)\" = 200 ]"
check 'the admin port listens on loopback only' sh -c "! ss -Hltn 'sport = :8900' | awk '{print \$4}' | grep -vqE '^(127\.0\.0\.1|\[::1\]):8900$'"
check 'the gateway answers on port 80' sh -c "[ \"$(status_code http://127.0.0.1/)\" != 000 ]"
check 'the program is in /opt/wafgateway, owned by root' sh -c '[ "$(stat -c %U /opt/wafgateway/WafGateway)" = root ] && [ -x /opt/wafgateway/WafGateway ]'
check 'the data folder is 0750 and owned by wafgateway' sh -c '[ "$(stat -c "%a %U" /var/lib/wafgateway)" = "750 wafgateway" ]'
check 'config.db was created there' test -f /var/lib/wafgateway/config.db
check 'other users cannot read config.db' sh -c '[ "$(( 0$(stat -c %a /var/lib/wafgateway/config.db) & 7 ))" -eq 0 ]'
check 'the settings folder is read-only for the service' sh -c '[ "$(stat -c "%a %U:%G" /etc/wafgateway)" = "750 root:wafgateway" ]'
check 'the file system is read-only for it except its data folder (ProtectSystem=strict)' sh -c '[ "$(systemctl show -p ProtectSystem --value wafgateway)" = strict ]'
check 'home folders are hidden and /tmp is private' sh -c '[ "$(systemctl show -p ProtectHome --value wafgateway)" = yes ] && [ "$(systemctl show -p PrivateTmp --value wafgateway)" = yes ]'
check 'its writable folder is /var/lib/wafgateway' sh -c "grep -q ' /var/lib/wafgateway ' /proc/$(main_pid)/mountinfo && grep ' / / ' /proc/$(main_pid)/mountinfo | grep -q ' ro[ ,]'"
check 'wafctl works through sudo (as the service user)' sh -c 'wafctl status | grep -q "Remote admin:"'
check 'files written by wafctl belong to the service user' sh -c '[ -z "$(find /var/lib/wafgateway -not -user wafgateway)" ]'

echo '=== Hardening (systemd-analyze security)'
systemd-analyze security wafgateway --no-pager 2>/dev/null | tail -n 1 || true
check 'systemd rates the exposure as OK or better' sh -c "systemd-analyze security wafgateway --no-pager 2>/dev/null | tail -n 1 | grep -qE 'OK|SAFE'"

echo '=== Upgrade (run again)'
size_before="$(stat -c %s /var/lib/wafgateway/config.db)"
run_installer || failures=$((failures + 1))
check 'the service is active again' systemctl is-active --quiet wafgateway
check 'the admin UI answers again' sh -c "[ \"$(status_code http://127.0.0.1:8900/healthz)\" = 200 ]"
check 'the configuration is kept' sh -c "[ \"\$(stat -c %s /var/lib/wafgateway/config.db)\" -ge $size_before ]"

echo '=== Uninstall'
run_installer --uninstall || failures=$((failures + 1))
check 'the service is removed' sh -c '! systemctl cat wafgateway'
check 'the program folder is removed' test ! -e /opt/wafgateway
check 'wafctl is removed' test ! -e /usr/local/bin/wafctl
check 'the data folder is kept' test -f /var/lib/wafgateway/config.db

run_installer --uninstall --purge || failures=$((failures + 1))
check 'with --purge the data and settings folders are deleted' sh -c '[ ! -e /var/lib/wafgateway ] && [ ! -e /etc/wafgateway ]'
check 'with --purge the user is removed' sh -c '! id wafgateway'

if [ "$failures" -gt 0 ]; then
    printf '%d check(s) failed.\n' "$failures"
    exit 1
fi
echo 'All checks passed.'
