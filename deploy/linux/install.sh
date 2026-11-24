#!/usr/bin/env bash
# Installs WAF Gateway as a systemd service on Ubuntu (Raspberry Pi: arm64, or x64), or removes it.
#
#   sudo ./install.sh                 install or upgrade, and start the service
#   sudo ./install.sh --ufw           also allow 80/tcp and 443/tcp in UFW
#   sudo ./install.sh --no-start      install or upgrade without starting
#   sudo ./install.sh --memory-max 512M   limit the service's memory (Raspberry Pi); --memory-max none removes it
#   sudo ./install.sh --uninstall     remove the service and program files; keep data and configuration
#   sudo ./install.sh --uninstall --purge   also delete data, configuration and the service user
#
# The service runs as the dedicated system user "wafgateway" (no login, no home folder of its own), with only the
# CAP_NET_BIND_SERVICE capability (ports 80 and 443) and the hardening of wafgateway.service. Data lives in
# /var/lib/wafgateway, optional settings in /etc/wafgateway/appsettings.json, the program in /opt/wafgateway.
set -euo pipefail

SERVICE=wafgateway
SERVICE_USER=wafgateway
PREFIX=/opt/wafgateway
DATA_DIR=/var/lib/wafgateway
CONFIG_DIR=/etc/wafgateway
UNIT_FILE=/etc/systemd/system/$SERVICE.service
WAFCTL_LINK=/usr/local/bin/wafctl
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION=install
PURGE=0
START=1
UFW=0
MEMORY_MAX=
MEMORY_DROPIN=/etc/systemd/system/$SERVICE.service.d/memory.conf

step() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE="$(cd "$2" && pwd)"; shift 2 ;;
        --uninstall) ACTION=uninstall; shift ;;
        --purge) PURGE=1; shift ;;
        --no-start) START=0; shift ;;
        --ufw) UFW=1; shift ;;
        --memory-max) MEMORY_MAX="${2:-}"; shift 2 || { printf 'Missing size after --memory-max\n\n' >&2; usage 2; } ;;
        -h|--help) usage 0 ;;
        *) printf 'Unknown option: %s\n\n' "$1" >&2; usage 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "Run the installer as root: sudo $0 $*"
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail "systemd is not running on this machine."
[ "$PURGE" -eq 0 ] || [ "$ACTION" = uninstall ] || fail "--purge is only valid with --uninstall."
case "$MEMORY_MAX" in
    ''|none) ;;
    *) printf '%s' "$MEMORY_MAX" | grep -Eq '^[1-9][0-9]*[KMG]?$' \
        || fail "--memory-max takes a size such as 512M or 1G, or none (was: $MEMORY_MAX)." ;;
esac

# The effective Gateway:Endpoints:<name> (built-in appsettings.json, overridden by the one in /etc/wafgateway).
endpoint_setting() {
    local name="$1" value="$2" file found
    for file in "$PREFIX/appsettings.json" "$CONFIG_DIR/appsettings.json"; do
        [ -f "$file" ] || continue
        found="$(tr -d '\r' < "$file" | grep -o "\"$name\"[[:space:]]*:[[:space:]]*[0-9]\+" | grep -o '[0-9]\+$' | tail -n 1 || true)"
        [ -z "$found" ] || value="$found"
    done
    printf '%s' "$value"
}

# Programs (other than the gateway) listening on TCP port $1.
port_listeners() {
    ss -Hltnp "sport = :$1" 2>/dev/null | grep -v '"WafGateway"' || true
}

ufw_rules() {
    local verb="$1" port
    command -v ufw >/dev/null 2>&1 || { warn "UFW is not installed; nothing to $verb."; return; }
    for port in "${@:2}"; do
        if [ "$verb" = allow ]; then
            ufw allow "$port/tcp" comment 'WAF Gateway' >/dev/null
            note "UFW: $port/tcp allowed."
        else
            ufw delete allow "$port/tcp" >/dev/null 2>&1 && note "UFW: rule for $port/tcp removed." || true
        fi
    done
}

# ---------------------------------------------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------------------------------------------
if [ "$ACTION" = uninstall ]; then
    step "Removing WAF Gateway"
    http_port="$(endpoint_setting HttpPort 80)"
    https_port="$(endpoint_setting HttpsPort 443)"
    if systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 && [ -f "$UNIT_FILE" ]; then
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
        rm -f "$UNIT_FILE"
        rm -rf "/etc/systemd/system/$SERVICE.service.d"
        systemctl daemon-reload
        note "Service removed."
    fi
    [ "$UFW" -eq 0 ] || ufw_rules delete "$http_port" "$https_port"
    rm -f "$WAFCTL_LINK"
    rm -rf "$PREFIX"
    note "$PREFIX removed."
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$DATA_DIR" "$CONFIG_DIR"
        note "$DATA_DIR and $CONFIG_DIR deleted."
        if id "$SERVICE_USER" >/dev/null 2>&1; then
            userdel "$SERVICE_USER" >/dev/null 2>&1 || warn "Could not remove the user $SERVICE_USER."
            getent group "$SERVICE_USER" >/dev/null 2>&1 && groupdel "$SERVICE_USER" >/dev/null 2>&1 || true
            note "User $SERVICE_USER removed."
        fi
    else
        note "Kept: $DATA_DIR (configuration, accounts, request log, keys) and $CONFIG_DIR. Delete them with --uninstall --purge."
    fi
    step "WAF Gateway is removed."
    exit 0
fi

# ---------------------------------------------------------------------------------------------------------------
# Install or upgrade
# ---------------------------------------------------------------------------------------------------------------
for file in WafGateway wafctl appsettings.json wafgateway.service; do
    [ -f "$SOURCE/$file" ] || fail "$file is not in $SOURCE. Run the installer from the extracted package, or pass --source."
done

# The package must match this machine (linux-arm64 on a Raspberry Pi, linux-x64 on a PC or server).
machine="$(uname -m)"
case "$machine" in
    aarch64|arm64) rid=linux-arm64 ;;
    x86_64|amd64) rid=linux-x64 ;;
    *) fail "Unsupported processor architecture: $machine (supported: aarch64, x86_64)." ;;
esac
if [ -f "$SOURCE/PACKAGE" ]; then
    package_rid="$(sed -n 's/^runtime=//p' "$SOURCE/PACKAGE" | tr -d '\r')"
    # WAFGATEWAY_ALLOW_FOREIGN_ARCH=1 is for tests only: an arm64 package on an x64 machine that runs it with QEMU.
    [ "$package_rid" = "$rid" ] || [ "${WAFGATEWAY_ALLOW_FOREIGN_ARCH:-0}" = 1 ] \
        || fail "This package is for $package_rid, but this machine needs $rid."
fi

if systemctl is-enabled "$SERVICE" >/dev/null 2>&1 || [ -f "$UNIT_FILE" ]; then
    step "Upgrading WAF Gateway in $PREFIX"
    systemctl stop "$SERVICE" 2>/dev/null || true
else
    step "Installing WAF Gateway in $PREFIX"
fi

# 1. The service user: a system account without login shell.
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin \
        --comment "WAF Gateway" "$SERVICE_USER"
    note "System user $SERVICE_USER created (no login)."
fi

# 2. Program files: owned by root, read-only for the service; replaced as a whole.
if [ "$SOURCE" != "$PREFIX" ]; then
    staging="$PREFIX.new"
    rm -rf "$staging"
    mkdir -p "$staging"
    cp -R "$SOURCE/." "$staging/"
    chown -R root:root "$staging"
    find "$staging" -type d -exec chmod 0755 {} +
    find "$staging" -type f -exec chmod 0644 {} +
    chmod 0755 "$staging/WafGateway" "$staging/wafctl" "$staging/install.sh" 2>/dev/null || chmod 0755 "$staging/WafGateway" "$staging/wafctl"
    rm -rf "$PREFIX.old"
    [ ! -d "$PREFIX" ] || mv "$PREFIX" "$PREFIX.old"
    mv "$staging" "$PREFIX"
    rm -rf "$PREFIX.old"
    note "Program files copied to $PREFIX."
fi

# 3. wafctl on the PATH; run as root it switches to the service user, so files it writes stay the service's.
cat > "$WAFCTL_LINK" <<EOF
#!/bin/sh
# WAF Gateway recovery tool. Run with sudo; it works as the service user $SERVICE_USER on $DATA_DIR.
if [ "\$(id -u)" -eq 0 ]; then
    exec runuser -u $SERVICE_USER -- $PREFIX/wafctl "\$@"
fi
exec $PREFIX/wafctl "\$@"
EOF
chmod 0755 "$WAFCTL_LINK"

# 4. Data and configuration folders (systemd also creates them; existing files are handed to the service user).
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
note "Data: $DATA_DIR (only $SERVICE_USER). Settings: $CONFIG_DIR (read-only for the service)."

# 5. The systemd unit.
sed "s|@PREFIX@|$PREFIX|g" "$SOURCE/wafgateway.service" > "$UNIT_FILE"
chmod 0644 "$UNIT_FILE"

# Memory limit, in a drop-in so upgrades keep it. .NET reads the limit and keeps its heap below it (75%).
if [ "$MEMORY_MAX" = none ]; then
    rm -f "$MEMORY_DROPIN"
    note "Memory limit removed."
elif [ -n "$MEMORY_MAX" ]; then
    mkdir -p "$(dirname "$MEMORY_DROPIN")"
    printf '# Written by install.sh --memory-max.\n[Service]\nMemoryMax=%s\n' "$MEMORY_MAX" > "$MEMORY_DROPIN"
    chmod 0644 "$MEMORY_DROPIN"
    note "Memory limit: $MEMORY_MAX (change with --memory-max, remove with --memory-max none)."
fi
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
note "Service $SERVICE enabled (starts at boot, restarts after a failure)."

# 6. Firewall: only on request (--ufw); otherwise a note.
http_port="$(endpoint_setting HttpPort 80)"
https_port="$(endpoint_setting HttpsPort 443)"
admin_port="$(endpoint_setting AdminPort 8900)"
if [ "$UFW" -eq 1 ]; then
    ufw_rules allow "$http_port" "$https_port"
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    note "UFW is active: allow the public ports with: sudo ufw allow $http_port/tcp && sudo ufw allow $https_port/tcp (or run the installer with --ufw)."
fi
note "The admin port $admin_port listens on 127.0.0.1 and ::1 only; never open it in the firewall."

# 7. Start, unless another program holds the public ports (nginx, Apache, ...).
busy="$(port_listeners "$http_port"; port_listeners "$https_port")"
if [ "$START" -eq 0 ]; then
    step "Installed; not started (--no-start). Start it with: sudo systemctl start $SERVICE"
elif [ -n "$busy" ]; then
    step "Installed, but not started: the public ports are in use"
    printf '%s\n' "$busy"
    note "Stop or move that program (for example a web server you now add as a route), then: sudo systemctl start $SERVICE"
else
    # Type=notify: start returns when the listeners are up, or fails when the gateway exits first.
    healthy=0
    if systemctl start "$SERVICE"; then
        for _ in $(seq 1 60); do
            # Not running any more (failed, or waiting to restart after a crash): stop waiting.
            [ "$(systemctl show -p SubState --value "$SERVICE")" = running ] || break
            if ! command -v curl >/dev/null 2>&1; then healthy=1; break; fi
            if curl -fs -o /dev/null --max-time 5 "http://127.0.0.1:$admin_port/healthz"; then healthy=1; break; fi
            sleep 1
        done
    fi
    if [ "$healthy" -eq 1 ]; then
        step "WAF Gateway is running"
    else
        warn "The service did not start. Its last log lines (more with: journalctl -u $SERVICE -n 100 --no-pager):"
        journalctl -u "$SERVICE" -n 20 --no-pager >&2 || true
    fi
fi

note "Admin UI (on this machine only): http://localhost:$admin_port - the first visit creates the admin account."
note "From another computer: ssh -L $admin_port:localhost:$admin_port <user>@<this machine>, then open http://localhost:$admin_port."
note "Logs: journalctl -u $SERVICE    Recovery tool: sudo wafctl status"
