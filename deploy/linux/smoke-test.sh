#!/usr/bin/env bash
# Runs the programs of a Linux package on a machine without .NET: wafctl, then the gateway on spare ports with a
# temporary data folder, until its admin UI answers. Changes nothing on the machine. The release workflow runs it in
# a plain Ubuntu container (linux-arm64 under QEMU), which is how it proves that no .NET runtime is needed.
#
#   deploy/linux/smoke-test.sh artifacts/linux/wafgateway-linux-arm64
#
# Needs curl, and the libraries .NET uses from the system: libicu and libssl (present on Ubuntu Server).
set -euo pipefail

PACKAGE="$(cd "${1:?usage: smoke-test.sh <package folder>}" && pwd)"
TIMEOUT="${SMOKE_TIMEOUT:-300}"   # seconds; emulated arm64 starts slowly
HTTP_PORT=18080
ADMIN_PORT=18900
WORK="$(mktemp -d)"
gateway=

cleanup() {
    [ -z "$gateway" ] || kill "$gateway" 2>/dev/null || true
    [ -z "$gateway" ] || wait "$gateway" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; [ ! -f "$WORK/gateway.log" ] || tail -n 50 "$WORK/gateway.log" >&2; exit 1; }

printf '=== %s, %s\n' "$(. /etc/os-release && echo "$PRETTY_NAME")" "$(uname -m)"
if command -v dotnet >/dev/null 2>&1; then
    echo "Note: dotnet is installed here ($(command -v dotnet)); the test does not prove the package runs without it."
else
    echo "No .NET installed (no dotnet on the PATH)."
fi
[ -f "$PACKAGE/PACKAGE" ] && sed 's/^/Package: /' "$PACKAGE/PACKAGE"
chmod +x "$PACKAGE/WafGateway" "$PACKAGE/wafctl" 2>/dev/null || true

echo '=== wafctl'
"$PACKAGE/wafctl" --help >/dev/null || fail "wafctl --help did not run."
echo "wafctl runs."

echo '=== Gateway'
export DOTNET_ENVIRONMENT=Production
export Gateway__Storage__DataDirectory="$WORK/data"
export Gateway__Storage__ConfigDirectory="$WORK/config"
export Gateway__Endpoints__HttpPort=$HTTP_PORT
export Gateway__Endpoints__HttpsPort=18443
export Gateway__Endpoints__AdminPort=$ADMIN_PORT
mkdir -p "$WORK/config"
(cd "$PACKAGE" && exec ./WafGateway) >"$WORK/gateway.log" 2>&1 &
gateway=$!

started=$SECONDS
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$ADMIN_PORT/healthz" || true)" = 200 ]; do
    kill -0 "$gateway" 2>/dev/null || fail "The gateway stopped while starting."
    [ $((SECONDS - started)) -lt "$TIMEOUT" ] || fail "The admin UI did not answer within $TIMEOUT seconds."
    sleep 2
done
echo "The admin UI answers after $((SECONDS - started)) s."

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$HTTP_PORT/" || true)"
[ "$code" != 000 ] || fail "The public port $HTTP_PORT does not answer."
echo "The public port answers (HTTP $code)."
[ -f "$WORK/data/config.db" ] || fail "config.db was not created in the data folder."
echo "config.db created."

kill "$gateway"
wait "$gateway" 2>/dev/null || true
gateway=
echo 'Smoke test passed.'
