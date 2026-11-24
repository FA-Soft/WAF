#!/usr/bin/env bash
# Builds the Linux package: the gateway and wafctl (self-contained, single file) with install.sh and the systemd unit,
# as a folder and a .tar.gz.
#
#   deploy/linux/build-package.sh                    linux-arm64 (Raspberry Pi), in artifacts/linux
#   deploy/linux/build-package.sh linux-x64          for x64 machines
#   deploy/linux/build-package.sh linux-arm64 out    in another folder
#
# Runs wherever the .NET SDK does (Linux, macOS, Windows with Git Bash): the build cross-compiles.
set -euo pipefail

RUNTIME="${1:-linux-arm64}"
REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${2:-$REPOSITORY/artifacts/linux}"
CONFIGURATION="${CONFIGURATION:-Release}"
PACKAGE="$OUTPUT/wafgateway-$RUNTIME"

case "$RUNTIME" in
    linux-arm64|linux-x64) ;;
    *) echo "Unsupported runtime: $RUNTIME (linux-arm64 or linux-x64)" >&2; exit 2 ;;
esac

rm -rf "$PACKAGE" "$PACKAGE.tar.gz"
mkdir -p "$PACKAGE"
for project in Waf.Host Waf.Cli; do
    echo "==> Publishing $project ($RUNTIME)"
    dotnet publish "$REPOSITORY/src/$project/$project.csproj" -c "$CONFIGURATION" -r "$RUNTIME" --self-contained \
        -p:PublishSingleFile=true -o "$PACKAGE" --nologo
done

# Not used by the service: debug symbols, Development settings and IIS hosting files.
rm -f "$PACKAGE"/*.pdb "$PACKAGE/appsettings.Development.json" "$PACKAGE/web.config" "$PACKAGE/aspnetcorev2_inprocess.dll"

cp "$REPOSITORY/deploy/linux/install.sh" "$REPOSITORY/deploy/linux/wafgateway.service" "$PACKAGE/"
printf 'runtime=%s\n' "$RUNTIME" > "$PACKAGE/PACKAGE"
chmod 0755 "$PACKAGE/install.sh" "$PACKAGE/WafGateway" "$PACKAGE/wafctl" 2>/dev/null || true

# Owned by root in the archive. A build on Windows cannot record execute permissions; install.sh sets them.
tar -C "$OUTPUT" --owner=0 --group=0 --numeric-owner -czf "$PACKAGE.tar.gz" "wafgateway-$RUNTIME"
echo "==> Package: $PACKAGE"
echo "    Archive: $PACKAGE.tar.gz"
