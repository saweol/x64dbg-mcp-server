#!/usr/bin/env bash
# Build a release into release/ at the repository root:
#
#   x64dbg_vm_gateway-<gw-version>-py3-none-any.whl   host gateway with the plugin bundled
#   x64dbg_vm_gateway-<gw-version>.tar.gz             its sdist (same content)
#   x64dbg-mcp-plugin-<version>.zip                   x64/plugins/*.dp64 and x32/plugins/*.dp32
#   SHA256SUMS
#
# Usage: scripts/build-release.sh   (from any directory)
#
# Needs Zig 0.14 ($ZIG, else zig on PATH, else ~/.local/share/zig/zig-linux-x86_64-0.14.0/zig)
# and uv on PATH. <version> is the plugin version in build.zig.zon. Every run starts over:
# release/ and the bundled copy in host/src/x64dbg_vm_gateway/data/plugin/ are removed first,
# so a failed run leaves neither behind; release/ only appears complete.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/host"
DIST="$ROOT/dist"
BUNDLE="$HOST/src/x64dbg_vm_gateway/data/plugin"
RELEASE="$ROOT/release"
X64_PLUGIN="x64/plugins/x64dbg-MCP-Server.dp64"
X32_PLUGIN="x32/plugins/x64dbg-MCP-Server.dp32"

log() { echo "build-release: $*" >&2; }
die() { echo "build-release: error: $*" >&2; exit 1; }

find_zig() {  # an absolute path: the build runs from the repository root
    if [ -n "${ZIG:-}" ]; then
        case "$ZIG" in
            */*)
                [ -f "$ZIG" ] && [ -x "$ZIG" ] || die "ZIG=$ZIG is not an executable"
                echo "$(cd "$(dirname "$ZIG")" && pwd)/$(basename "$ZIG")"
                ;;
            *)
                command -v "$ZIG" >/dev/null 2>&1 || die "ZIG=$ZIG is not an executable"
                command -v "$ZIG"
                ;;
        esac
        return
    fi
    if command -v zig >/dev/null 2>&1; then
        command -v zig
        return
    fi
    local fallback="${HOME:-}/.local/share/zig/zig-linux-x86_64-0.14.0/zig"
    [ -x "$fallback" ] || die "Zig 0.14 not found: set ZIG=/path/to/zig, put zig on PATH, or unpack Zig to $fallback"
    echo "$fallback"
}

ZIG_BIN="$(find_zig)"
command -v uv >/dev/null 2>&1 || die "uv not found on PATH (https://docs.astral.sh/uv/)"
if command -v python3 >/dev/null 2>&1; then
    PYTHON=(python3)
else
    PYTHON=(uv run --no-project --quiet python)
fi

VERSION="$(sed -n 's/^[[:space:]]*\.version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/build.zig.zon" | head -n 1)"
[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || die "no usable .version in build.zig.zon (got '$VERSION')"
ZIG_VERSION="$("$ZIG_BIN" version)"
case "$ZIG_VERSION" in
    0.14.*) ;;
    *) log "warning: Zig $ZIG_VERSION; the plugin is built and tested with 0.14.0" ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/release"
rm -rf "$RELEASE" "$BUNDLE"

log "plugin $VERSION: zig build -Doptimize=ReleaseSafe --prefix dist (Zig $ZIG_VERSION)"
(cd "$ROOT" && "$ZIG_BIN" build -Doptimize=ReleaseSafe --prefix "$DIST")
for f in "$X64_PLUGIN" "$X32_PLUGIN"; do
    [ -s "$DIST/$f" ] || die "the Zig build did not produce dist/$f"
done

log "bundling the plugin into the package"
mkdir -p "$BUNDLE/x64" "$BUNDLE/x32"
cp "$DIST/$X64_PLUGIN" "$BUNDLE/x64/"
cp "$DIST/$X32_PLUGIN" "$BUNDLE/x32/"
printf '%s\n' "$VERSION" > "$BUNDLE/VERSION"

log "uv build (sdist, then the wheel from it)"
(cd "$HOST" && uv build --out-dir "$TMP/out")

mkdir -p "$STAGE"
shopt -s nullglob
wheels=("$TMP"/out/*.whl)
sdists=("$TMP"/out/*.tar.gz)
shopt -u nullglob
[ "${#wheels[@]}" -eq 1 ] || die "expected one wheel from uv build, got ${#wheels[@]}"
cp "${wheels[0]}" "$STAGE/"
if [ "${#sdists[@]}" -gt 0 ]; then
    cp "${sdists[@]}" "$STAGE/"
fi

# The plugin zip (fixed timestamps: the same build gives the same zip), a check that the
# wheel really carries the plugin, and SHA256SUMS over everything in release/.
"${PYTHON[@]}" -I - "$DIST" "$STAGE" "$VERSION" "$X64_PLUGIN" "$X32_PLUGIN" <<'PY'
import hashlib
import sys
import zipfile
from pathlib import Path

dist, release, version = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
entries = sys.argv[4:]
with zipfile.ZipFile(release / f"x64dbg-mcp-plugin-{version}.zip", "w") as zf:
    for name in entries:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, (dist / name).read_bytes())

(wheel,) = release.glob("*.whl")
with zipfile.ZipFile(wheel) as zf:
    names = set(zf.namelist())
for name in entries:
    arch, _, file = name.split("/")
    inside = f"x64dbg_vm_gateway/data/plugin/{arch}/{file}"
    if inside not in names:
        sys.exit(f"build-release: error: {wheel.name} lacks {inside} (check [tool.hatch.build] artifacts)")

lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
         for p in sorted(release.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
(release / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
PY
mv "$STAGE" "$RELEASE"

log "release/ written:"
(cd "$RELEASE" && cat SHA256SUMS) >&2
