#!/usr/bin/env bash
# Build a release into release/ at the repository root:
#
#   x64dbg_vm_gateway-<gw-version>-py3-none-any.whl   host gateway with the plugin, the static-tool
#                                                     sync scripts and the demo samples bundled
#   x64dbg_vm_gateway-<gw-version>.tar.gz             its sdist (same content)
#   x64dbg-mcp-plugin-<version>.zip                   x64/plugins/*.dp64 and x32/plugins/*.dp32
#   SHA256SUMS
#
# Usage: scripts/build-release.sh   (from any directory)
#
# Needs Zig 0.14 ($ZIG, else zig on PATH, else ~/.local/share/zig/zig-linux-x86_64-0.14.0/zig)
# and uv on PATH. <gw-version> is host/pyproject.toml's version, <version> the plugin version in
# build.zig.zon. Every run starts over: release/ and the bundled copies in
# host/src/x64dbg_vm_gateway/data/plugin/ and data/samples/ are removed first, so a failed run leaves
# none of them behind; release/ only appears complete. The demo samples (`x64dbg-vm-gateway demo`)
# are the benign E2E programs of host/tests/vm/samples/hello.zig, built for x86_64 and x86 Windows
# by host/tests/vm/samples/build.sh; only the two .exe files are bundled. The sync scripts under
# static/<tool>/ are packaged
# from their committed copies in host/src/x64dbg_vm_gateway/data/static/; the run stops before
# building anything when a copy differs from static/ (copy the files again).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/host"
DIST="$ROOT/dist"
BUNDLE="$HOST/src/x64dbg_vm_gateway/data/plugin"
STATIC_COPY="$HOST/src/x64dbg_vm_gateway/data/static"
SAMPLES="$HOST/src/x64dbg_vm_gateway/data/samples"
SAMPLE_BUILD="$HOST/tests/vm/samples/build.sh"
SAMPLE_FILES=(e2e_sample_x86_64.exe e2e_sample_x86.exe)
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
rm -rf "$RELEASE" "$BUNDLE" "$SAMPLES"

log "checking the packaged static-tool scripts against static/"
"${PYTHON[@]}" -I - "$ROOT/static" "$STATIC_COPY" <<'PY'
import sys
from pathlib import Path

static, copy = Path(sys.argv[1]), Path(sys.argv[2])
repo = sorted(p.relative_to(static).as_posix() for p in static.glob("*/*.py") if p.parent.name != "tests")
packaged = sorted(p.relative_to(copy).as_posix() for p in copy.rglob("*.py") if "__pycache__" not in p.parts)
if not repo:
    sys.exit("build-release: error: no sync scripts under static/")
if repo != packaged:
    sys.exit(f"build-release: error: the static script lists differ: static/ has {repo}, "
             f"host/src/x64dbg_vm_gateway/data/static/ has {packaged}")
for rel in repo:
    if (static / rel).read_bytes() != (copy / rel).read_bytes():
        sys.exit(f"build-release: error: host/src/x64dbg_vm_gateway/data/static/{rel} differs from "
                 f"static/{rel}: copy it again")
PY

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

log "demo samples: $SAMPLE_BUILD (x86_64, x86)"
[ -f "$SAMPLE_BUILD" ] || die "$SAMPLE_BUILD not found"
mkdir -p "$TMP/samples"
# Zig leaves .pdb and .obj files next to the executables: build elsewhere, bundle the .exe files only
(cd "$TMP" && ZIG="$ZIG_BIN" bash "$SAMPLE_BUILD" "$TMP/samples" >&2) \
    || { rm -rf "$BUNDLE"; die "the demo sample build failed (host/tests/vm/samples/build.sh)"; }
mkdir -p "$SAMPLES"
for f in "${SAMPLE_FILES[@]}"; do
    [ -s "$TMP/samples/$f" ] || { rm -rf "$BUNDLE" "$SAMPLES"; die "the sample build did not produce $f"; }
    cp "$TMP/samples/$f" "$SAMPLES/"
done

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
# wheel really carries the plugin, the static scripts and the demo samples, and SHA256SUMS over
# everything in release/.
"${PYTHON[@]}" -I - "$DIST" "$STAGE" "$VERSION" "$STATIC_COPY" "${SAMPLE_FILES[*]}" "$X64_PLUGIN" \
    "$X32_PLUGIN" <<'PY'
import hashlib
import sys
import zipfile
from pathlib import Path

dist, release, version, static_copy = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
samples = sys.argv[5].split()
entries = sys.argv[6:]
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
for script in sorted(static_copy.rglob("*.py")):
    if "__pycache__" in script.parts:
        continue
    inside = f"x64dbg_vm_gateway/data/static/{script.relative_to(static_copy).as_posix()}"
    if inside not in names:
        sys.exit(f"build-release: error: {wheel.name} lacks {inside}")
for sample in samples:
    inside = f"x64dbg_vm_gateway/data/samples/{sample}"
    if inside not in names:
        sys.exit(f"build-release: error: {wheel.name} lacks {inside} (check [tool.hatch.build] artifacts)")

lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
         for p in sorted(release.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
(release / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
PY
mv "$STAGE" "$RELEASE"

log "release/ written:"
(cd "$RELEASE" && cat SHA256SUMS) >&2
