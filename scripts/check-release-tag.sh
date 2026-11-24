#!/usr/bin/env bash
# Check that a release tag names the gateway version:
#
#   scripts/check-release-tag.sh v0.1.0    (from any directory)
#
# A release tag vX.Y.Z must equal "v" + the [project] version in host/pyproject.toml, which is
# the version of the wheel (x64dbg_vm_gateway-X.Y.Z-py3-none-any.whl) the release carries. The
# plugin zip keeps its own version, the plugin version in build.zig.zon. The release workflow
# runs this first, so a tag that does not match publishes nothing: bump host/pyproject.toml (and
# host/uv.lock) first, or tag the version it already has.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYPROJECT="$ROOT/host/pyproject.toml"

die() { echo "check-release-tag: error: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: scripts/check-release-tag.sh <tag>   (for example v0.1.0)"
TAG="$1"
[ -f "$PYPROJECT" ] || die "host/pyproject.toml not found under $ROOT"

if command -v python3 >/dev/null 2>&1 && python3 -I -c 'import tomllib' >/dev/null 2>&1; then
    PYTHON=(python3)
elif command -v uv >/dev/null 2>&1; then
    PYTHON=(uv run --no-project --quiet python)
else
    die "needs Python 3.11+ (tomllib) or uv to read host/pyproject.toml"
fi

VERSION="$("${PYTHON[@]}" -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    print(tomllib.load(f)["project"]["version"])
' "$PYPROJECT")"
[ -n "$VERSION" ] || die "host/pyproject.toml has no [project] version"

if [ "$TAG" != "v$VERSION" ]; then
    die "tag '$TAG' does not match the gateway version in host/pyproject.toml ($VERSION): tag v$VERSION, or change the version first (the plugin zip keeps the plugin version from build.zig.zon)"
fi
echo "check-release-tag: $TAG matches host/pyproject.toml version $VERSION" >&2
