#!/usr/bin/env bash
# =============================================================================
# SSL Manager — deployment preflight matrix driver (host side)
#
# Runs deploy/test/preflight.sh inside clean Ubuntu containers across the
# supported LTS releases and CPU architectures, reporting pass/fail per combo.
#
# Usage:
#   deploy/test/run-matrix.sh                 # defaults below
#   IMAGES="ubuntu:26.04" run-matrix.sh       # one distro
#   PLATFORMS="linux/arm64" run-matrix.sh     # native only (skip emulation)
#
# Defaults cover both currently-supported Ubuntu LTS releases on both arches.
# amd64 on Apple Silicon runs under emulation (slower) but mirrors x86_64 prod.
# =============================================================================
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGES="${IMAGES:-ubuntu:24.04 ubuntu:26.04}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64}"

docker info >/dev/null 2>&1 || { echo "Docker daemon is not running. Start Docker Desktop and retry."; exit 1; }

declare -a RESULTS
fail=0

for img in ${IMAGES}; do
    for plat in ${PLATFORMS}; do
        echo
        echo "############################################################"
        echo "# ${img}   ${plat}"
        echo "############################################################"
        if docker run --rm --platform "${plat}" \
            -v "${REPO}:/src:ro" \
            "${img}" bash /src/deploy/test/preflight.sh; then
            RESULTS+=("PASS  ${img}  ${plat}")
        else
            RESULTS+=("FAIL  ${img}  ${plat}")
            fail=1
        fi
    done
done

echo
echo "==================== MATRIX SUMMARY ===================="
for r in "${RESULTS[@]}"; do
    if [[ "${r}" == PASS* ]]; then echo -e "  \033[1;32m${r}\033[0m"; else echo -e "  \033[1;31m${r}\033[0m"; fi
done
echo "======================================================="
exit "${fail}"