#!/usr/bin/env bash
# =============================================================================
# SSL Manager — full install.sh matrix (host side)
#
# Boots a systemd-enabled container per {distro × arch}, runs install.sh
# non-interactively end-to-end, then verifies the service/timers/nginx/socket
# via verify-install.sh. Complements run-matrix.sh, which covers only the
# dependency/app layer.
#
# Usage:
#   deploy/test/install-matrix.sh
#   IMAGES="ubuntu:26.04" PLATFORMS="linux/arm64" deploy/test/install-matrix.sh
#
# NOTE: a privileged systemd container validates installer logic, unit wiring,
# nginx, socket perms and live serving — it is NOT a faithful test of the
# systemd sandboxing directives (ProtectSystem, PrivateDevices, SystemCallFilter,
# RestrictAddressFamilies). Treat a real machine as the final word on those.
#
# Known limitation: NON-NATIVE (qemu-emulated) combos can fail service start with
# status=226/NAMESPACE because the emulation layer can't set up the mount
# namespaces those directives require — notably Ubuntu 26.04 (systemd 259) under
# linux/amd64 emulation on an arm64 host. This is an emulation artifact, not an
# install.sh defect: the same unit starts cleanly on the NATIVE arch. Run the
# install matrix on the native arch (and the dependency matrix for the other).
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
        safe="$(echo "${img}-${plat}" | tr '/:.' '___')"
        tag="ssl-mgr-systemd-${safe}"
        cname="sslmgr-inst-${safe}-$$"

        echo
        echo "############################################################"
        echo "# install test: ${img}   ${plat}"
        echo "############################################################"

        ok=1
        docker build --platform "${plat}" --build-arg BASE="${img}" \
            -t "${tag}" -f "${REPO}/deploy/test/Dockerfile.systemd" "${REPO}/deploy/test" \
            || { RESULTS+=("FAIL(build)  ${img}  ${plat}"); fail=1; continue; }

        docker rm -f "${cname}" >/dev/null 2>&1 || true
        docker run -d --name "${cname}" --platform "${plat}" \
            --privileged --cgroupns=host \
            -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
            --tmpfs /run --tmpfs /run/lock \
            -v "${REPO}:/src:ro" \
            "${tag}" >/dev/null \
            || { RESULTS+=("FAIL(run)  ${img}  ${plat}"); fail=1; continue; }

        # Wait for systemd to settle (running, or 'degraded' which is fine here).
        docker exec "${cname}" bash -c '
            for _ in $(seq 1 30); do
                s=$(systemctl is-system-running 2>/dev/null || true)
                [ "$s" = running ] || [ "$s" = degraded ] && exit 0
                sleep 1
            done' || true

        # Run install.sh non-interactively: port 5001, 2 workers, blank secret
        # (auto-generate), confirm yes. Work from a writable copy of the repo.
        docker exec "${cname}" bash -c '
            set -e
            cp -a /src /opt/src
            cd /opt/src
            printf "5001\n2\n\ny\n" | bash install.sh' || ok=0

        if [[ "${ok}" -eq 1 ]]; then
            docker exec "${cname}" bash /src/deploy/test/verify-install.sh || ok=0
        fi

        [[ "${ok}" -eq 1 ]] && RESULTS+=("PASS  ${img}  ${plat}") || { RESULTS+=("FAIL  ${img}  ${plat}"); fail=1; }
        docker rm -f "${cname}" >/dev/null 2>&1 || true
    done
done

echo
echo "================ INSTALL MATRIX SUMMARY ================"
for r in "${RESULTS[@]}"; do
    if [[ "${r}" == PASS* ]]; then echo -e "  \033[1;32m${r}\033[0m"; else echo -e "  \033[1;31m${r}\033[0m"; fi
done
echo "======================================================="
exit "${fail}"