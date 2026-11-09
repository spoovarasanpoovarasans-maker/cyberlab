#!/usr/bin/env bash
# Build one image per challenges/<id>/ directory.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> building cyberlab/forwarder:latest"
docker build --pull -t "cyberlab/forwarder:latest" infra/forwarder

found=0
for dir in challenges/*/; do
    [ -f "${dir}challenge.yaml" ] || continue
    id="$(basename "$dir")"
    image="cyberlab/challenge-${id}:latest"
    echo "==> building ${image}"
    docker build --pull -t "${image}" "${dir}"
    found=$((found + 1))
done

if [ "${found}" -eq 0 ]; then
    echo "No challenges found under challenges/" >&2
    exit 1
fi

echo "Built ${found} challenge image(s) and the relay image."
