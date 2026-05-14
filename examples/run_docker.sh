#!/usr/bin/env bash
set -euo pipefail

sample="${1:?usage: examples/run_docker.sh /path/to/sample.exe [out-dir]}"
out_dir="${2:-out/$(basename "$sample")}"

docker build --platform linux/amd64 -t speakeasy-extensions:1.5.11 .

python3 tools/run_speakeasy_docker.py \
  --profile "${SPEAKEASY_PROFILE:-fast}" \
  --report-dir "$out_dir" \
  "$sample"
