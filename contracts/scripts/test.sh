#!/usr/bin/env bash
set -euxo pipefail

cd "$(dirname -- "$0")/.."

aptos move test --package-dir platform
aptos move test --package-dir mcms
aptos move test --package-dir data-feeds
