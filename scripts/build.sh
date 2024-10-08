#!/usr/bin/env bash

CONTAINER_VERSION="aptos"

set -euxo pipefail

pushd "$(dirname -- "$0")/../../../chainlink"
# Attempt to build the Docker image
if docker build . -t smartcontract/chainlink:${CONTAINER_VERSION} -f ./plugins/chainlink.Dockerfile --build-arg TAGS=dev; then
    echo "Docker build successful."
fi

popd

pushd "$(dirname -- "$0")/.."
docker build . -t smartcontract/chainlink-aptos -f ./scripts/chainlink.Dockerfile
popd
