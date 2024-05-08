#!/usr/bin/env bash

dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

container_name="chainlink-aptos.devnet"
container_image="aptoslabs/tools:aptos-node-v1.11.0"

if [ -n "${CUSTOM_IMAGE:-}" ]; then
  container_image="${CUSTOM_IMAGE}"
fi

echo "Using container image: ${container_image}"

set -e pipefail

bash "${dir}/devnet.down.sh"


network_name="chainlink-aptos.network"

if ! docker network inspect "$network_name" >/dev/null 2>&1; then
    docker network create --subnet=172.254.0.0/24 "$network_name"
    echo "Docker network '$network_name' created successfully."
fi

temp_dir=$(mktemp -d)

container_ip="172.254.0.101"

echo "Starting ${container_name} (${container_ip})"

listen_args=()
# On linux, we can connect to the container ip directly.
if [ "$(uname)" = "Darwin" ]; then
	echo "Listening on all interfaces on MacOS"
  listen_args+=("-p" "0.0.0.0:8080:8080", "-p", "0.0.0.0:8081:8081")
fi

docker run \
  "${listen_args[@]}" \
  -d \
  --platform linux/amd64 \
  --name "${container_name}" \
  --ip "${container_ip}" \
  --network "${network_name}" \
  "${container_image}" \
  aptos node run-local-testnet --with-faucet --force-restart --bind-to 0.0.0.0

echo "Waiting for ${container_name} container to become ready.."
start_time=$(date +%s)
prev_output=""
while true; do
  output=$(docker logs "${container_name}" 2>&1)
  if [[ "${output}" != "${prev_output}" ]]; then
    echo -n "${output#$prev_output}"
    prev_output="${output}"
  fi

  if [[ $output == *"Node API is ready"* ]]; then
    echo ""
    echo "${container_name} is ready."
    break

  fi

  current_time=$(date +%s)
  elapsed_time=$((current_time - start_time))

  if ((elapsed_time > 600)); then
    echo "Error: Command did not become ready within 600 seconds"
    exit 1
  fi

  sleep 3
done
