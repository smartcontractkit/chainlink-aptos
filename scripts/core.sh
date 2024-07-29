#!/usr/bin/env bash

CONTAINER_VERSION="latest"
KEYSTONE_ADDR=$(cat "$(dirname -- "$0")"/../contracts/keystone/contract_address.txt)

# Check if .env file exists in the parent directory
if [ -f "../.env" ]; then
    source "../.env"
    echo "Loaded environment variables from ../.env"
fi

set -euo pipefail

bash "$(dirname -- "$0")/core.down.sh"

container_name="chainlink.core"

# https://github.com/smartcontractkit/chainlink/blob/600365a7a27508d699dbd4b994fafba7dc288659/integration-tests/client/chainlink_k8s.go#L82-L83
api_email="notreal@fakeemail.ch"
api_password="fj293fbBnlQ!f9vNs"

CL_CONFIG=$(cat <<-END
[Log]
Level = 'debug'

[Feature]
FeedsManager = true
LogPoller = true
UICSAKeys = true


[OCR2]
Enabled = true

[P2P]
[P2P.V2]
Enabled = true
DeltaDial = '5s'
DeltaReconcile = '5s'
ListenAddresses = ['0.0.0.0:6691']

[WebServer]
HTTPPort = 6688
TLS.HTTPSPort = 0
AllowOrigins = '*'

[[Aptos]]
Enabled = true
ChainID = "localnet"

[Aptos.Workflow]
ForwarderAddress = "$KEYSTONE_ADDR"
PublicKey = ""

[[Aptos.Nodes]]
Name = 'primary'
URL = "http://chainlink-aptos.devnet:8080/v1"

# [[EVM]]
# ChainID = '11155111'

[[EVM]]
ChainID = '1337'
MinContractPayment = '0'
Enabled = true
Nodes = [{ Name = 'node-geth-0', WSURL = 'ws://chainlink.geth:8546', HTTPURL = 'http://chainlink.geth:8544' }]
END
)
# [[EVM]]
# ChainID = '$SOURCE_CHAIN_ID'
# GasEstimator = { PriceMax = '200 gwei', LimitDefault = 6000000, FeeCapDefault = '200 gwei' }
# Nodes = [{ Name = 'node-eth-sepolia', WSURL = '$SOURCE_CHAIN_WS', HTTPURL = '$SOURCE_CHAIN_HTTP' }]

# [[EVM]]
# ChainID = '$DEST_CHAIN_ID'
# ChainType = 'optimismBedrock'
# FinalityDepth = 200
# LogPollInterval = '2s'
# NoNewHeadsThreshold = '40s'
# MinIncomingConfirmations = 1
# Transactions = { ResendAfterThreshold = '30s'}
# NodePool = { SyncThreshold = 10 }
# OCR = { ContractConfirmations = 1 }
# HeadTracker = { HistoryDepth = 300 }
# GasEstimator = { EIP1559DynamicFees = true, BlockHistory.BlockHistorySize = 60, PriceMin = '1 wei', BumpMin = '100 wei' }
# Nodes = [{ Name = 'node-base-sepolia', WSURL = '$DEST_CHAIN_WS', HTTPURL = '$DEST_CHAIN_HTTP' }]

if [[ -z "${CL_CONFIG:-}" ]]; then
	echo "No CL_CONFIG env var provided." >&2
	exit 1
fi

platform_arg=""
if [ -n "${CORE_IMAGE:-}" ]; then
	image_name="${CORE_IMAGE}"
else
	image_name="smartcontract/chainlink-aptos:${CONTAINER_VERSION}"
fi
echo "Using core image: ${image_name}"

listen_ips="0.0.0.0"

NODE_COUNT="${NODE_COUNT:-5}"
# NODE_COUNT="${NODE_COUNT:-1}"

declare -i core_base_port=50100
declare -i core_p2p_base_port=50200

for ((i = 1; i <= NODE_COUNT; i++)); do
	database_name="core_test_${i}"
	echo "Creating database: ${database_name}"
	# postgres_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' chainlink.postgres)
	# TODO: use postgres db ip
	host_postgres_url="postgresql://postgres:postgres@127.0.0.1:5432/postgres"
	# psql "${host_postgres_url}" -c "DROP DATABASE ${database_name};" &>/dev/null || true
	psql "${host_postgres_url}" -c "CREATE DATABASE ${database_name};" &>/dev/null || true

	# TODO: remove this and use node ids
	listen_args=()
	for ip in $listen_ips; do
		listen_args+=("-p" "${ip}:$((core_base_port + i - 1)):6688")
		listen_args+=("-p" "${ip}:$((core_p2p_base_port + i - 1)):6691")
	done

	echo "Starting core container $i"
	container_name_docker="${container_name}.$i"

	# --add-host=host.containers.internal:host-gateway \
	docker run \
		--rm \
		-it \
		-d \
		"${listen_args[@]}" \
		--name "${container_name_docker}" \
		--network-alias "${container_name_docker}" \
		--network chainlink \
		-e "CL_CONFIG=${CL_CONFIG}" \
		-e "CL_DATABASE_URL=postgresql://postgres:postgres@chainlink.postgres:5432/${database_name}?sslmode=disable" \
		-e 'CL_PASSWORD_KEYSTORE=asdfasdfasdfasdf' \
		--entrypoint bash \
		"${image_name}" \
		-c \
		"echo -e \"${api_email}\\n${api_password}\" > /tmp/api_credentials && chainlink node start --api /tmp/api_credentials"
done

echo "Waiting for core containers to become ready.."
for ((i = 1; i <= NODE_COUNT; i++)); do
	container_name_docker="${container_name}.$i"

	start_time=$(date +%s)
	prev_output=""
	while true; do
		output=$(docker logs "${container_name_docker}" 2>&1)
		if [[ "${output}" != "${prev_output}" ]]; then
			echo -n "${output#"$prev_output"}"
			prev_output="${output}"
		fi

		if [[ $output == *"Listening and serving HTTP"* ]]; then
			echo ""
			echo "node is ready."
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
done
