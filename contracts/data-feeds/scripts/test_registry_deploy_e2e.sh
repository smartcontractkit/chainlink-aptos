#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  Data Feeds: Aptos test script for the Registry migration to support 2 Forwarders
#  • Optional command tracing         :  DEBUG=1 ./test_registry_deploy_e2e.sh
#  • Skip local network auto-shutdown :  SKIP_SHUTDOWN=1 ./test_registry_deploy_e2e.sh
# ------------------------------------------------------------------------------

set -euo pipefail
if [[ "${DEBUG:-}" =~ ^(1|true|yes|y)$ ]]; then
  set -x
fi

# ──────────────────────────────────────────────────────────────────────────────
#  Cosmetics (colour & spinner helpers)
# ──────────────────────────────────────────────────────────────────────────────
if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  use_tty=true
  BOLD=$(tput bold)  RESET=$(tput sgr0)
  GREEN=$(tput setaf 2)  RED=$(tput setaf 1)  YELLOW=$(tput setaf 3) CYAN=$(tput setaf 6)
  SPIN_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  tput civis # hide cursor
  trap 'tput cnorm' EXIT INT TERM
else
  use_tty=false
  BOLD='' RESET='' GREEN='' RED='' YELLOW='' CYAN='' SPIN_CHARS='-\|/'
fi

print()      { printf '%b\n' "$*"; }
heading()    { print "\n${CYAN}${BOLD}$*${RESET}"; }
success()    { print "  ${GREEN}✔ $*${RESET}"; }
# fail <msg> [<logfile>]
fail() {
  local msg=$1 log=${2:-}
  print "  ${RED}✖ ${msg}${RESET}"
  [[ -f "$log" ]] && { print ""; cat "$log"; }
}
warn()       { print "  ${YELLOW}$*${RESET}"; }

spinner() {              # spinner <pid>
  local pid=$1 i=0
  if [[ $- == *x* ]]; then             # x-trace already ON → turn it off
    (
      set +e   # <-- turn -e OFF inside this subshell
      set +x   # quiet
      while kill -0 "$pid" 2>/dev/null; do
        printf "\r  %s " "${SPIN_CHARS:i++%${#SPIN_CHARS}:1}"
        sleep 0.1
      done
    )
  else
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  %s " "${SPIN_CHARS:i++%${#SPIN_CHARS}:1}"
      sleep 0.1
    done                              # quiet spinner
  fi
}

run() {
  # run <description> <var_to_capture_output> <command ...>
  local desc=$1 outvar=$2; shift 2
  local log_file; log_file=$(mktemp)
  heading "$desc"
  local start_time; start_time=$(date +%s)

  # wrap command in subshell so set -e outside doesn’t kill spinner instantly
  (
    set +e  # we’ll handle exit code ourselves
    "$@" >"$log_file" 2>&1
    echo $? >"$log_file.rc"
  ) & local pid=$!

  $use_tty && spinner "$pid"
  wait "$pid"

  local exit_code; exit_code=$(cat "$log_file.rc")
  local duration=$(( $(date +%s)-start_time))

  if [[ $exit_code -ne 0 ]]; then
    fail "$desc (in ${duration}s)" "$log_file"
    rm -f "$log_file" "$log_file.rc"
    exit $exit_code
  fi

  printf -v "$outvar" '%s' "$(cat "$log_file")"
  success "$desc (in ${duration}s)"
  rm -f "$log_file" "$log_file.rc"
}

# ──────────────────────────────────────────────────────────────────────────────
#  Constants / Inputs
# ──────────────────────────────────────────────────────────────────────────────
DATA_FEEDS_PACKAGE_NAME="data-feeds"

ORACLE_PUBKEYS=(
      "247d0189f65f58be83a4e7d87ff338aaf8956e9acb9fcc783f34f9edc29d1b40"
      "ba20d3da9b07663f1e8039081a514649fd61a48be2d241bc63537ee47d028fcd"
      "046faf34ebfe42510251e6098bc34fa3dd5f2de38ac07e47f2d1b34ac770639f"
      "1221e131ef21014a6a99ed22376eb869746a3b5e30fd202cf79e44efaeb8c5c2"
      "425d1354a7b8180252a221040c718cac0ba0251c7efe31a2acefbba578dc2153"
      "4a94c75cb9fe8b1fba86fd4b71ad130943281fdefad10216c46eb2285d60950f"
      "96dc85670c49caa986de4ad288e680e9afb0f5491160dcbb4868ca718e194fc8"
      "bddafb20cc50d89e0ae2f244908c27b1d639615d8186b28c357669de3359f208"
      "4fa557850e4d5c21b3963c97414c1f37792700c4d3b8abdb904b765fd47e39bf"
      "b8834eaa062f0df4ccfe7832253920071ec14dc4f78b13ecdda10b824e2dd3b6"
    )

# Quote each element and join with commas
ORACLE_PUBKEY_ARGS=$(IFS=, ; printf '"%s",' "${ORACLE_PUBKEYS[@]}")
ORACLE_PUBKEY_ARGS="[${ORACLE_PUBKEY_ARGS%,}]"

WORKFLOW_ONWER="0x47e6133409dd4df069f3f84ed0fd7d0aa5459373"

FEED_ID_1="0x0101199b3b000332000000000000000000000000000000000000000000000000"
FEED_ID_2="0x011e22d6bf000332000000000000000000000000000000000000000000000000"

# report 1

EXPECTED_BENCHMARK_1="16633723478918340000"

# from txn
# https://explorer.aptoslabs.com/txn/6735665031/events?network=testnet
FORWARDER_REPORT_PAYLOAD_1="0x000e4b6883e5cf2bc73f28ab4292b3e54ca68ed5df5892be0472cb03cb586a4500000000000000000000000000000000000000000000000000000000638411000000000000000000000000000000000000000000000000000000000000000000017566fe1477ae328e9551a3f265b1f10ef7d6d924be34b864c522711c1bd5a03b682f11e300000001000000019be08f717e9e63462530af0d0b78761c824cfb73a6d292544b0b39c82f6f42623731656238663033326547e6133409dd4df069f3f84ed0fd7d0aa545937300070000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200101199b3b000332000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001200003b9e7679825b8e61a1ea70693173ac66c718a578bac342b9a8bc3111ec46000000000000000000000000000000000000000000000000000000000682f11de00000000000000000000000000000000000000000000000000000000682f11e200000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000068306362000000000000000000000000000000000000000000000000e6d6db5ff5009da0000000000000000000000000000000000000000000000000e6c9d5657f4120d8000000000000000000000000000000000000000000000000e6e3e15a6ac02620"

ORACLE_SIGNATURES_1=(
      "b8834eaa062f0df4ccfe7832253920071ec14dc4f78b13ecdda10b824e2dd3b64f897ca764f57f8de0e0c02ac25dcea1835b32f9b072e9badfb898308564da077ce6eca3e230ec12dfa7145df66050b3da5c13fd64916a3bf4ca15dd51fe7b00"
      "247d0189f65f58be83a4e7d87ff338aaf8956e9acb9fcc783f34f9edc29d1b4087e9f6c9106d46de8f50bb47a6919bc16aeea35b882c4fba0684afe86171059126b8b13b7621ec3a2d0ff2f19440814e2169ea04c208546092d76ba1a8c90b06"
#       "425d1354a7b8180252a221040c718cac0ba0251c7efe31a2acefbba578dc2153eb5d3fd3cc8b7dc9612264df0d2a9ae3f6af508803545a2b559f45cf9922f2602857da00184f30e7f6663fea99b7dbed93bbe881c069d44d8d603f9650a03c07"
#       "bddafb20cc50d89e0ae2f244908c27b1d639615d8186b28c357669de3359f208f6d92cc62de7a77360d3ecd67526380b0b43d2211ac4f3a05108e59563f5bb86e60bbb72d1e3cb3af15ec86c21aab0bcd70dc35eac2d09a20307df0ca79a5f08"
    )

# Quote each element and join with commas
ORACLE_SIGNATURES_ARGS_1=$(IFS=, ; printf '"%s",' "${ORACLE_SIGNATURES_1[@]}")
ORACLE_SIGNATURES_ARGS_1="[${ORACLE_SIGNATURES_ARGS_1%,}]"

# report 2

EXPECTED_BENCHMARK_2="16545126541999927000"

# from txn
# https://explorer.aptoslabs.com/txn/6735703808/events?network=testnet
FORWARDER_REPORT_PAYLOAD_2="0x000e4b6883e5cf2bc73f28ab4292b3e54ca68ed5df5892be0472cb03cb586a45000000000000000000000000000000000000000000000000000000006387f100000000000000000000000000000000000000000000000000000000000000000001f3005c056ca36866b358a8657a5563017ec957f8bee21091805f085928e2c4fc682f19e000000001000000019be08f717e9e63462530af0d0b78761c824cfb73a6d292544b0b39c82f6f42623731656238663033326547e6133409dd4df069f3f84ed0fd7d0aa545937300070000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200101199b3b000332000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001200003b9e7679825b8e61a1ea70693173ac66c718a578bac342b9a8bc3111ec46000000000000000000000000000000000000000000000000000000000682f19d700000000000000000000000000000000000000000000000000000000682f19db00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000068306b5b000000000000000000000000000000000000000000000000e59c18ee1bcaeed8000000000000000000000000000000000000000000000000e58e516ca1093700000000000000000000000000000000000000000000000000e5a9e06f968ca6b0"

ORACLE_SIGNATURES_2=(
      "247d0189f65f58be83a4e7d87ff338aaf8956e9acb9fcc783f34f9edc29d1b403d5084eaa1f0796df330fc3b684716571e09ba79b17a05931e879b12c397ba7ff60e5417b700d596deddf9e5b8aefe645165ae7995ffb3b691f5eb1caeb13e01"
      "425d1354a7b8180252a221040c718cac0ba0251c7efe31a2acefbba578dc2153314750ea2738004868d379bcd85f8258627abb25531dc5ee9d3d165dc5195134bf51fa5206b76209757c2cecc1f96da42d0c4c1074656d37576bccef57260d09"
#       "bddafb20cc50d89e0ae2f244908c27b1d639615d8186b28c357669de3359f208cb92b5eaad8bec529d21dadc2ad5c6e72d394060e71263c176fb8f416a896344bdbb81075d91dd9a883109ebdd4c1dccfd054af5a7be3b810c1cbc618c161c08"
#       "046faf34ebfe42510251e6098bc34fa3dd5f2de38ac07e47f2d1b34ac770639f0e5c9997c2c29979d0f4992b432e019447f93da0313c10c5b091100764728c4acf5846fbe62934eae28a6fb8c88431e20295f8397a648ea91f14d5d02a1d1d0d""
    )

# Quote each element and join with commas
ORACLE_SIGNATURES_ARGS_2=$(IFS=, ; printf '"%s",' "${ORACLE_SIGNATURES_2[@]}")
ORACLE_SIGNATURES_ARGS_2="[${ORACLE_SIGNATURES_ARGS_2%,}]"

# report 3

EXPECTED_BENCHMARK_3="16526275841636362000"
EXPECTED_BENCHMARK_3_2="5413085400000000000"

# from txn
# https://explorer.aptoslabs.com/txn/6735712981/payload?network=testnet
FORWARDER_REPORT_PAYLOAD_3="0x000e4b6883e5cf2bc73f28ab4292b3e54ca68ed5df5892be0472cb03cb586a45000000000000000000000000000000000000000000000000000000006388f5000000000000000000000000000000000000000000000000000000000000000000010ed75b455f5d15f5e7dfc9c032f14348643c3040846b4396aea09c9a85a6fd9e682f1bf700000001000000019be08f717e9e63462530af0d0b78761c824cfb73a6d292544b0b39c82f6f42623731656238663033326547e6133409dd4df069f3f84ed0fd7d0aa5459373000700000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0011e22d6bf0003320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000030fdc6af30c4de9d6d00480a21bfae268cd8d35bf66f74c3b03ef05147fa600000000000000000000000000000000000000000000000000000000682f1bf200000000000000000000000000000000000000000000000000000000682f1bf600000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000068306d760000000000000000000000000000000000000000000000004b1f247dd5da70000000000000000000000000000000000000000000000000004b1aad70484cb0000000000000000000000000000000000000000000000000004b239b8b636830000101199b3b000332000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001200003b9e7679825b8e61a1ea70693173ac66c718a578bac342b9a8bc3111ec46000000000000000000000000000000000000000000000000000000000682f1bef00000000000000000000000000000000000000000000000000000000682f1bf300000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000068306d73000000000000000000000000000000000000000000000000e559205168dae710000000000000000000000000000000000000000000000000e549456aa96f6110000000000000000000000000000000000000000000000000e568fb3828466d10"

ORACLE_SIGNATURES_3=(
      "b8834eaa062f0df4ccfe7832253920071ec14dc4f78b13ecdda10b824e2dd3b650f9ed36a642f11e3889cd38f0ab8f8fd2f96c9175508e0e733cb4f4acb5323aa54d0058ba846b72cc80e6b6ab586cddbfaf97c74710ccebd5624f1cf4d2960a"
      "425d1354a7b8180252a221040c718cac0ba0251c7efe31a2acefbba578dc21538289b2b3143d66b98fa7ba9dad02a95cf4e737a219add55e53e9f7247050b7cb1b0cb0c7160b8cbe4a767f95f3a7bcf86b436a6d66ba75f1d96e2f9f2fc3b003"
#       "bddafb20cc50d89e0ae2f244908c27b1d639615d8186b28c357669de3359f208ec3069a4b07551665329d6bebfa84bd42168bee29063b0c7510def33a9ed1c459023a182d12c2b3308eb567908b0bb357124ebaf3175b55873eef6704f434400"
#       "046faf34ebfe42510251e6098bc34fa3dd5f2de38ac07e47f2d1b34ac770639fc8efd47529269d7f616a8b2a79ee5e8060c4fbd9f8d26940606beb22d0044727b1145d32891738c46952066206a607a44eef66c12a3b69fd7da77c1b95c56000"
    )

# Quote each element and join with commas
ORACLE_SIGNATURES_ARGS_3=$(IFS=, ; printf '"%s",' "${ORACLE_SIGNATURES_3[@]}")
ORACLE_SIGNATURES_ARGS_3="[${ORACLE_SIGNATURES_ARGS_3%,}]"

# ──────────────────────────────────────────────────────────────────────────────
#  Environment
# ──────────────────────────────────────────────────────────────────────────────
PUBLISHER_PROFILE=test_registry_migration_e2e
NETWORK=local
TMP_KEY_FILE=test-key.tmp

echo -e "e2e Data Feeds Registry Deployment test starting! 🚀\n"

if [[ "${DEBUG:-}" =~ ^(1|true|yes|y)$ ]]; then
  echo -e "✅ DEBUG=1 set! Script will output command trace! 🚀"
else
  echo -e "🛑 DEBUG not set..\nYou can use DEBUG=1 to output the command trace! 🚀\n"
fi

if [[ "${SKIP_SHUTDOWN:-}" =~ ^(1|true|yes|y)$ ]]; then
  echo -e "✅ SKIP_SHUTDOWN=1 set! Script will keep running the local network after the test!! 🚀\n"
else
  echo -e 🛑 "SKIP_SHUTDOWN not set..\nYou can use SKIP_SHUTDOWN=1 to keep the local network running after the test! 🚀\n"
fi

REST_PORT=8080
FAUCET_PORT=8081
LOG_FILE=/tmp/aptos-testnet.log

wait_for_ports() {
  local port1=$1
  local port2=$2
  local max_retries=30

  echo "⏳ Waiting for ports $port1 and $port2 to become available..."

  for i in $(seq 1 "$max_retries"); do
    port1_up=$(lsof -i :"$port1" -sTCP:LISTEN -t >/dev/null 2>&1 && echo "yes" || echo "no")
    port2_up=$(lsof -i :"$port2" -sTCP:LISTEN -t >/dev/null 2>&1 && echo "yes" || echo "no")

    if [[ "$port1_up" == "yes" && "$port2_up" == "yes" ]]; then
      echo "✅ Both ports are now listening: $port1 and $port2"
      return 0
    fi

    sleep 1
  done

  echo "❌ Timed out waiting for both ports to be available."
  echo "    $port1: $port1_up"
  echo "    $port2: $port2_up"
  exit 1
}

# Check if the exact aptos process is running
if pgrep -f "aptos node run-local-testnet" >/dev/null; then
  echo "✅ Aptos local testnet process is already running."

  APTOS_PID=$(pgrep -f "aptos node run-local-testnet")
  echo "Aptos local network PID: $APTOS_PID"

  # Confirm both ports are listening
  if lsof -i :"$REST_PORT" -sTCP:LISTEN -t >/dev/null && \
     lsof -i :"$FAUCET_PORT" -sTCP:LISTEN -t >/dev/null; then
    echo "✅ Ports $REST_PORT and $FAUCET_PORT are in use by Aptos testnet."
  else
    echo "❌ Aptos process is running but one or both required ports are not listening."
    exit 1
  fi
else
  # Ensure ports are not taken by some other process
  if lsof -i :"$REST_PORT" -sTCP:LISTEN -t >/dev/null; then
    echo "❌ Port $REST_PORT is in use by another process. Can't start Aptos."
    exit 1
  fi

  if lsof -i :"$FAUCET_PORT" -sTCP:LISTEN -t >/dev/null; then
    echo "❌ Port $FAUCET_PORT is in use by another process. Can't start Aptos."
    exit 1
  fi

  echo "🚀 Starting Aptos local testnet with faucet..."
  nohup aptos node run-local-testnet --with-faucet > "$LOG_FILE" 2>&1 &
  APTOS_PID=$!
  echo -e "✅ Started in background. Logs at $LOG_FILE\n"
  echo "Aptos local network PID: $APTOS_PID"

  run "Waiting for Aptos local network to fully boot!" _out \
    wait_for_ports $REST_PORT $FAUCET_PORT
fi


# Kill the node when the script exits (normal or error)
cleanup() {
  if [[ -n "${APTOS_PID:-}" ]]; then
    if ! [[ "${SKIP_SHUTDOWN:-}" =~ ^(1|true|yes|y)$ ]]; then
      echo "🛑 Cleaning up Aptos testnet (PID ${APTOS_PID})"
      kill "${APTOS_PID}" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT


if [[ ! -f .aptos/config.yaml ]] || ! grep -q "^  $PUBLISHER_PROFILE:" .aptos/config.yaml; then
  echo -e "\nWe are about to make your address profile: ($PUBLISHER_PROFILE) for the e2e test!\n"
  echo -e "💥 This will create a .aptos/ folder in your current directory. 💥 Be aware. Re-run from a diretory if your choosing if you wish..\n"
  aptos key generate --output-file $TMP_KEY_FILE --assume-yes
  echo -e "\n"
  aptos init \
    --profile $PUBLISHER_PROFILE \
    --network $NETWORK \
    --assume-yes \
    --private-key-file $TMP_KEY_FILE
  rm "$TMP_KEY_FILE"
  rm "$TMP_KEY_FILE.pub"
fi


PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_ROOT="$SCRIPT_DIR/../.."

# ──────────────────────────────────────────────────────────────────────────────
#  Helper to extract “Code was successfully deployed” address from stdout
# ──────────────────────────────────────────────────────────────────────────────
extract_addr() {
  # Grab the first 0x-prefixed address on a “Code was successfully …” line.
  # Works with both “deployed” and “published” message variants.
  grep -Eo 'Code was successfully .* object address +0x[0-9a-fA-F]+' \
  | head -n1 | grep -Eo '0x[0-9a-fA-F]+'
}

# ──────────────────────────────────────────────────────────────────────────────
#  0.  Fund gas
# ──────────────────────────────────────────────────────────────────────────────
run "Funding dev account with test APT" _out \
  aptos account fund-with-faucet --profile "$PUBLISHER_PROFILE" --amount 100000000

# ──────────────────────────────────────────────────────────────────────────────
#  1.  Deploy Forwarder 1
# ──────────────────────────────────────────────────────────────────────────────
run "Deploy Forwarder 1" OUT_FWD1 \
  aptos move create-object-and-publish-package \
    --package-dir "$CONTRACTS_ROOT/platform" \
    --address-name platform \
    --named-addresses owner="$PUBLISHER_ADDR" \
    --profile "$PUBLISHER_PROFILE" \
    --max-gas 50000 --assume-yes

PLATFORM_FORWARDER_ADDR=$(print "$OUT_FWD1" | extract_addr)
run "Forwarder 1: $PLATFORM_FORWARDER_ADDR" _out true

# If address empty ⇒ show full CLI output before dying
if [[ -z "$PLATFORM_FORWARDER_ADDR" ]]; then
  fail "Could not extract Forwarder 1 contract address" <(print "$OUT_FWD1")
  exit 1
fi

run "Set config on Forwarder 1" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::set_config" \
    --assume-yes --args u32:1 u32:1 u8:1 "hex:$ORACLE_PUBKEY_ARGS"

# ──────────────────────────────────────────────────────────────────────────────
#  2.  Deploy Forwarder 2
# ──────────────────────────────────────────────────────────────────────────────
run "Deploy Forwarder 2" OUT_FWD2 \
  aptos move create-object-and-publish-package \
    --profile "$PUBLISHER_PROFILE" \
    --package-dir "$CONTRACTS_ROOT/platform_secondary" \
    --address-name platform_secondary \
    --named-addresses owner_secondary="$PUBLISHER_ADDR" \
    --max-gas 50000 --assume-yes

PLATFORM_SECONDARY_FORWARDER_ADDR=$(print "$OUT_FWD2" | extract_addr)
run "Forwarder 2: $PLATFORM_SECONDARY_FORWARDER_ADDR" _out true

# If address empty ⇒ show full CLI output before dying
if [[ -z "$PLATFORM_SECONDARY_FORWARDER_ADDR" ]]; then
  fail "Could not extract Forwarder 1 contract address" <(print "$OUT_FWD2")
  exit 1
fi

run "Set config on Forwarder 2" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$PLATFORM_SECONDARY_FORWARDER_ADDR::forwarder::set_config" \
    --assume-yes --args u32:1 u32:1 u8:1 "hex:$ORACLE_PUBKEY_ARGS"

# ──────────────────────────────────────────────────────────────────────────────
#  3.  Deploy legacy data-feeds package
# ──────────────────────────────────────────────────────────────────────────────
run "Deploy data-feeds (supports benchmark reports & 2 forwarders)" OUT_DF \
  aptos move create-object-and-publish-package \
    --profile "$PUBLISHER_PROFILE" \
    --package-dir "$CONTRACTS_ROOT/$DATA_FEEDS_PACKAGE_NAME" \
    --address-name data_feeds \
    --named-addresses platform="$PLATFORM_FORWARDER_ADDR",owner="$PUBLISHER_ADDR",platform_secondary="$PLATFORM_SECONDARY_FORWARDER_ADDR",owner_secondary="$PUBLISHER_ADDR" \
    --max-gas 50000 --assume-yes

DATA_FEEDS_ADDR=$(print "$OUT_DF" | extract_addr)
run "Registry: $DATA_FEEDS_ADDR" _out true

# If address empty ⇒ show full CLI output before dying
if [[ -z "$DATA_FEEDS_ADDR" ]]; then
  fail "Could not extract Forwarder 1 contract address" <(print "$OUT_DF")
  exit 1
fi

run "Set workflow config" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::set_workflow_config" \
    --assume-yes --args "hex:[\"$WORKFLOW_ONWER\"]" 'string:[]'

run "Register feed #1 (LINK)" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" \
    --assume-yes --args "hex:[\"$FEED_ID_1\"]" 'string:["LINK"]' 'hex:0x99'

run "Register feed #2 (APT)" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" \
    --assume-yes --args "hex:[\"$FEED_ID_2\"]" 'string:["APT"]' 'hex:0x99'

# ──────────────────────────────────────────────────────────────────────────────
#  4.  Report 1 – write & verify
# ──────────────────────────────────────────────────────────────────────────────
run "Write report 1 (via Forwarder 1)" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::report" \
    --assume-yes --args "address:$DATA_FEEDS_ADDR" \
    "hex:$FORWARDER_REPORT_PAYLOAD_1" "hex:$ORACLE_SIGNATURES_ARGS_1"

run "Read report 1" OUT_REPORT1_READ \
  aptos move view \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes

BENCHMARK_1=$(print "$OUT_REPORT1_READ" | jq -r '.Result[0][0].feed.benchmark')
[[ "$BENCHMARK_1" == "$EXPECTED_BENCHMARK_1" ]] \
  && success "Benchmark 1 matches expected value" \
  || { fail "Benchmark 1 mismatch"; exit 1; }

# ──────────────────────────────────────────────────────────────────────────────
#  5.  Report 2 – write & verify
# ──────────────────────────────────────────────────────────────────────────────
run "Write report 2 (via Forwarder 1)" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::report" \
    --assume-yes --args "address:$DATA_FEEDS_ADDR" \
    "hex:$FORWARDER_REPORT_PAYLOAD_2" "hex:$ORACLE_SIGNATURES_ARGS_2"

run "Read report 2" OUT_REPORT2_READ \
  aptos move view \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes

BENCHMARK_2=$(print "$OUT_REPORT2_READ" | jq -r '.Result[0][0].feed.benchmark')
[[ "$BENCHMARK_2" == "$EXPECTED_BENCHMARK_2" ]] \
  && success "Benchmark 2 matches expected value" \
  || { fail "Benchmark 2 mismatch"; exit 1; }

# ──────────────────────────────────────────────────────────────────────────────
#  6.  Report 3 – write (via 2nd forwarder) & verify
# ──────────────────────────────────────────────────────────────────────────────
run "Write report 3 (via Forwarder 2)" _out \
  aptos move run \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$PLATFORM_SECONDARY_FORWARDER_ADDR::forwarder::report" \
    --assume-yes --args "address:$DATA_FEEDS_ADDR" \
    "hex:$FORWARDER_REPORT_PAYLOAD_3" "hex:$ORACLE_SIGNATURES_ARGS_3"

run "Read report 3" OUT_REPORT3_READ \
  aptos move view \
    --profile "$PUBLISHER_PROFILE" \
    --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes

BENCHMARK_3=$(print "$OUT_REPORT3_READ"   | jq -r '.Result[0][0].feed.benchmark')
BENCHMARK_3_2=$(print "$OUT_REPORT3_READ" | jq -r '.Result[0][1].feed.benchmark')

[[ "$BENCHMARK_3"   == "$EXPECTED_BENCHMARK_3"   ]] && success "Benchmark 3 primary   OK" || { fail "Benchmark 3 primary mismatch";   exit 1; }
[[ "$BENCHMARK_3_2" == "$EXPECTED_BENCHMARK_3_2" ]] && success "Benchmark 3 secondary OK" || { fail "Benchmark 3 secondary mismatch"; exit 1; }

# ──────────────────────────────────────────────────────────────────────────────
#  Summary
# ──────────────────────────────────────────────────────────────────────────────
heading "🎉 All benchmarks validated — deployment pipeline complete"
print "  Forwarder 1 address : $PLATFORM_FORWARDER_ADDR"
print "  Forwarder 2 address : $PLATFORM_SECONDARY_FORWARDER_ADDR"
print "  Registry address    : $DATA_FEEDS_ADDR"
print "  Publisher account   : $PUBLISHER_ADDR"
