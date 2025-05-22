#!/usr/bin/env bash
set -euxo pipefail

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

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/.."

# get local gas
aptos account fund-with-faucet --profile default --amount 100000000

echo "Deploying Forwarder 1..."

# deploy platform forwarder
OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir "$REPO_ROOT/platform" \
  --address-name platform \
  --named-addresses owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
  --max-gas 50000 \
	--assume-yes)
 
echo "✅ Deployed Forwarder 1! 🚀"

# # Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > $REPO_ROOT/platform/contract_address.txt
PLATFORM_FORWARDER_ADDR=$(cat $REPO_ROOT/platform/contract_address.txt)
echo "Contract deployed to address: $PLATFORM_FORWARDER_ADDR"
echo "Contract address saved to contract_address.txt"

echo "Setting config on Forwarder 1..."

aptos move run --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::set_config" --assume-yes --args u32:1 u32:1 u8:1 "hex:$ORACLE_PUBKEY_ARGS"

echo "✅ Config set on Forwarder 1! 🚀"

echo "Deploying Forwarder 2..."

# deploy secondary platform forwarder
OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir "$REPO_ROOT/platform_secondary" \
  --address-name platform_secondary \
  --named-addresses owner_secondary=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
  --max-gas 50000 \
	--assume-yes)

echo "✅ Deployed Forwarder 2! 🚀"
 
# # Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > $REPO_ROOT/platform_secondary/contract_address.txt
PLATFORM_SECONDARY_FORWARDER_ADDR=$(cat $REPO_ROOT/platform_secondary/contract_address.txt)
echo "Contract deployed to address: $PLATFORM_SECONDARY_FORWARDER_ADDR"
echo "Contract address saved to contract_address.txt"

echo "Setting config on Forwarder 2..."

aptos move run --function-id "$PLATFORM_SECONDARY_FORWARDER_ADDR::forwarder::set_config" --assume-yes --args u32:1 u32:1 u8:1 "hex:$ORACLE_PUBKEY_ARGS"

echo "✅ Config set on Forwarder 2! 🚀"

echo "Deploying data-feeds..."

# deploy data feeds
 OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir "$REPO_ROOT/data-feeds-pre-migration" \
  --address-name data_feeds \
  --named-addresses platform=$PLATFORM_FORWARDER_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
  --max-gas 50000 \
 --assume-yes)

 echo "✅ Deployed data-feeds! 🚀"

# Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > $REPO_ROOT/data-feeds/contract_address.txt
DATA_FEEDS_ADDR=$(cat $REPO_ROOT/data-feeds/contract_address.txt)
echo "Contract deployed to address: $DATA_FEEDS_ADDR"
echo "Contract address saved to contract_address.txt"

echo "Setting workflow config..."

# data_feeds::router::set_workflow_config(workflow_owners, workflow_names)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_workflow_config" --assume-yes --args "hex:[\"$WORKFLOW_ONWER\"]" 'string:[]'

echo "✅ Workflow config set! 🚀"

echo "Setting feed_id 1 on Registry..."

# data_feeds::router::set_feeds(feed_ids, descriptions, config_id)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" --assume-yes --args "hex:[\"$FEED_ID_1\"]" 'string:["FOOBAR"]' 'hex:0x99'

echo "✅ feed_id 1 set on Registry! 🚀"

echo "Setting feed_id 2 on Registry..."

aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" --assume-yes --args "hex:[\"$FEED_ID_2\"]" 'string:["BARFOO"]' 'hex:0x99'

echo "✅ feed_id 2 set on Registry! 🚀"

echo "Writing report 1 to Registry..."

# send writes to registry via forwarder
aptos move run --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::report" --assume-yes --args "address:$DATA_FEEDS_ADDR" "hex:$FORWARDER_REPORT_PAYLOAD_1" "hex:$ORACLE_SIGNATURES_ARGS_1"

echo "✅ Report 1 written to Registry! 🚀"

# reads saved value
 OUTPUT=$(aptos move view --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes)

BENCHMARK_1=$(echo "$OUTPUT" | jq -r '.Result[0][0].feed.benchmark')

if [[ "$EXPECTED_BENCHMARK_1" != "$BENCHMARK_1" ]]; then
  echo "❌ Bad read after write"
  echo "   Expected: $EXPECTED_BENCHMARK_1"
  echo "   Got:      $BENCHMARK_1"
  exit 1
else
  echo "✅ Correct benchmark value read from Registry!! 🚀"
fi

echo "Upgrading Registry to support benchmark reports and 2 Forwarders..."

# upgrade data feeds
 OUTPUT=$(aptos move upgrade-object \
  --package-dir "$REPO_ROOT/data-feeds" \
  --object-address $DATA_FEEDS_ADDR \
  --address-name data_feeds \
  --named-addresses data_feeds=$DATA_FEEDS_ADDR,platform=$PLATFORM_FORWARDER_ADDR,owner=$PUBLISHER_ADDR,platform_secondary=$PLATFORM_SECONDARY_FORWARDER_ADDR,owner_secondary=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
  --max-gas 50000 \
 --assume-yes)

echo "✅ Registry upgraded! 🚀"

echo "Writing report 2 to Registry..."

# send writes to registry via forwarder
aptos move run --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::report" --assume-yes --args "address:$DATA_FEEDS_ADDR" "hex:$FORWARDER_REPORT_PAYLOAD_2" "hex:$ORACLE_SIGNATURES_ARGS_2"

echo "✅ Report 2 written to Registry! 🚀"

# reads saved value
 OUTPUT=$(aptos move view --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes)

BENCHMARK_2=$(echo "$OUTPUT" | jq -r '.Result[0][0].feed.benchmark')

if [[ "$EXPECTED_BENCHMARK_2" != "$BENCHMARK_2" ]]; then
  echo "❌ Bad read after write"
  echo "   Expected: $EXPECTED_BENCHMARK_2"
  echo "   Got:      $BENCHMARK_2"
  exit 1
else
  echo "✅ Correct benchmark value read from Registry!! 🚀"
fi

echo "Writing report 3 to Registry..."

# send writes to registry via forwarder
aptos move run --function-id "$PLATFORM_SECONDARY_FORWARDER_ADDR::forwarder::report" --assume-yes --args "address:$DATA_FEEDS_ADDR" "hex:$FORWARDER_REPORT_PAYLOAD_3" "hex:$ORACLE_SIGNATURES_ARGS_3"

echo "✅ Report 3 written to Registry! 🚀"

# reads saved value
 OUTPUT=$(aptos move view --function-id "$DATA_FEEDS_ADDR::registry::get_feeds" --assume-yes)

BENCHMARK_3=$(echo "$OUTPUT" | jq -r '.Result[0][0].feed.benchmark')
BENCHMARK_3_2=$(echo "$OUTPUT" | jq -r '.Result[0][1].feed.benchmark')

if [[ "$EXPECTED_BENCHMARK_3" != "$BENCHMARK_3" ]]; then
  echo "❌ Bad read after write"
  echo "   Expected: $EXPECTED_BENCHMARK_3"
  echo "   Got:      $BENCHMARK_3"
  exit 1
else
  echo "✅ Correct benchmark value read from Registry!! 🚀"
fi

if [[ "$EXPECTED_BENCHMARK_3_2" != "$BENCHMARK_3_2" ]]; then
  echo "❌ Bad read after write"
  echo "   Expected: $EXPECTED_BENCHMARK_3_2"
  echo "   Got:      $BENCHMARK_3_2"
  exit 1
else
  echo "✅ Correct benchmark value read from Registry!! 🚀"
fi


