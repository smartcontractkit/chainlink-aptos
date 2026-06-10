# CRE Canary Receiver (For Mainnet and Staging)

Simple Aptos receiver used by the CRE Aptos capability canary.

The package publishes `cre_canary_receiver::canary_receiver`. On publish, `init_module` registers receiver callbacks with two forwarder storage modules: `platform::storage` and `platform_secondary::storage`. Each forwarded report payload is decoded as UTF-8, emitted in `MessageReceived`, and increments an on-chain counter.

## Required Values

```sh
export PLATFORM_ADDRESS="<forwarder-platform-package-address>"
export PLATFORM_SECONDARY_ADDRESS="<second-forwarder-platform-package-address>"
export APTOS_PROFILE="<aptos-cli-profile>"
```

Query platform owner addresses (needed for compilation):

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_ADDRESS}::forwarder::get_owner"

aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_SECONDARY_ADDRESS}::forwarder::get_owner"
```

Then set them:

```sh
export PLATFORM_OWNER_ADDRESS="<owner-from-above>"
export PLATFORM_SECONDARY_OWNER_ADDRESS="<owner-from-above>"
```

## Deploy (Object Address)

Uses `deploy-object` to publish to a new object address rather than under your EOA.

```sh
cd contracts/cre-receiver

aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver \
  --named-addresses platform="$PLATFORM_ADDRESS",owner="$PLATFORM_OWNER_ADDRESS",platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

## Verify

```sh
export CRE_CANARY_RECEIVER_ADDRESS="<object-address-from-deploy-output>"

aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${CRE_CANARY_RECEIVER_ADDRESS}::canary_receiver::get_counter"
```

Expected initial result:

```json
{
  "Result": ["0"]
}
```

## Staging Testnet

```sh
export PLATFORM_ADDRESS="0xc4d0e0bb02d0b0a0e4bfdd32b55e45c024b3da3c2ba21b883c765b10ffeb87e0"
export PLATFORM_OWNER_ADDRESS="0x753fc7758cf1f6653f6bc3ec12a29b566b6c962d33891964453b27f6e5c55b89"
export PLATFORM_SECONDARY_ADDRESS="0x729e127b91225da8bae6d9c032a01f1342d17cdfad06bb6ee8438bb23106612d"
export PLATFORM_SECONDARY_OWNER_ADDRESS="0x753fc7758cf1f6653f6bc3ec12a29b566b6c962d33891964453b27f6e5c55b89"
export APTOS_PROFILE="default"

aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver \
  --named-addresses platform="$PLATFORM_ADDRESS",owner="$PLATFORM_OWNER_ADDRESS",platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

> Move.toml must use `ChainlinkPlatformSecondary` for the secondary dependency.

## Notes

- Uses `aptos move deploy-object` instead of `aptos move publish`. The package lives at its own object address, separate from the deployer's EOA.
- The `owner` and `owner_secondary` named addresses are required by the platform dependencies (used in `forwarder::init_module`). They must match the values used when the platform packages were originally deployed, or bytecode won't match and you'll get `EPACKAGE_DEP_MISSING`.
- A receiver must be registered with each forwarder/storage package that will call it.
- If two forwarders use the same Move module names at different addresses, the receiver still needs two static dependencies with distinct named addresses.
