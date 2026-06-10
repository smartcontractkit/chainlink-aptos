# CRE Canary Receiver (Primary Only)

Simplified Aptos receiver for the CRE Aptos capability canary. Registers only with the primary forwarder (`platform::storage`), unlike `cre-receiver` which registers with both primary and secondary.

On publish, `init_module` registers a single callback with `platform::storage`. Each forwarded report payload is decoded as UTF-8, emitted in `MessageReceived`, and increments an on-chain counter.

## Required Values

```sh
export PLATFORM_ADDRESS="<forwarder-platform-package-address>"
export APTOS_PROFILE="<aptos-cli-profile>"
```

## Deploy (Object Address)

This package uses `deploy-object` to publish to a new object address rather than under your EOA.

### First attempt (will fail)

The `owner` named address is intentionally omitted here. This will fail because `ChainlinkPlatform` declares `owner` as a named address and the compiler requires it to be resolved, even though the receiver itself never references `@owner`.

```sh
aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver_primary \
  --named-addresses platform="$PLATFORM_ADDRESS"
```

### Working deploy

Query the platform owner address first:

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_ADDRESS}::forwarder::get_owner"
```

Then deploy with `owner` included:

```sh
export PLATFORM_OWNER_ADDRESS="<owner-address-from-above>"

aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver_primary \
  --named-addresses platform="$PLATFORM_ADDRESS",owner="$PLATFORM_OWNER_ADDRESS"
```

The command will output the object address where the package was deployed. Save it for verification.

## Verify

```sh
export CRE_CANARY_RECEIVER_PRIMARY_ADDRESS="<object-address-from-deploy>"

aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${CRE_CANARY_RECEIVER_PRIMARY_ADDRESS}::canary_receiver::get_counter"
```

Expected initial result:

```json
{
  "Result": [
    "0"
  ]
}
```

## Notes

- Uses `aptos move deploy-object` instead of `aptos move publish`. The package lives at its own object address, separate from the deployer's EOA.
- The `owner` named address is required by the `ChainlinkPlatform` dependency (used in `forwarder::init_module` to set the initial owner). It must match the value used when platform was originally deployed, or the on-chain bytecode won't match and you'll get `EPACKAGE_DEP_MISSING`.
- Only the primary platform forwarder is used. For dual-forwarder setups, see `cre-receiver`.
