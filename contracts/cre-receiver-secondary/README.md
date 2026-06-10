# CRE Canary Receiver (Secondary Only)

Simplified Aptos receiver for the CRE Aptos capability canary. Registers only with the secondary forwarder (`platform_secondary::storage`), unlike `cre-receiver` which registers with both primary and secondary.

On publish, `init_module` registers a single callback with `platform_secondary::storage`. Each forwarded report payload is decoded as UTF-8, emitted in `MessageReceived`, and increments an on-chain counter.

## Move.toml Package Name

The dependency name in `Move.toml` must match the on-chain package name:

- **Prod testnet**: Use `ChainlinkPlatformB`
- **Staging / mainnet**: Use `ChainlinkPlatformSecondary`

## Required Values

```sh
export PLATFORM_SECONDARY_ADDRESS="<forwarder-platform-secondary-package-address>"
export APTOS_PROFILE="<aptos-cli-profile>"
```

Query the platform secondary owner address (needed for compilation):

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_SECONDARY_ADDRESS}::forwarder::get_owner"
```

Then set it:

```sh
export PLATFORM_SECONDARY_OWNER_ADDRESS="<owner-from-above>"
```

## Deploy (Object Address)

Uses `deploy-object` to publish to a new object address rather than under your EOA.

```sh
cd contracts/cre-receiver-secondary

aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver_secondary \
  --named-addresses platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

## Verify

```sh
export CRE_CANARY_RECEIVER_SECONDARY_ADDRESS="<object-address-from-deploy-output>"

aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${CRE_CANARY_RECEIVER_SECONDARY_ADDRESS}::canary_receiver::get_counter"
```

Expected initial result:

```json
{
  "Result": [
    "0"
  ]
}
```

## Prod Testnet

```sh
export PLATFORM_SECONDARY_ADDRESS="0xfe335602574abdd34b82f6260bf01b426b902819663fdb801a0c75b2c68f517f"
export PLATFORM_SECONDARY_OWNER_ADDRESS="0xc10291bb05fe4c3392cabb17fe2945bb530f5902b4c83ecaaceb0c35c7e11182"
export APTOS_PROFILE="default"

aptos move deploy-object \
  --profile "$APTOS_PROFILE" \
  --address-name cre_canary_receiver_secondary \
  --named-addresses platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

> Move.toml must use `ChainlinkPlatformB` for the dependency.

## Notes

- Uses `aptos move deploy-object` instead of `aptos move publish`. The package lives at its own object address, separate from the deployer's EOA.
- The `owner_secondary` named address is required by the `ChainlinkPlatformB` dependency (used in `forwarder::init_module` to set the initial owner). It must match the value used when the platform secondary package was originally deployed, or bytecode won't match and you'll get `EPACKAGE_DEP_MISSING`.
- Only the secondary platform forwarder is used. For the primary forwarder, see `cre-receiver-primary`.
