# CRE Canary Receiver

Simple Aptos receiver used by the CRE Aptos capability canary.

The package publishes `cre_canary_receiver::canary_receiver`. On publish, `init_module` registers receiver callbacks with two forwarder storage modules: `platform::storage` and `platform_secondary::storage`. Each forwarded report payload is decoded as UTF-8, emitted in `MessageReceived`, and increments an on-chain counter.

## Required Values

Set these values before compiling or publishing:

```sh
export CRE_CANARY_RECEIVER_ADDRESS="<publisher-account-address>"
export PLATFORM_ADDRESS="<first-forwarder-platform-package-address>"
export PLATFORM_SECONDARY_ADDRESS="<second-forwarder-platform-package-address>"
export PLATFORM_OWNER_ADDRESS="<first-platform-owner-address>"
export PLATFORM_SECONDARY_OWNER_ADDRESS="<second-platform-owner-address>"
export APTOS_PROFILE="<aptos-cli-profile>"
```

`CRE_CANARY_RECEIVER_ADDRESS` must match the account used by `APTOS_PROFILE`.

If you do not know `PLATFORM_OWNER_ADDRESS`, query it from the deployed platform package:

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_ADDRESS}::forwarder::get_owner"
```

Repeat for the secondary platform owner:

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${PLATFORM_SECONDARY_ADDRESS}::forwarder::get_owner"
```

## Compile

Run from this directory:

```sh
cd contracts/cre-receiver

aptos move compile \
  --named-addresses cre_canary_receiver="$CRE_CANARY_RECEIVER_ADDRESS",platform="$PLATFORM_ADDRESS",owner="$PLATFORM_OWNER_ADDRESS",platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

## Publish

Publishing runs `init_module`, which registers callbacks with both storage modules.

```sh
aptos move publish \
  --profile "$APTOS_PROFILE" \
  --named-addresses cre_canary_receiver="$CRE_CANARY_RECEIVER_ADDRESS",platform="$PLATFORM_ADDRESS",owner="$PLATFORM_OWNER_ADDRESS",platform_secondary="$PLATFORM_SECONDARY_ADDRESS",owner_secondary="$PLATFORM_SECONDARY_OWNER_ADDRESS"
```

## Verify

Check that the module published and state initialized:

```sh
aptos move view \
  --profile "$APTOS_PROFILE" \
  --function-id "${CRE_CANARY_RECEIVER_ADDRESS}::canary_receiver::get_counter"
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

- A receiver must be registered with each forwarder/storage package that will call it.
- This package is intended to be deployed once per environment, with that environment's two forwarder/storage package addresses passed as `platform` and `platform_secondary`.
- If two forwarders use the same Move module names at different addresses, the receiver still needs two static dependencies with distinct named addresses.
- Move module names cannot clash at the publisher account. If the account already has a module with the same name, publish will fail with `EMODULE_NAME_CLASH`.
