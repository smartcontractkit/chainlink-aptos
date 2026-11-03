# Forwarder ← MCMS PoC

Proves that MCMS can control a forwarder that has **no MCMS integration**, without changing or redeploying the forwarder:

```
mcms::execute ── dispatch hook ──► forwarder_mcms_adapter::adapter::mcms_entrypoint
                                     │ get_callback_params → signer of the adapter's MCMS owner account
                                     └─ static call ──► dummy_forwarder::forwarder::set_value(&signer, n)
```

The forwarder's owner is set to the adapter's **MCMS owner resource account**, using the forwarder's existing 2-step `transfer_ownership` / `accept_ownership`. The `accept_ownership` step must go through MCMS → adapter, because only MCMS can produce that account's signer.

Packages:
- `contracts/poc/dummy_forwarder`: mirrors `platform::forwarder`'s ownership model, with a `u64` value instead of configs.
- `contracts/poc/forwarder_mcms_adapter`: depends on `ChainlinkManyChainMultisig` + `DummyForwarder`.

## 0. Prereqs

- `aptos` CLI. The repo pins 9.4.0; newer versions should work.
- An ed25519 testnet account funded with a few APT (https://aptos.dev/network/faucet).
- Go compiles packages with `--skip-fetch-latest-git-deps`, so the AptosFramework git dependency must already be cached. Running step 1 caches it.

## 1. Move unit tests (local)

```bash
cd contracts/poc/dummy_forwarder && aptos move test --dev
cd ../forwarder_mcms_adapter     && aptos move test --dev
```

`adapter::test_mcms_controls_forwarder` runs the full MCMS dispatch → adapter → forwarder chain locally:
1. Transfer ownership to the adapter's MCMS owner.
2. MCMS `accept_ownership`.
3. MCMS `set_value(42)`.
4. MCMS hands ownership back.

## 2. Testnet run (Go SDK)

From `integration-tests/`:

```bash
export DEPLOYER_KEY=0x...            # ed25519 private key (pays gas, submits txs)
# optional: export MCMS_SIGNER_KEY=...  # secp256k1 key for the 1-of-1 MCMS signer; generated + saved to poc-state.json if unset

go run ./cmd/forwarder_mcms_poc all
```

Or step by step. Addresses are persisted in `poc-state.json`.

| Step | What it does |
|---|---|
| `deploy-forwarder` | Deploys `dummy_forwarder` to a code object; owner = deployer |
| `set-value 7` | Deployer calls `forwarder::set_value(7)` directly |
| `status` | Prints value, owner, pending owner and addresses |
| `deploy-mcms` | Deploys MCMS (owner = deployer); bypasser role = 1-of-1 with the MCMS signer key |
| `deploy-adapter` | Deploys the adapter compiled against the deployed forwarder + MCMS; `init_module` registers the MCMS entrypoint; prints the adapter's MCMS owner account |
| `transfer-to-mcms` | Deployer calls `transfer_ownership(adapterOwner)`, then an MCMS proposal calls adapter `accept_ownership` |
| `mcms-set-value 42` | MCMS proposal calls adapter `set_value(42)`; checks the value, and checks that a direct deployer `set_value` now aborts with `E_NOT_OWNER` |
| `mcms-transfer-back` | MCMS proposal calls adapter `transfer_ownership(deployer)`; deployer accepts |

Flags:
- `--rpc-url`: default testnet.
- `--state-file`
- `--deploy-max-gas`: default 2,000,000. The account must hold `max_gas × gas_price`. Raise this if a deploy fails with `OUT_OF_GAS`.

**MCMS signer keys:** MCMS signers are EVM addresses recovered from secp256k1 signatures, so the Aptos ed25519 deployer key can't be the MCMS signer. The same operator simply holds both keys.

## Optional: deploy the dummy forwarder with the CLI instead

```bash
cd contracts/poc/dummy_forwarder
aptos move deploy-object --address-name dummy_forwarder --named-addresses owner=<DEPLOYER_ADDR> --profile <testnet-profile>
aptos move run  --function-id <FWD_ADDR>::forwarder::set_value --args u64:7 --profile <testnet-profile>
aptos move view --function-id <FWD_ADDR>::forwarder::get_value --profile <testnet-profile>
```

Then put `"forwarder": "<FWD_ADDR>"` into `poc-state.json` and continue from `deploy-mcms`.
