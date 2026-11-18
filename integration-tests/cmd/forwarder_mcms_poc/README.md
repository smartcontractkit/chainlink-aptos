# Forwarder ← MCMS PoC

This proves that MCMS can control **two** forwarders that have **no MCMS integration**, without changing or redeploying them. The two forwarders mirror `platform` and `platform_secondary`. MCMS controls both through **one adapter**, and **MCMS publishes that adapter itself**:

```
mcms::execute ── dispatch hook ──► forwarder_mcms_adapter::adapter::mcms_entrypoint
                                     │ get_callback_params → signer of the adapter's MCMS owner account
                                     │ first arg = target forwarder address
                                     ├─ static call ──► dummy_forwarder::forwarder::<fn>(&signer, ...)
                                     └─ static call ──► dummy_forwarder_secondary::forwarder::<fn>(&signer, ...)
```

How control is handed over:
- **Both forwarders' owner** is set to the adapter's **MCMS owner resource account**, using each forwarder's existing two-step `transfer_ownership` / `accept_ownership`. `accept_ownership` must go through MCMS → adapter, because only MCMS can produce that account's signer.
- **The adapter is published through `mcms_deployer`** (`stage_code_chunk_and_publish_to_object(seed)`) in a bypass proposal. Its code object is therefore owned by the same MCMS owner account from the start, and no EOA ever owns it.

## Packages

- **`contracts/poc/dummy_forwarder`**, package `DummyForwarder`, named addresses `dummy_forwarder` / `owner`. It mirrors `platform::forwarder`'s ownership model, with a `u64` value in place of the configs.
- **`contracts/poc/dummy_forwarder_secondary`**, package `DummyForwarderSecondary`, named addresses `dummy_forwarder_secondary` / `owner_secondary`. It's the same code, copied the way `platform_secondary` copies `platform`.
- **`contracts/poc/forwarder_mcms_adapter`**:
  - depends on MCMS and both dummy forwarders;
  - has one module and one entrypoint;
  - its functions are `set_value(forwarder, u64)`, `transfer_ownership(forwarder, to)` and `accept_ownership(forwarder)`;
  - `forwarder` must be one of the two forwarder addresses, otherwise the call aborts with `E_UNKNOWN_FORWARDER` (`0x10002`).

## 0. Prereqs

- `aptos` CLI. The repo pins 9.4.0; newer versions should work.
- An ed25519 testnet account funded with a few APT (https://aptos.dev/network/faucet).
- Go compiles packages with `--skip-fetch-latest-git-deps`, so the AptosFramework git dependency must already be cached. Running step 1 caches it.

## 1. Move unit tests (local)

```bash
cd contracts/poc/dummy_forwarder           && aptos move test --dev
cd ../dummy_forwarder_secondary            && aptos move test --dev
cd ../forwarder_mcms_adapter               && aptos move test --dev
```

The adapter tests run the full MCMS dispatch → adapter → forwarder chain locally. They check that:
- both forwarders can be handed to MCMS;
- each op touches only its target;
- the old owners are rejected afterwards;
- an unknown forwarder or an unknown function aborts;
- ownership of one forwarder can be handed back without affecting the other.

## 2. Testnet run (Go SDK)

From `integration-tests/`. **Use a fresh state file.** Older state files hold an adapter published by an EOA, with the single-forwarder ABI.

```bash
export DEPLOYER_KEY=0x...            # ed25519 private key (pays gas, submits txs)
# optional: export MCMS_SIGNER_KEY=...  # secp256k1 key for the 1-of-1 MCMS signer; generated + saved to the state file if unset

go run ./cmd/forwarder_mcms_poc all --state-file poc-state-v2.json
```

You can also run the steps one at a time; addresses are persisted in the state file. The steps that act on forwarders take `--target primary|secondary|both`, which defaults to `both`.

| Step | What it does |
|---|---|
| `deploy-forwarder` | Deploys both dummy forwarders to code objects; owner = deployer |
| `set-value 7` | Deployer calls `set_value(7)` directly on the target(s) |
| `status` | Prints both forwarders' value, owner and pending owner; the adapter code object's owner; `is_owned_code_object` |
| `deploy-mcms` | Deploys MCMS (owner = deployer); bypasser role = 1-of-1 with the MCMS signer key |
| `mcms-own-self` | The deployer calls `mcms_account::transfer_ownership_to_self`; an MCMS proposal accepts. **Required before MCMS can publish code:** `mcms_deployer` checks that its caller (`@mcms`) is the MCMS owner. Afterwards the deployer has no MCMS admin rights. |
| `deploy-adapter` | **MCMS publishes the adapter.** It first runs `mcms-own-self` if needed. See the steps below the table. `--adapter-seed` overrides the seed; each seed works only once. |
| `transfer-to-mcms` | The deployer calls `transfer_ownership(adapterOwner)` on each target. Then **one** MCMS proposal calls the adapter's `accept_ownership(<fwd>)` for each target. |
| `mcms-set-value 42` | **One** proposal sets primary = 42 and secondary = 43. It checks both values, then checks that direct deployer `set_value` aborts with `E_NOT_OWNER` (`0x50007`) on both. |
| `mcms-bad-target` | A proposal calls the adapter's `set_value(<unknown addr>, 1)`. This must fail with `E_UNKNOWN_FORWARDER` (`0x10002`). |
| `mcms-transfer-back` | A proposal calls the adapter's `transfer_ownership(<fwd>, deployer)` for each target; the deployer accepts. |

What `deploy-adapter` does:
1. Computes the adapter and owner addresses from the seed.
2. Compiles the adapter against both forwarders.
3. Submits a bypass proposal with the `mcms_deployer` stage/publish ops.
4. Asserts that `mcms_owner_address`, the code-object owner and `is_owned_code_object` all match.

`all` runs, in order:
1. `deploy-forwarder`
2. `set-value 7`
3. `deploy-mcms`
4. `deploy-adapter`
5. `transfer-to-mcms`
6. `mcms-set-value 42`
7. `mcms-bad-target`
8. `status`

PoC proposals set `overridePreviousRoot`, so a deliberately failed op (from `mcms-bad-target`) doesn't block the next proposal.

Flags:
- `--rpc-url`: default testnet.
- `--state-file`
- `--target`
- `--adapter-seed`
- `--deploy-max-gas`: default 2,000,000. The account must hold `max_gas × gas_price`. Raise this if a deploy fails with `OUT_OF_GAS`.

**MCMS signer keys:** MCMS signers are EVM addresses recovered from secp256k1 signatures, so the Aptos ed25519 deployer key can't be the MCMS signer. The same operator simply holds both keys.
