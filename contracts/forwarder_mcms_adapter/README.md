# ChainlinkForwarderMcmsAdapter

This package lets MCMS govern the two CRE forwarders, `platform::forwarder` and `platform_secondary::forwarder`, without changing or redeploying them. Receivers are compiled against the forwarder addresses, so those addresses must not change.

```
mcms::execute → timelock_dispatch → mcms_registry (dispatch hook)
  → forwarder_mcms_adapter::adapter::mcms_entrypoint
  → get_callback_params → signer of the adapter's MCMS owner account
  → platform::forwarder::<fn> | platform_secondary::forwarder::<fn>   (static call)
```

The two forwarders' owner checks only compare the caller's address with `State.owner_address`. Setting that owner on both forwarders to `adapter::mcms_owner_address()` gives MCMS owner control of both, and nothing else can act as that owner. Only `mcms_registry` holds that account's signer capability, and it hands the signer out only during an MCMS-executed op.

The adapter has no state and no admin functions.

## Calls

Each MCMS operation targets `<adapter address>::adapter::<function>`.

**The first BCS argument is always the target forwarder address.** It must be `@platform` or `@platform_secondary`; any other address aborts with `E_UNKNOWN_FORWARDER`. The function names and the remaining arguments match the forwarder's owner-gated entry functions exactly:

| function | data (BCS, concatenated) |
|---|---|
| `set_config` | `forwarder: address, don_id: u32, config_version: u32, f: u8, oracles: vector<vector<u8>>` |
| `clear_config` | `forwarder: address, don_id: u32, config_version: u32` |
| `transfer_ownership` | `forwarder: address, to: address` |
| `accept_ownership` | `forwarder: address` |

These four are every owner-gated function on the forwarder. The adapter deliberately does not cover these, because none of them is owner-gated:
- `forwarder::report`, which anyone may transmit;
- `storage::register`, which receivers call;
- `storage::migrate_to_v2`, which is permissionless;
- views.

| Error | Code | Meaning |
|---|---|---|
| `E_UNKNOWN_FUNCTION` | `0x10001` | The function isn't one of the four above |
| `E_UNKNOWN_FORWARDER` | `0x10002` | The target is neither forwarder |
| `E_SAME_FORWARDER_ADDRESSES` | `0x10003` | Publish-time guard: `@platform == @platform_secondary` |
| `E_NOT_PUBLISHED_BY_MCMS` | `0x50004` | Publish-time guard: the adapter was not published through `mcms_deployer` |
| `mcms::bcs_stream` `E_NOT_CONSUMED` / `E_OUT_OF_BYTES` | `0x30003` / `0x20002` | Trailing bytes or missing arguments |

Forwarder errors such as `E_NOT_OWNER` and `E_INSUFFICIENT_SIGNERS` pass through unchanged.

Views: `mcms_owner_address()`, `forwarders()`, `type_and_version()`.

## Named addresses

| name | value |
|---|---|
| `forwarder_mcms_adapter` | the adapter's code object address. When published via `mcms_deployer`, this is `mcms_registry::get_new_code_object_address(seed)` |
| `mcms` | the MCMS instance that governs the forwarders |
| `platform`, `platform_secondary` | the deployed forwarders |
| `owner`, `owner_secondary` | only needed to compile the forwarder dependencies; any value works |

At publish time Aptos checks that each dependency's package name matches the package deployed at that address. The names here are `ChainlinkPlatform` and `ChainlinkPlatformSecondary`, which match every environment.

## Security: no path to the forwarders without MCMS

Whoever controls a forwarder's config controls what it writes on-chain. That is why the adapter must never act on a forwarder without MCMS. These are the only ways to get the signer of the forwarder owner (the adapter's MCMS owner account), and why each one requires MCMS:

| Path | Why only MCMS |
|---|---|
| `mcms_registry::get_callback_params` (used by `mcms_entrypoint`) | Returns the signer only while `ExecutingCallbackParams` exists for this owner account. That is created only by `start_dispatch`, which is `friend`-only (`mcms::mcms`, `mcms_deployer`), so it runs only inside `mcms::execute` of a signed, quorum-approved root. The params are consumed on read, and they require the `McmsCallback` proof type, which only this module can construct. Tests: `test_entrypoint_not_callable_outside_dispatch`, `test_other_module_cannot_take_signer_during_dispatch`. |
| `mcms_registry::get_signer_for_code_object_upgrade` | `friend`-only. It is used solely by `mcms_deployer` to upgrade code, inside an MCMS op. |
| The signer capability itself | Stored in `OwnerRegistration` under the resource account; only `mcms_registry` can read it. The account was created by `@mcms` as a resource account and has no private key. |
| **Upgrading the adapter** to new code that misuses the signer during a legitimate MCMS op | **Upgrade authority is MCMS-only.** `init_module` aborts with `E_NOT_PUBLISHED_BY_MCMS` unless the adapter's code object is owned by MCMS, which is only true when it is published through `mcms_deployer`. An EOA-published copy cannot be initialized, so no EOA ever holds upgrade rights. Any later upgrade is itself an `mcms_deployer` op behind a proposal. Test: `test_init_requires_mcms_published_code`. |

Within an MCMS op, the adapter only:
- calls the four owner-gated functions;
- calls them only on `@platform` / `@platform_secondary`;
- passes the arguments through unchanged, with exact decoding (no trailing or missing bytes).

The forwarder's own validation still applies. The adapter holds no state, has no other public functions, and never returns or stores the signer.

**Trust that remains outside this package:**
- **The MCMS configuration.** Signers, quorum, and especially the **bypasser** role, which executes without the timelock delay, are now the security boundary for forwarder config. Use a production quorum and decide deliberately who may bypass.
- **The forwarder code objects.** Until each forwarder's code object is handed to MCMS (see below), whoever owns it can upgrade the forwarder itself, which bypasses any owner check.
- **The handover target.** The native multisig must call `transfer_ownership` with exactly `adapter::mcms_owner_address()`. Check this before signing.

## Deploying and handing over

This sequence was proven on testnet with dummy forwarders; see `integration-tests/cmd/forwarder_mcms_poc` on the `mcms-adapter-poc` branch.

1. **MCMS must own itself.** `mcms_deployer` checks that its caller (`@mcms`) is the MCMS owner. If needed: `mcms_account::transfer_ownership_to_self`, then an MCMS proposal runs `mcms_account::accept_ownership`.
2. **Publish the adapter through MCMS.** Pick a seed, compile with `forwarder_mcms_adapter = get_new_code_object_address(seed)`, and propose the `mcms_deployer::stage_code_chunk*` ops (`deployment/ccip/utils.CreateChunksAndStage`). The adapter's code is then owned by its MCMS owner account (`get_new_code_object_owner_address(seed)`, the same account as `mcms_owner_address()`). No externally owned account (EOA) ever owns it.
3. **The current forwarder owner (native multisig)** calls `forwarder::transfer_ownership(adapter::mcms_owner_address())` on each forwarder.
4. **One MCMS proposal** calls `adapter::accept_ownership(@platform)` and `adapter::accept_ownership(@platform_secondary)`.

From then on, `set_config` / `clear_config` go through MCMS proposals. To move ownership away from MCMS later, call `adapter::transfer_ownership(<forwarder>, <new owner>)`; the new owner then accepts directly.

The forwarders' **code objects** (upgrade authority) are a separate handover:
1. The current owner calls `0x1::object::transfer(F, mcms_registry::get_preexisting_code_object_owner_address(F))`.
2. `mcms_registry::create_owner_for_preexisting_code_object(F)` registers that owner.

Upgrades then go through `mcms_deployer::stage_code_chunk_and_upgrade_object_code`.

## Tests

```bash
aptos move test --dev --skip-fetch-latest-git-deps --package-dir contracts/forwarder_mcms_adapter
```

The suite covers both forwarders, every function, isolation between the two forwarders, pass-through of the forwarder's own validation, rejection of old owners, and malformed input. It also covers the security properties: no signer outside an MCMS dispatch, no signer for any other proof type even during a dispatch, and no initialization unless MCMS published the code. Unit tests cannot publish through `mcms_deployer`, so they register the entrypoint with `test_init_module`, which skips that check. The passing case of the check is proven by publishing through MCMS on testnet.
