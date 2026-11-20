# CRE forwarder governance on Aptos

These changesets put the two Aptos CRE forwarders under a dedicated MCMS:
- `platform`, the **zone-a** primary forwarder;
- `platform_secondary`, the **zone-b** secondary forwarder.

They do this through `forwarder_mcms_adapter` (`contracts/forwarder_mcms_adapter`). Once MCMS governs the forwarders, the same changesets configure them through MCMS proposals.

## Datastore refs

| type | version | qualifier | written by |
|---|---|---|---|
| `AptosForwarder` | 1.0.0 | `zone-a` / `zone-b` | `DeployForwarders`, or imported for existing forwarders (`catalog_create_address` pipeline); read by every changeset |
| `AptosManyChainMultisig` | 1.0.0 | `CLLCRE` (default) | `DeployCREMCMS` |
| `AptosForwarderMcmsAdapter` | 1.0.0 | `CLLCRE` | `DeployForwarderAdapter` |
| `AptosForwarderMcmsAdapterOwner` | 1.0.0 | `CLLCRE` | `DeployForwarderAdapter`. This is the adapter's MCMS owner account, and the address both forwarders are handed to. |

## Lifecycle

| # | changeset | mode | notes |
|---|---|---|---|
| 0 | `DeployForwarders` | direct | Deploys `platform` (zone-a) and/or `platform_secondary` (zone-b) with the deployer key and records the `AptosForwarder` refs. Owner defaults to the deployer. Not needed for forwarders that already exist; import those with `catalog_create_address` instead. |
| 1 | `DeployCREMCMS` | direct deploy + proposal | Deploys and configures MCMS and transfers ownership to itself. The proposal accepts that ownership and sets the min delay. **Execute it before step 2.** |
| 2 | `DeployForwarderAdapter` | proposal | Publishes the adapter through `mcms_deployer`, compiled against the zone-a/zone-b forwarders. Requires MCMS to own itself. Logs and records the adapter owner account. |
| 3 | `TransferForwarderOwnership` | direct, or MCMS | **Direct:** the deployer, which owns the forwarders, proposes `To`. `To` defaults to the adapter owner, which is the staging handover. A native multisig owner (prod) proposes the adapter owner with its own tooling instead. **MCMS:** hands forwarders back out; `To` is required. |
| 4 | `AcceptForwarderOwnership` | MCMS, or direct | **MCMS:** the adapter owner accepts; the pending owner must be the adapter owner. **Direct:** the deployer accepts. |
| 5 | `SetForwarderConfig` / `ClearForwarderConfig` | direct, or MCMS | **Direct** while the deployer owns the forwarder. **MCMS** once the adapter owner does. |

The mode is chosen by `MCMS`: leave it unset to send directly with the deployer key, or set it to a `TimelockConfig` to build a proposal. Each changeset checks that the forwarder's on-chain owner matches the chosen mode, so a run in the wrong mode fails in preconditions, before anything is sent or proposed.

`SetForwarderConfig` takes the DON's node IDs and looks up each node in the job distributor:
- Node IDs can be CSA keys, `p2p_…` peer IDs, or `node_…` JD IDs; all entries must use the same form.
- Each node's Aptos OCR2 onchain signing key (ed25519) for that chain becomes an oracle.
- Bootstrap nodes are skipped.
- The forwarder's bounds are enforced: at least `3F+1` and at most 31 signers.

## Example inputs

```yaml
# 1. Deploy the CRE MCMS
chainSelector: 743186221051783445 # aptos-testnet
mcms:
  proposer:  { quorum: 1, signers: ["0x..."], groupSigners: [] }
  bypasser:  { quorum: 1, signers: ["0x..."], groupSigners: [] }
  canceller: { quorum: 1, signers: ["0x..."], groupSigners: [] }
  timelockMinDelay: 0
timelockConfig: { mcmsAction: schedule, minDelay: 0s }

# 3. Staging handover (deployer-owned forwarders) -> adapter owner
chainSelector: 743186221051783445

# 4. MCMS accepts both forwarders
chainSelector: 743186221051783445
mcms: { mcmsAction: schedule, minDelay: 0s }

# 5. Set a DON config on zone-a through MCMS
chainSelector: 743186221051783445
zone: zone-a
don: { id: 1, configVersion: 1, f: 1, nodeIDs: ["<csa key>", "..."] }
mcms: { mcmsAction: schedule, minDelay: 0s }
```

## Tests

- **Unit:** `go test ./cre/` in `deployment`, covering signer resolution, zones, and validation.
- **Lifecycle:** `integration-tests/deployment/cre`. It runs the whole flow on an Aptos localnet, which needs Docker and the Aptos CLI.
