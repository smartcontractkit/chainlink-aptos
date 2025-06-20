# CCIP Token Pools on Aptos

## Overview

CCIP Token Pools are smart contracts that manage the cross-chain transfer of tokens in the Chainlink Cross-Chain Interoperability Protocol (CCIP). On Aptos, token pools handle the locking/releasing or burning/minting of tokens when they are transferred to/from other blockchains.

### Key Points

Tokens with dynamic dispatch are supported for both pools, however the deposit and withdraw overrides are not invoked during `lock_or_burn` and `release_or_mint` functions.

## Pool Types

There are **3 types** of token pools available on Aptos:

1. **Lock/Release Token Pool** (`lock_release_token_pool`)
2. **Burn/Mint Token Pool** (`burn_mint_token_pool`)
3. **USDC Token Pool** (`usdc_token_pool`)

### 1. Lock/Release Token Pool (`lock_release_token_pool`)

- Tokens that have dynamic dispatch configured for **custom deposit and withdraw functions must provide a `transfer_ref`** when initializing this pool.
- Tokens which do not have `transfer_ref` available can still register with this pool but **they must not have custom dispatch logic** on deposit and withdraw configured.

**Operation Modes**:

1. **With TransferRef**:

   - Uses `deposit_with_ref()` and `withdraw_with_ref()`
   - Bypasses custom deposit and withdraw dispatch logic
   - **Required** for tokens with custom dispatch

2. **Without TransferRef**:
   - Uses `fungible_asset::deposit/withdraw()`
   - **Only allowed** for tokens without dynamic dispatch configured

**Mechanism**:

- **Outbound**: Locks tokens in the pool's store
- **Inbound**: Releases previously locked tokens

**When to Use**:

- For tokens that exist natively on Aptos and need to be "locked" when sent to other chains
- You want to maintain the original token supply on Aptos
- Tokens that do not have mint/burn refs saved

#### Token Pool Configuration Matrix

| Has Dynamic Dispatch | TransferRef Provided | Is Valid   |
| -------------------- | -------------------- | ---------- |
| ❌                   | ❌ **(Optional)**    | **Yes ✅** |
| ❌                   | ✅ **(Optional)**    | **Yes ✅** |
| ✅                   | ✅ **Mandatory**     | **Yes ✅** |
| ✅                   | ❌ **Mandatory**     | **No ❌**  |

### 2. Burn/Mint Token Pool (`burn_mint_token_pool`)

- `mint_ref` and `burn_ref` are required for initialization with this pool.

**Mechanism**:

- **Outbound**: Burns tokens from total supply
- **Inbound**: Mints new tokens, increasing total supply

**When to Use**:

- Total supply must be increased or decreased across swaps
- Tokens which need to be burned and minted across chains, such as wrapped or synthetic tokens
- You have mint/burn capabilities for the token
- Simpler accounting model preferred

### 3. USDC Token Pool (`usdc_token_pool`)

- Specialized pool for USDC tokens that integrates with Circle's Cross-Chain Transfer Protocol (CCTP)
- Uses Circle's native burn/mint mechanism for USDC transfers
- Requires integration with Circle's `message_transmitter` and `token_messenger_minter` contracts

**Mechanism**:

- **Outbound**: Burns USDC via Circle's protocol and emits attestation
- **Inbound**: Mints USDC using Circle's attestation system

**When to Use**:

- Specifically for USDC token transfers

## Deployment Guide

### Prerequisites

1. **Token Must Exist**: Deploy your fungible asset first
2. **Token Ownership Required**: **Only the token owner can deploy pools**. The deployer must be one of:
   - The direct owner of the token object
   - The root owner of the token object

### Deploy Pool Contract

For **Lock/Release Pool**:

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/ccip_token_pools/lock_release_token_pool \
  --address-name lock_release_token_pool \
  --named-addresses lock_release_local_token=<YOUR_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
mcms_register_entrypoints=<MCMS_REGISTER_ENTRYPOINTS_ADDRESS>
```

For **Burn/Mint Pool**:

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/ccip_token_pools/burn_mint_token_pool \
  --address-name burn_mint_token_pool \
  --named-addresses burn_mint_local_token=<YOUR_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
mcms_register_entrypoints=<MCMS_REGISTER_ENTRYPOINTS_ADDRESS>
```

For **USDC Pool**:

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/ccip_token_pools/usdc_token_pool \
  --address-name usdc_token_pool \
  --named-addresses local_token=<YOUR_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
message_transmitter=<MESSAGE_TRANSMITTER_ADDRESS>,\
token_messenger_minter=<TOKEN_MESSENGER_MINTER_ADDRESS>,\
deployer=<DEPLOYER_ADDRESS>
```

### Initialize Pool

**Lock/Release Pool**:

```move
// For tokens WITHOUT dynamic dispatch
lock_release_token_pool::initialize(admin_signer, option::none());

// For tokens WITH dynamic dispatch
lock_release_token_pool::initialize(admin_signer, option::some(transfer_ref));
```

**Burn/Mint Pool**:

```move
burn_mint_token_pool::initialize(admin_signer, burn_ref, mint_ref);
```

**USDC Pool**:

```move
usdc_token_pool::initialize(admin_signer);
```

### Configure Cross-Chain Support

```move
// Add supported destination chains
pool::apply_chain_updates(
    admin_signer,
    vector[], // remote_chain_selectors_to_remove
    vector[destination_chain_selector], // remote_chain_selectors_to_add
    vector[vector[remote_pool_address]], // remote_pool_addresses_to_add
    vector[remote_token_address] // remote_token_addresses_to_add
);
```

### Set Rate Limits

```move
pool::set_chain_rate_limiter_config(
    admin_signer,
    remote_chain_selector,
    true,  // outbound_is_enabled
    1000000, // outbound_capacity
    100,     // outbound_rate
    true,    // inbound_is_enabled
    1000000, // inbound_capacity
    100      // inbound_rate
);
```

### Configure Allowlist

Configure who can call the pool functions:

```move
pool::apply_allowlist_updates(
    admin_signer,
    vector[], // removes
    vector[0xabc], // adds
);
```

## Token Admin Registry Integration

### Automatic Registration Process

The Token Admin Registry manages which pools are authorized for specific tokens. It maintains a **1:1 mapping** of tokens to pools.

**During pool deployment**, each pool automatically registers itself with the Token Admin Registry via the `init_module` function:

```move
// Automatic registration during pool deployment (in init_module)
token_admin_registry::register_pool(
    publisher,
    pool_module_name,  // e.g., b"lock_release_token_pool"
    token_address,
    administrator_address,
    CallbackProof {}
);
```

This ensures that:

- The token is immediately associated with the new pool
- The specified administrator has control over the pool
- The pool can be called by CCIP for cross-chain operations

### Pool Management Functions

**Check Current Pool**:

```move
let pool_address = token_admin_registry::get_pool(token_address);
```

**Check Pool Administrator**:

```move
let admin_address = token_admin_registry::get_administrator(token_address);
```

**Transfer Pool Admin**:

```move
token_admin_registry::transfer_admin_role(admin_signer, token_address, new_admin);
```

**Accept Admin Role**:

```move
token_admin_registry::accept_admin_role(new_admin_signer, token_address);
```

### Pool Unregistration

To completely remove a pool from the Token Admin Registry:

```move
token_admin_registry::unregister_pool(
    admin_signer,
    token_address
);
```

**⚠️ Warning**: Unregistering a pool will:

- Remove the token-to-pool mapping
- Disable cross-chain transfers for that token unless registered with another pool
- Require re-registration to restore functionality

### Pool Upgrades

To upgrade an existing pool to a new version:

#### Option 1: Upgrade Existing Pool Object

If you want to upgrade the code of an existing pool:

```bash
aptos move upgrade-object \
  --object-address <TOKEN_POOL_ADDRESS> \
  --address-name lock_release_token_pool \
  --named-addresses lock_release_local_token=<YOUR_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
mcms_register_entrypoints=<MCMS_REGISTER_ENTRYPOINTS_ADDRESS>
```

Where `TOKEN_POOL_ADDRESS` is the address of the existing pool object.

#### Option 2: Deploy New Pool and Switch Registration

To switch pools for a token, you must deploy a new pool contract and use the unregister/register pattern to update the Token Admin Registry.

1. **Deploy New Pool**: Deploy the new pool contract using the deployment commands above

2. **Migrate Funds/Refs** (BEFORE unregistering):

   - For Lock/Release pools:
     - Move locked funds from old to new pool
     - Migrate TransferRef if provided
   - For Burn/Mint pools:
     - Migrate BurnRef and MintRef

3. **Unregister Old Pool**:

   ```move
   token_admin_registry::unregister_pool(
       admin_signer,
       token_address
   );
   ```

4. **Register New Pool**:

   ```move
   token_admin_registry::register_pool(
       new_pool_signer,
       pool_module_name,  // e.g., b"lock_release_token_pool"
       token_address,
       administrator_address,
       CallbackProof {}
   );
   ```

5. **Update Configurations**: Set up rate limits and chain configs on new pool

#### Upgrade Considerations

- **State Migration**: Plan how to handle existing state and locked funds
- **Downtime**: Coordinate upgrades to minimize service interruption
- **Testing**: Thoroughly test new pool versions before upgrading
- **Rollback Plan**: Have a strategy to revert if issues arise

## Configuration Best Practices

### Rate Limiting

- **Capacity**: Maximum token units (in smallest denomination) that can be transferred in a time window
- **Rate**: Token unit refill rate per second (in smallest denomination)
- **Separate Limits**: Configure different limits for inbound vs outbound
- **Denomination**: All rate limit values are specified in the token's smallest unit (e.g., for a token with 18 decimals, 1 full token = 10^18 units)

```move
// Conservative example for high-value tokens
// Note: All amounts are in the smallest denomination of the token (e.g., wei for ETH)
set_chain_rate_limiter_config(
    admin,
    chain_selector,
    true, 1000000,  // outbound: 1M units capacity (smallest denomination)
    100,            // 100 units/second refill (smallest denomination)
    true, 2000000,  // inbound: 2M units capacity (smallest denomination)
    200             // 200 units/second refill (smallest denomination)
);
```

### Multi-Chain Setup

```move
// Configure multiple destination chains
let chain_selectors = vector[ethereum_selector, polygon_selector, bsc_selector];
let remote_pools = vector[
    vector[eth_pool_address],
    vector[polygon_pool_address],
    vector[bsc_pool_address]
];
let remote_tokens = vector[eth_token, polygon_token, bsc_token];

apply_chain_updates(admin, vector[], chain_selectors, remote_pools, remote_tokens);
```

### Security Considerations

1. **TransferRef Storage**: Store TransferRef securely if provided
2. **Admin Key Management**: Use multi-sig for pool administration
3. **Rate Limits**: Set conservative limits initially
4. **Allowlists**: Consider using allowlists for restricted tokens
5. **Monitoring**: Monitor pool balances and cross-chain activity

## Troubleshooting

### Common Issues

**"Dispatchable token without transfer ref"**

- **Cause**: Token has custom dispatch but no TransferRef provided
- **Solution**: Provide TransferRef during initialization or create token without dynamic dispatch

**"Insufficient balance"**

- **Cause**: Pool doesn't have enough tokens for release
- **Solution**: Check pool balance and inbound transfer history, Fund pool if needed

**"Chain not supported"**

- **Cause**: Destination chain not configured
- **Solution**: Add chain via `apply_chain_updates()`

**"Rate limit exceeded"**

- **Cause**: Transfer exceeds configured rate limits
- **Solution**: Wait for rate limit refill or increase limits

**"Pool not registered"**

- **Cause**: Token is not associated with any pool in Token Admin Registry
- **Solution**: Deploy and register a pool for the token

### Diagnostic Commands

```move
// Check pool configuration
pool::get_supported_chains();
pool::balance();
pool::get_remote_pools(chain_selector);

// Check token admin registry
token_admin_registry::get_pool(token_address);
token_admin_registry::get_administrator(token_address);
```

## Migration from Other Chains

When bringing tokens from EVM chains to Aptos:

1. **Assess Token Type**:

   - Simple ERC-20 → Use any pool type
   - Custom logic → Implement equivalent in Aptos with dispatch

2. **Choose Pool Strategy**:

   - Keep original on source chain → Lock/Release
   - Burn on source, mint on Aptos → Burn/Mint
   - USDC specifically → USDC Pool

3. **Handle Custom Logic**:

   - Implement custom dynamic dispatch functions if needed
   - Always provide TransferRef for pools if token uses dynamic dispatch

4. **Configure Mappings**:
   - Map remote token addresses correctly
   - Set up bidirectional pool relationships

## Support and Resources

- **CCIP Documentation**: [Chainlink CCIP Docs](https://docs.chain.link/ccip)
- **Aptos Move Documentation**: [Aptos Developer Docs](https://aptos.dev)
- **Contract Source**: `contracts/ccip/ccip_token_pools/`
- **Example Implementations**: `contracts/ccip/ccip_token_pools/*/tests/`
