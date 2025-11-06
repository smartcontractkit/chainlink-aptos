# CCIP Token Pools on Aptos

## Overview

CCIP Token Pools are smart contracts that manage the cross-chain transfer of tokens in the Chainlink Cross-Chain Interoperability Protocol (CCIP). On Aptos, token pools handle the locking/releasing or burning/minting of tokens when they are transferred to/from other blockchains.

### Key Points

Tokens with dynamic dispatch are supported for most pools, however the deposit and withdraw overrides are not invoked during `lock_or_burn` and `release_or_mint` functions.

## Pool Types

There are **5 types** of token pools available on Aptos:

1. **Lock/Release Token Pool** (`lock_release_token_pool`)
2. **Burn/Mint Token Pool** (`burn_mint_token_pool`)
3. **USDC Token Pool** (`usdc_token_pool`)
4. **Managed Token Pool** (`managed_token_pool`)
5. **Regulated Token Pool** (`regulated_token_pool`)

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

### 4. Managed Token Pool (`managed_token_pool`)

- **Automatically registers with CCIP Token Admin Registry** during deployment
- Designed specifically for tokens deployed with the managed token package
- Uses allowlist-based permission system for secure mint/burn operations
- **Does not support dynamic dispatch** - calls `fungible_asset` module functions directly
- Managed token uses internal refs, not dynamic dispatch mechanisms

**Operation Modes**:

- Pool's address must be added to managed token's allowlists before operation
- Pool calls `managed_token::mint()` and `managed_token::burn()` functions directly
- Managed token validates permissions via allowlist checks
- Pool automatically registers with Token Admin Registry during deployment

**Mechanism**:

- **Outbound**: Pool calls managed token to burn tokens from total supply
- **Inbound**: Pool calls managed token to mint new tokens to recipient

**When to Use**:

- For tokens deployed with the managed token package
- When you need allowlist-based control over token operations
- Multiple protocol integrations while retaining developer control
- **Cannot be used with existing standard fungible assets**

### 5. Regulated Token Pool (`regulated_token_pool`)

- **Automatically registers with CCIP Token Admin Registry** during deployment
- Designed specifically for tokens deployed with the regulated token package
- Uses **bridge functions** (`bridge_mint()` and `bridge_burn()`) to bypass dynamic dispatch conflicts
- Requires `BRIDGE_MINTER_OR_BURNER_ROLE` authorization from the regulated token
- Maintains all regulatory controls (freezing, pausing, recovery)

**Operation Modes**:

- Pool's store address must have `BRIDGE_MINTER_OR_BURNER_ROLE` on the regulated token
- Pool calls `regulated_token::bridge_burn()` and `bridge_mint()` directly
- Bridge functions use `MintRef`/`BurnRef` directly to avoid fungible_asset store operations
- Resolves error 65564 caused by dynamic dispatch conflicts in standard pools

**Mechanism**:

- **Outbound**: Pool calls regulated token to burn tokens via bridge function, bypassing dispatch
- **Inbound**: Pool calls regulated token to mint new tokens to recipient via bridge function

**When to Use**:

- For tokens deployed with the regulated token package
- When you need regulatory compliance features (account freezing, pause, recovery)
- Role-based access control with RBAC system
- **Cannot be used with standard fungible assets**

**Key Difference from Burn/Mint Pool**:

- Uses specialized bridge functions instead of direct `fungible_asset` operations
- Required because regulated tokens have dynamic dispatch enabled
- Preserves all regulatory controls and security features

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

For **Managed Token Pool**:

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/ccip_token_pools/managed_token_pool \
  --address-name managed_token_pool \
  --named-addresses managed_token=<MANAGED_TOKEN_ADDRESS>,\
managed_token=<MANAGED_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
mcms_register_entrypoints=<MCMS_REGISTER_ENTRYPOINTS_ADDRESS>
```

For **Regulated Token Pool**:

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/ccip_token_pools/regulated_token_pool \
  --address-name regulated_token_pool \
  --named-addresses regulated_token=<REGULATED_TOKEN_ADDRESS>,\
ccip=<CCIP_ADDRESS>,\
ccip_token_pool=<CCIP_TOKEN_POOL_ADDRESS>,\
mcms=<MCMS_ADDRESS>,\
mcms_register_entrypoints=<MCMS_REGISTER_ENTRYPOINTS_ADDRESS>
```

### Initialize Pool

**Lock/Release Pool**:

```move
// For tokens WITHOUT dynamic dispatch
lock_release_token_pool::initialize(admin_signer, option::none(), rebalancer_address);

// For tokens WITH dynamic dispatch (must provide transfer_ref)
lock_release_token_pool::initialize(admin_signer, option::some(transfer_ref), rebalancer_address);
```

**Burn/Mint Pool**:

```move
burn_mint_token_pool::initialize(admin_signer, burn_ref, mint_ref);
```

**USDC Pool**:

```move
usdc_token_pool::initialize(admin_signer);
```

**Managed Token Pool**:

```move
// 1. Pool registers automatically during deployment

// 2. Token owner proposes administrator
token_admin_registry::propose_administrator(
    token_owner,
    managed_token::token_metadata(),
    administrator_address
);

// 3. Administrator accepts role
token_admin_registry::accept_admin_role(
    administrator_signer,
    managed_token::token_metadata()
);

// 4. Administrator activates the pool
token_admin_registry::set_pool(
    administrator_signer,
    managed_token::token_metadata(),
    @managed_token_pool
);

// 5. Add pool to token allowlists
let pool_store_address = managed_token_pool::get_store_address();

managed_token::apply_allowed_minter_updates(
    token_owner,
    vector[], // remove
    vector[pool_store_address] // add pool as minter
);

managed_token::apply_allowed_burner_updates(
    token_owner,
    vector[], // remove
    vector[pool_store_address] // add pool as burner
);
```

**Regulated Token Pool**:

```move
// 1. Pool registers automatically during deployment

// 2. Grant bridge role to pool's store address
let pool_store_address = regulated_token_pool::get_store_address();
regulated_token::grant_role(
    admin_signer,
    BRIDGE_MINTER_OR_BURNER_ROLE,
    pool_store_address
);

// 3. Token owner proposes administrator
token_admin_registry::propose_administrator(
    token_owner,
    regulated_token::token_metadata(),
    administrator_address
);

// 4. Administrator accepts role
token_admin_registry::accept_admin_role(
    administrator_signer,
    regulated_token::token_metadata()
);

// 5. Administrator activates the pool
token_admin_registry::set_pool(
    administrator_signer,
    regulated_token::token_metadata(),
    @regulated_token_pool
);
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

### Updated Registration Process

The Token Admin Registry manages which pools are authorized for specific tokens. The current flow supports **multiple pools per token** but only **one active pool** at a time.

**⚠️ Critical Requirement**: `propose_administrator` is the **only function** that adds tokens to `token_configs`. This means:

- It **must be called** before `accept_admin_role` or `set_pool` can work
- Without this step, the token will not exist in the registry's configuration
- All subsequent admin operations will fail if this step is skipped

### Step-by-Step Registration Flow

#### Step 1: Register Pool

During pool deployment, each pool automatically registers itself with the Token Admin Registry via the `init_module` function:

```move
// Automatic registration during pool deployment (in init_module)
token_admin_registry::register_pool(
    publisher,
    pool_module_name,  // e.g., b"lock_release_token_pool"
    token_address,
    CallbackProof {}
);
```

**This step:**

- Registers the pool for the token (multiple pools can be registered)
- **Does NOT activate the pool** for use
- **Does NOT add the token to token_configs**

#### Step 2: Propose Administrator

**⚠️ Authorization Required**: Only the **token owner** or **CCIP owner** can propose an administrator for the token:

```move
// Must be called by token owner or CCIP owner
token_admin_registry::propose_administrator(
    token_owner,
    token_address,
    proposed_admin_address
);
```

**This step:**

- **Verifies caller owns the token** or is CCIP owner (security checkpoint)
- Adds the token to `token_configs` (REQUIRED for later operations)
- Sets a pending administrator
- Can only be called if no administrator is already set

#### Step 3: Accept Admin Role

The proposed administrator must accept the role:

```move
// Must be called by the proposed administrator
token_admin_registry::accept_admin_role(
    proposed_admin_signer,
    token_address
);
```

**This step:**

- Sets the administrator as active
- Clears the pending administrator
- Enables the administrator to manage pools for this token

#### Step 4: Activate Pool

The administrator can now activate a specific registered pool:

```move
// Must be called by the token's administrator
token_admin_registry::set_pool(
    admin_signer,
    token_address,
    pool_address_to_activate
);
```

**This step:**

- Activates the specified pool for the token
- Replaces any previously active pool
- **Does NOT clean up** the previous pool's resources (old pool remains registered but inactive)

### Complete Flow Example

```move
// 1. Pool registers automatically during deployment (in init_module)
// token_admin_registry::register_pool(...) // Called automatically

// 2. Token owner proposes admin
token_admin_registry::propose_administrator(
    token_owner,
    managed_token::token_metadata(),
    pool_administrator_address
);

// 3. Proposed admin accepts role
token_admin_registry::accept_admin_role(
    pool_administrator,
    managed_token::token_metadata()
);

// 4. Admin activates the pool
token_admin_registry::set_pool(
    pool_administrator,
    managed_token::token_metadata(),
    @managed_token_pool  // Pool address to activate
);
```

### Multiple Pools Support

The new system allows multiple pools to be registered for the same token:

- **Registration**: Multiple pools can register for the same token (no uniqueness check)
- **Activation**: Only one pool can be active at a time via `set_pool`
- **Switching**: Administrators can switch between registered pools using `set_pool`
- **No Automatic Cleanup**: Previous pools remain registered but inactive when a new pool is activated

**Important Implications:**

- Inactive registered pools continue to exist and can be queried via `get_pool_local_token`
- Resources from inactive pools are not automatically cleaned up
- Multiple pool objects may exist for the same token simultaneously
- Only the active pool (returned by `get_pool`) should be trusted for operations

### Pool Management Functions

**Check Active Pool**:

```move
let active_pool_address = token_admin_registry::get_pool(token_address);
```

**Check Pool's Token** (works for ANY registered pool, not just active):

```move
let local_token = token_admin_registry::get_pool_local_token(pool_address);
```

**Check Token Configuration**:

```move
let (pool_address, admin, pending_admin) = token_admin_registry::get_token_config(token_address);
```

**Transfer Admin Role**:

```move
// Current admin proposes new admin
token_admin_registry::transfer_admin_role(current_admin, token_address, new_admin);

// New admin accepts
token_admin_registry::accept_admin_role(new_admin_signer, token_address);
```

### Security Considerations

⚠️ **Critical Security Issue**: `get_pool_local_token` returns information for ANY registered pool, **even if it's not currently active**. This could allow adversaries to mislead users into believing a pool is active when it's only registered but not in use.

**Attack Scenario:**

1. Adversary deploys a malicious pool and registers it for a legitimate token
2. Adversary calls `get_pool_local_token(malicious_pool)` and gets the legitimate token address
3. Users might assume the malicious pool is the active pool for that token
4. Users interact with the malicious pool instead of the legitimate active pool

**Example of safe verification**:

```move
// DON'T just trust get_pool_local_token
let local_token = token_admin_registry::get_pool_local_token(some_pool);

// DO verify the pool is actually active for the token
let active_pool = token_admin_registry::get_pool(local_token);
assert!(active_pool == some_pool, E_POOL_NOT_ACTIVE);
```

**Best Practice**: Always verify pool activation status before trusting any pool operations.

### Pool Unregistration

To completely remove a pool from the Token Admin Registry:

```move
token_admin_registry::unregister_pool(
    admin_signer,
    token_address
);
```

**⚠️ Critical Warning**: `unregister_pool` is **highly destructive** and will:

- Remove the pool registration completely
- **Remove the token from `token_configs` entirely** (destroys all token admin configuration)
- Remove the administrator assignment for the token
- Emit a `TokenUnregistered` event
- **Disable ALL pool operations** for that token until completely re-registered

**Recovery Process**: To restore functionality after unregistration, you must restart the **entire 4-step flow**:

1. Deploy new pool (auto-registers)
2. `propose_administrator` (re-adds token to `token_configs`)
3. `accept_admin_role`
4. `set_pool`

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

**"Not allowed minter/burner" (Managed Token Pool)**

- **Cause**: Pool not added to managed token's allowlists
- **Solution**: Add pool's store address to managed token allowlists:
  ```move
  managed_token::apply_allowed_minter_updates(token_owner, vector[], vector[pool_store_address]);
  managed_token::apply_allowed_burner_updates(token_owner, vector[], vector[pool_store_address]);
  ```

**"Missing role" or "Unauthorized" (Regulated Token Pool)**

- **Cause**: Pool's store address doesn't have `BRIDGE_MINTER_OR_BURNER_ROLE`
- **Solution**: Grant the bridge role to pool's store address:
  ```move
  let pool_store_address = regulated_token_pool::get_store_address();
  regulated_token::grant_role(admin_signer, BRIDGE_MINTER_OR_BURNER_ROLE, pool_store_address);
  ```

### Diagnostic Commands

```move
// Check pool configuration
pool::get_supported_chains();
pool::balance();
pool::get_remote_pools(chain_selector);

// Check token admin registry
token_admin_registry::get_pool(token_address);
token_admin_registry::get_administrator(token_address);

// For managed token pool specifically
managed_token_pool::get_store_address(); // Get pool's resource account address
managed_token::is_minter_allowed(pool_store_address); // Check minter permission
managed_token::is_burner_allowed(pool_store_address); // Check burner permission

// For regulated token pool specifically
regulated_token_pool::get_store_address(); // Get pool's resource account address
regulated_token::has_role(pool_store_address, BRIDGE_MINTER_OR_BURNER_ROLE); // Check bridge role
```

## Migration from Other Chains

When bringing tokens from EVM chains to Aptos:

1. **Assess Token Type**:

   - Simple ERC-20 → Use any pool type
   - Custom logic → Implement equivalent in Aptos with dispatch

2. **Choose Pool Strategy**:

   - Keep original on source chain → Lock/Release
   - Burn on source, mint on Aptos → Burn/Mint or Managed or Regulated
   - USDC specifically → USDC Pool
   - Regulatory compliance needed → Regulated Token Pool
   - Allowlist-based control needed → Managed Token Pool

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
