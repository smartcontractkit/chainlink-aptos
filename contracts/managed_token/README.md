# Managed Token

## Overview

The **Managed Token** is a secure, flexible fungible asset implementation designed for cross-chain interoperability and multi-protocol integration. Unlike standard fungible assets that transfer mint/burn capabilities to individual contracts, the Managed Token retains control through an allowlist-based permission system.

## Key Features

- **Retained Control**: Token developers maintain ownership of mint/burn capabilities
- **Allowlist-Based Security**: Granular permission control for minters and burners
- **CCIP Integration**: Designed to work with CCIP Managed Token Pools
- **Emergency Controls**: Ability to revoke permissions when needed

## Why Managed Token?

### The Problem with Standard Burn/Mint Pools

Traditional CCIP burn/mint token pools require developers to provide mint/burn refs:

```move
struct BurnMintTokenPoolState {
    burn_ref: BurnRef,
    mint_ref: MintRef,
}
```

**Limitations:**

- If spare burn/mint refs were not created during token creation, the token cannot work with this pool.

### The Managed Token Solution

```move
struct TokenState {
    allowed_minters: AllowlistState,   // Multiple authorized minters
    allowed_burners: AllowlistState,   // Multiple authorized burners
    token: Object<Metadata>
}
```

**Benefits:**

- Developer keeps mint/burn control via allowlists
- Multiple signers can be authorized
- Can add/remove permissions
- Emergency revocation capabilities

## Security Model

### Allowlist-Based Permissions

The Managed Token uses two separate allowlists:

1. **Allowed Minters**: Addresses authorized to mint new tokens
2. **Allowed Burners**: Addresses authorized to burn existing tokens

```move
public entry fun mint(minter: &signer, to: address, amount: u64) {
    let minter_addr = signer::address_of(minter);
    assert_is_allowed_minter(minter_addr);  // ← Allowlist check
    // ... mint logic
}

public entry fun burn(burner: &signer, from: address, amount: u64) {
    let burner_addr = signer::address_of(burner);
    assert_is_allowed_burner(burner_addr);  // ← Allowlist check
    // ... burn logic
}
```

### Ownership Controls

- **Token Owner**: Has full control over allowlists and can mint/burn directly
- **Allowlisted Addresses**: Can mint/burn according to their permissions

## Deployment Guide

### Prerequisites

- New token deployment (existing tokens cannot be retrofitted)
- Control over the deployment account
- Understanding of allowlist management

### Step 1: Deploy Contract

```bash
aptos move deploy-object \
  --package-dir contracts/ccip/managed_token \
  --address-name managed_token
```

### Step 2: Initialize Token

```move
managed_token::initialize(
    publisher,
    option::some(1000000000), // max_supply (optional)
    string::utf8(b"My Token"),
    string::utf8(b"MTK"),
    8, // decimals
    string::utf8(b"https://mytoken.com/icon.png"),
    string::utf8(b"https://mytoken.com")
);
```

### Step 3: Configure Initial Allowlists

```move
// Add minters
managed_token::apply_allowed_minter_updates(
    owner,
    vector[], // addresses_to_remove
    vector[@ccip_pool, @dex_contract] // addresses_to_add
);

// Add burners
managed_token::apply_allowed_burner_updates(
    owner,
    vector[], // addresses_to_remove
    vector[@ccip_pool, @lending_protocol] // addresses_to_add
);
```

## Integration with CCIP

### Managed Token Pool Setup

The Managed Token is designed to work with the **Managed Token Pool** for CCIP cross-chain transfers:

```move
// 1. Deploy managed token pool (automatically registers with CCIP)

// 2. Add pool to token allowlists
let pool_address = managed_token_pool::get_store_address();

managed_token::apply_allowed_minter_updates(
    token_owner,
    vector[],
    vector[pool_address]
);

managed_token::apply_allowed_burner_updates(
    token_owner,
    vector[],
    vector[pool_address]
);
```

### Cross-Chain Token Flow

**Outbound (Aptos → Other Chain):**

1. User initiates CCIP transfer
2. Managed Token Pool calls `managed_token::burn()`
3. Allowlist permits the burn operation
4. Tokens are burned, reducing total supply
5. Message sent to destination chain

**Inbound (Other Chain → Aptos):**

1. CCIP message received on Aptos
2. Managed Token Pool calls `managed_token::mint()`
3. Allowlist permits the mint operation
4. New tokens minted to recipient
5. Total supply increases

## API Reference

### View Functions

```move
#[view]
/// Returns the address of the token's metadata object
public fun token_metadata(): address

#[view]
/// Returns list of addresses allowed to mint
public fun get_allowed_minters(): vector<address>

#[view]
/// Returns list of addresses allowed to burn
public fun get_allowed_burners(): vector<address>

#[view]
/// Check if address can mint
public fun is_minter_allowed(minter: address): bool

#[view]
/// Check if address can burn
public fun is_burner_allowed(burner: address): bool

#[view]
/// Returns the current owner
public fun owner(): address
```

### Administrative Functions

```move
/// Update the minter allowlist
public entry fun apply_allowed_minter_updates(
    caller: &signer,
    minters_to_remove: vector<address>,
    minters_to_add: vector<address>
)

/// Update the burner allowlist
public entry fun apply_allowed_burner_updates(
    caller: &signer,
    burners_to_remove: vector<address>,
    burners_to_add: vector<address>
)

/// Transfer ownership to new address
public entry fun transfer_ownership(caller: &signer, to: address)

/// Accept pending ownership transfer
public entry fun accept_ownership(caller: &signer)
```

### Token Operations

```move
/// Mint tokens to specified address (requires allowlist permission)
public entry fun mint(minter: &signer, to: address, amount: u64)

/// Burn tokens from specified address (requires allowlist permission)
public entry fun burn(burner: &signer, from: address, amount: u64)
```

## Best Practices

### Security Considerations

1. **Careful Allowlist Management**

   - Only add trusted contracts to allowlists
   - Regularly review authorized addresses
   - Remove unused permissions promptly

2. **Multi-Signature Recommended**

   - Use multi-sig for token ownership
   - Require multiple approvals for allowlist changes
   - Implement timelock for critical operations

3. **Emergency Procedures**
   - Have a plan to revoke compromised permissions
   - Monitor mint/burn activities

## Limitations

### New Tokens Only

- **Cannot retrofit existing tokens** with managed token functionality
- Existing tokens must use Lock/Release token pools for CCIP
- Migration from existing tokens requires new token deployment

### Allowlist Dependency

- All mint/burn operations depend on allowlist checks
- Incorrect allowlist configuration can break functionality
- Requires active management of permissions

### Dynamic Dispatch

- **Dynamic dispatch is not configurable** for Managed Token as of now
- Custom deposit/withdraw functions cannot be registered
- Standard fungible asset operations only

## Comparison with Alternatives

| Feature                    | Managed Token                  | Standard FA + Burn/Mint Pool  | Lock/Release Pool                    |
| -------------------------- | ------------------------------ | ----------------------------- | ------------------------------------ |
| **Developer Control**      | ✅ Full control via allowlists | ❌ Refs transferred to pool   | ✅ Full control retained             |
| **Multiple Protocols**     | ✅ Via allowlist management    | ❌ Single pool only           | ✅ Via transfer ref sharing          |
| **Supply Model**           | 🔥 Burn/Mint (supply changes)  | 🔥 Burn/Mint (supply changes) | 🔒 Lock/Release (supply constant)    |
| **Existing Token Support** | ❌ New tokens only             | ❌ New tokens only            | ✅ Can use existing tokens           |
| **Emergency Controls**     | ✅ Can revoke permissions      | ❌ Limited control            | ✅ Can revoke transfer ref           |
| **Liquidity Management**   | ✅ No liquidity required       | ✅ No liquidity required      | ❌ **Requires constant rebalancing** |
| **Operational Complexity** | ✅ Set-and-forget              | ✅ Set-and-forget             | ❌ **Active monitoring required**    |
| **Capital Efficiency**     | ✅ 100% efficient              | ✅ 100% efficient             | ❌ **Must over-provision liquidity** |
| **Transfer Reliability**   | ✅ Always succeeds             | ✅ Always succeeds            | ❌ **Fails when liquidity depleted** |

### Lock/Release Pool Challenges

**Liquidity Fragmentation**

- Each destination chain needs sufficient locked tokens for outbound transfers
- Popular chains can become liquidity-depleted, blocking transfers

**Rebalancing Overhead**

- Requires active monitoring of liquidity levels across all chains
- Manual intervention needed to move liquidity between chains
- Operational costs and complexity increase with chain count

**Capital Inefficiency**

- Total locked liquidity must exceed circulating supply significantly
- Much higher capital requirements than burn/mint models
- Unused liquidity generates no yield

## Troubleshooting

### Common Issues

**"Not allowed minter" Error**

- Check if address is in minter allowlist: `is_minter_allowed(address)`
- Add address to allowlist: `apply_allowed_minter_updates()`

**"Not allowed burner" Error**

- Check if address is in burner allowlist: `is_burner_allowed(address)`
- Add address to allowlist: `apply_allowed_burner_updates()`

**Ownership Issues**

- Verify current owner: `owner()`
- Complete ownership transfer: `accept_ownership()`

### Support and Resources

- **Contract Source**: `contracts/managed_token/sources/managed_token.move`
- **Integration Examples**: `contracts/ccip/ccip_token_pools/managed_token_pool/`
- **Test Cases**: `contracts/managed_token/tests/`
