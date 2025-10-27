# Regulated Token

Regulated token implementation that provides role-based access control, freezing capabilities, pausing functionality, and recovery mechanisms for regulatory compliance.

## Overview

Regulated Token extends the Aptos standard with regulatory features required for compliance with financial regulations.
The token supports dynamic dispatch for seamless integration with cross-chain protocols like CCIP (Chainlink Cross-Chain Interoperability Protocol).

## Key Features

### 🔐 **Role-Based Access Control (RBAC)**

- **PAUSER_ROLE (0)**: Can pause the contract to halt all operations
- **UNPAUSER_ROLE (1)**: Can resume contract operations
- **FREEZER_ROLE (2)**: Can freeze individual accounts
- **UNFREEZER_ROLE (3)**: Can unfreeze individual accounts
- **MINTER_ROLE (4)**: Can mint new tokens
- **BURNER_ROLE (5)**: Can burn tokens from accounts
- **BRIDGE_MINTER_OR_BURNER_ROLE (6)**: Special role for cross-chain bridge operations
- **RECOVERY_ROLE (7)**: Can recover tokens from frozen accounts or stuck funds

### 🌉 **Cross-Chain Bridge Support**

- **Dynamic Dispatch**: Registered dispatch functions for seamless cross-chain integration
- **Bridge Functions**: Specialized `bridge_mint()` and `bridge_burn()` functions that bypass dynamic dispatch conflicts
- **CCIP Integration**: Native support for Chainlink's Cross-Chain Interoperability Protocol

### 👑 **Administrative Controls**

- **Three-Step Ownership Transfer**: Secure admin role transfers with confirmation and execution
- **Role Management**: Admin can grant/revoke roles

## Ownership Transfer Process

The Regulated Token uses a **3-step ownership transfer** process to ensure secure transfer of administrative control. This is different from typical 2-step processes and is required due to Aptos's security model.

### Why 3 Steps?

Aptos's `0x1::object::transfer` function requires the **original owner's signer** to execute the transfer. This security requirement means:

- The new owner cannot complete the transfer on their own
- The original owner must authorize and execute the final transfer
- Both parties must explicitly agree to the transfer

### The 3-Step Process

#### Step 1: Original Owner Initiates Transfer

The current owner calls `transfer_ownership` to propose a new owner:

```bash
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::transfer_ownership \
  --args address:<NEW_OWNER_ADDRESS> \
  --profile current_owner

# Example:
aptos move run \
  --function-id 0x772225b9cc6f60891b1866c5c57f3f8d8fb236173ab12fbb296cd77cc5a2b7ae::regulated_token::transfer_ownership \
  --args address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 \
  --profile current_owner
```

**What happens:**

- Creates a pending transfer request
- Emits `OwnershipTransferRequested` event
- Original owner remains in control

#### Step 2: New Owner Accepts Transfer

The proposed new owner calls `accept_ownership` to confirm they want ownership:

```bash
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::accept_ownership \
  --profile new_owner

# Example:
aptos move run \
  --function-id 0x772225b9cc6f60891b1866c5c57f3f8d8fb236173ab12fbb296cd77cc5a2b7ae::regulated_token::accept_ownership \
  --profile new_owner
```

**What happens:**

- Validates the caller is the proposed owner
- Marks the transfer as accepted
- Emits `OwnershipTransferAccepted` event
- Transfer still NOT complete - original owner still has control

#### Step 3: Original Owner Executes Transfer

**⚠️ CRITICAL STEP:** The original owner must call `execute_ownership_transfer` to finalize:

```bash
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::execute_ownership_transfer \
  --args address:<NEW_OWNER_ADDRESS> \
  --profile current_owner

# Example:
aptos move run \
  --function-id 0x772225b9cc6f60891b1866c5c57f3f8d8fb236173ab12fbb296cd77cc5a2b7ae::regulated_token::execute_ownership_transfer \
  --args address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 \
  --profile current_owner
```

**What happens:**

- Validates both steps 1 and 2 are complete
- Calls `0x1::object::transfer` with original owner's signer
- Transfers ownership to new address
- Emits `OwnershipTransferred` event
- New owner now has full control

### Checking Transfer Status

Monitor the ownership transfer process:

```bash
# Check current owner
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::admin

# Check if there's a pending transfer
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::has_pending_transfer

# Check who the transfer is from
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::pending_transfer_from

# Check who the transfer is to
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::pending_transfer_to

# Check if new owner has accepted
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::pending_transfer_accepted
```

## Security Considerations

### Access Control

- All sensitive operations are protected by role-based access control (minting, burning, freezing, pausing)
- Only the admin can grant/revoke roles
- Roles must be explicitly granted by the admin

## Deployment and Usage

### Prerequisites

Before deploying or interacting with the regulated token, ensure you have:

1. **Aptos CLI installed and configured**

   1. Install the Aptos CLI: https://aptos.dev/build/cli
   2. Configure your CLI with a profile by running this in the root of the repository:

   ```bash
   aptos init
   ```

Setup multiple profiles if needed:

```bash
aptos init --profile admin
aptos init --profile minter
aptos init --profile burner
aptos init --profile freezer
```

### Deployment

#### Step 1: Deploy the Contract

```bash
# Navigate to the contract directory
cd contracts/regulated_token

# Deploy using object code deployment
aptos move deploy-object \
  --address-name regulated_token \
  --named-addresses admin=<ADMIN_ADDRESS>

# Example with actual addresses:
aptos move deploy-object \
  --address-name regulated_token \
  --named-addresses admin=0x007730cd28ee1cdc9e999336cbc430f99e7c44397c0aa77516f6f23a78559bb5
```

- Replace `<ADMIN_ADDRESS>` with your actual admin account address
- Deployment creates a `TokenStateDeployment` that must be initialized before use

#### Step 2: Initialize the Token

After deployment, initialize the token with metadata and activate it:

For maximum supply, pass empty vector for unlimited, or a specific number for capped supply.
Below we use 'u128:[]' for unlimited supply.

```bash
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::initialize \
  --args u8:0 string:"RegulatedToken" string:"TKN" u8:8 string:"https://regulatedtoken.com/icon.png" string:"RegulatedToken"

# Example with actual token address:
aptos move run \
  --function-id 0x772225b9cc6f60891b1866c5c57f3f8d8fb236173ab12fbb296cd77cc5a2b7ae::regulated_token::initialize \
  --args 'u128:[]' string:"RegulatedToken" string:"TKN" u8:8 string:"https://regulatedtoken.com/icon.png" string:"RegulatedToken"
```

**Parameters:**

- `max_supply`: Optional maximum supply (use 'u128:[]' for unlimited, or any number ('u128:[100000000]') for capped)
- `name`: Token name
- `symbol`: Token symbol (e.g., "MRT")
- `decimals`: Number of decimal places (typically 8)
- `icon`: URL to token icon image
- `project`: Project or organization name

#### Step 3: Verify Deployment

```bash
# Check if token state exists
aptos account list --query resources --account <REGULATED_TOKEN_ADDRESS>

# Get token metadata address
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::token_metadata

# Check admin
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::admin
```

### Access Control Management

#### Role Definitions

| Role Number | Role Name                    | Permissions                     |
| ----------- | ---------------------------- | ------------------------------- |
| 0           | PAUSER_ROLE                  | Pause all token operations      |
| 1           | UNPAUSER_ROLE                | Resume token operations         |
| 2           | FREEZER_ROLE                 | Freeze individual accounts      |
| 3           | UNFREEZER_ROLE               | Unfreeze accounts               |
| 4           | MINTER_ROLE                  | Mint new tokens                 |
| 5           | BURNER_ROLE                  | Burn tokens from accounts       |
| 6           | BRIDGE_MINTER_OR_BURNER_ROLE | Cross-chain minting/burning     |
| 7           | RECOVERY_ROLE                | Recover tokens and frozen funds |

#### Granting Roles

Only the admin can grant roles to accounts using their private key:

```bash
# Grant minter role to an account
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::grant_role \
  --args u8:4 address:<MINTER_ADDRESS> \
  --profile admin

# Example: Grant minter role
aptos move run \
  --function-id 0x27093661ff0eb2560771b6a616ac60788a7252f6917c8cdb29942052fa8567a::regulated_token::grant_role \
  --args u8:4 address:0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 \
  --profile admin
```

#### Checking Role Assignments

```bash
# Check if account has specific role
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::has_role \
  --args address:<ACCOUNT_ADDRESS> u8:<ROLE_NUMBER>

# Get all minters
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::get_minters

# Get all accounts with freezer role
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::get_freezers
```

### Command-Line Operations

#### Transferring Tokens

Users can transfer tokens between accounts using the standard Fungible Asset transfer function:

**⚠️ Note**:

- For `Object<T>` parameters in Move functions, use `address:<OBJECT_ADDRESS>` in the CLI (not `object:`). The CLI only supports: `['address','bool','hex','string','u8','u16','u32','u64','u128','u256','raw']`.
- For functions with generic types like `<T: key>`, you must specify `--type-args 0x1::fungible_asset::Metadata` for Fungible Assets.

```bash
# Transfer tokens between accounts
aptos move run \
  --function-id 0x1::primary_fungible_store::transfer \
  --type-args 0x1::fungible_asset::Metadata \
  --args address:<METADATA_OBJECT_ADDRESS> address:<RECIPIENT_ADDRESS> u64:<AMOUNT> \
  --profile <SENDER_PROFILE>

# Example: Transfer 100 tokens (assuming 8 decimals = 100 * 10^8)
aptos move run \
  --function-id 0x1::primary_fungible_store::transfer \
  --type-args 0x1::fungible_asset::Metadata \
  --args address:0x27093661ff0eb2560771b6a616ac60788a7252f6917c8cdb29942052fa8567a address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 u64:10000000000 \
  --profile sender
```

**Parameters:**

- `--type-args 0x1::fungible_asset::Metadata`: Required for generic function calls
- `address:<METADATA_OBJECT_ADDRESS>`: The metadata object address of the regulated token (obtained from deployment/initialization)
- `address:<RECIPIENT_ADDRESS>`: The recipient's account address
- `u64:<AMOUNT>`: Amount in smallest units (e.g., for 8 decimals, multiply by 10^8)

**Getting the Metadata Object Address:**

```bash
# Get the token metadata address
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::token_metadata
```

#### Checking Balances

```bash
# Check account balance
aptos move view \
  --function-id 0x1::primary_fungible_store::balance \
  --type-args 0x1::fungible_asset::Metadata \
  --args address:<ACCOUNT_ADDRESS> address:<METADATA_OBJECT_ADDRESS>

# Example: Check balance
aptos move view \
  --function-id 0x1::primary_fungible_store::balance \
  --type-args 0x1::fungible_asset::Metadata \
  --args address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 address:0x27093661ff0eb2560771b6a616ac60788a7252f6917c8cdb29942052fa8567a
```

#### Transfer Considerations for Regulated Tokens

⚠️ **Important**: Transfers may fail if:

1. **Sender account is frozen**: Check with `is_frozen` before attempting transfer
2. **Recipient account is frozen**: Recipient must be unfrozen to receive tokens
3. **Contract is paused**: No transfers allowed when contract is paused
4. **Insufficient balance**: Sender must have enough tokens

```bash
# Pre-transfer checks
# 1. Check if contract is paused
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::is_paused

# 2. Check if sender is frozen
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::is_frozen \
  --args address:<SENDER_ADDRESS>

# 3. Check if recipient is frozen
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::is_frozen \
  --args address:<RECIPIENT_ADDRESS>

# 4. Check sender balance
aptos move view \
  --function-id 0x1::primary_fungible_store::balance \
  --type-args 0x1::fungible_asset::Metadata \
  --args address:<SENDER_ADDRESS> address:<METADATA_OBJECT_ADDRESS>
```

#### Minting Tokens

Accounts with `MINTER_ROLE` or `BRIDGE_MINTER_OR_BURNER_ROLE` can mint tokens:

```bash
# Mint tokens to an account
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::mint \
  --args address:<RECIPIENT_ADDRESS> u64:<AMOUNT> \
  --profile minter

# Example: Mint 1000 tokens (assuming 8 decimals = 1000 * 10^8)
aptos move run \
  --function-id 0x27093661ff0eb2560771b6a616ac60788a7252f6917c8cdb29942052fa8567a::regulated_token::mint \
  --args address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 u64:100000000000 \
  --profile minter
```

#### Burning Tokens

Accounts with `BURNER_ROLE` or `BRIDGE_MINTER_OR_BURNER_ROLE` can burn tokens:

```bash
# Burn tokens from an account
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::burn \
  --args address:<TARGET_ADDRESS> u64:<AMOUNT> \
  --profile burner

# Example: Burn 500 tokens
aptos move run \
  --function-id 0x27093661ff0eb2560771b6a616ac60788a7252f6917c8cdb29942052fa8567a::regulated_token::burn \
  --args address:0x742d35cc6551c76ffc4b3f2b78c5dd1e99aada3a3a8e8becc024df3c23ed36e8 u64:50000000000 \
  --profile burner
```

#### Account Management

Accounts with `FREEZER_ROLE` can freeze accounts:

```bash
# Freeze a single account
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::freeze_account \
  --args address:<ACCOUNT_TO_FREEZE> \
  --profile freezer

# Freeze multiple accounts at once
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::freeze_accounts \
  --args 'address:["<ACCOUNT1>"]' \
  --profile freezer

# Check if specific account is frozen
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::is_frozen \
  --args address:<ACCOUNT_ADDRESS>
```

#### Pausing and Administrative Functions

Accounts with `PAUSER_ROLE` and `UNPAUSER_ROLE` can pause and unpause the contract:

```bash
# Pause the contract (requires PAUSER_ROLE)
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::pause \
  --profile unpauser

# Check if contract is paused
aptos move view \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::is_paused

# Unpause the contract (requires UNPAUSER_ROLE)
aptos move run \
  --function-id <REGULATED_TOKEN_ADDRESS>::regulated_token::unpause \
  --profile unpauser
```

## Testing

Run tests under the `contracts/regulated_token` directory:

```bash
aptos move test --dev
```

## Integration with CCIP

The regulated token is designed for seamless integration with Chainlink's CCIP protocol:

1. **Dynamic Dispatch**: Enables automatic token pool routing
2. **Bridge Functions**: Solve dispatch conflicts in cross-chain operations
3. **Token Admin Registry**: Automatic registration with CCIP infrastructure
4. **Rate Limiting**: Compatible with CCIP token pool rate controls
