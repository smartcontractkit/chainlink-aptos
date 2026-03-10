# Chainlink CCIP on Aptos

Chainlink Cross-Chain Interoperability Protocol (CCIP) enables secure cross-chain messaging and token transfers between Aptos and other blockchain networks. This guide provides comprehensive examples and best practices for building cross-chain applications on Aptos.

**Create CCIP module:**

```move
module my_app::ccip_sender {
    use std::signer;
    use std::vector;
    use aptos_framework::event;
    use ccip_router::router;
    use ccip::client;

    /// Send a simple message to another chain
    public entry fun send_message(
        sender: &signer,
        destination_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        fee_token: address,
        fee_token_store: address,
    ) {
        // Create extra_args for gas limit and execution settings
        let extra_args = client::encode_generic_extra_args_v2(200000, true);

        let message_id = router::ccip_send(
            sender,
            destination_chain_selector,
            receiver,
            data,
            vector::empty(), // No tokens
            vector::empty(), // No token amounts
            vector::empty(), // No token stores
            fee_token,
            fee_token_store,
            extra_args,
        );

        // Process the returned message_id for tracking
    }
}
```

## Architecture Overview

CCIP on Aptos consists of several core components:

- **Router**: Entry point for all CCIP operations
- **OnRamp**: Processes outgoing messages from Aptos
- **OffRamp**: Processes incoming messages to Aptos
- **Token Pools**: Manage token locking/releasing or burning/minting
- **Fee Quoter**: Calculates cross-chain transaction fees

### Message Flow

1. **Outgoing Messages (Aptos → Other Chains)**:

   ```
   Dapp → Router → OnRamp → Fee Quoter → Token Pools → Event Emission
   ```

2. **Incoming Messages (Other Chains → Aptos)**:
   ```
   Off-chain DONs → OffRamp → Token Pools → Receiver Contract
   ```

## CCIP Send Function Reference

The core function for sending cross-chain messages is `router::ccip_send`. Here's the complete function signature and detailed parameter explanations:

### Function Signature

```move
public entry fun ccip_send(
    caller: &signer,                    // Transaction sender
    dest_chain_selector: u64,           // Destination blockchain identifier
    receiver: vector<u8>,               // Recipient address on destination chain
    data: vector<u8>,                   // Message payload
    token_addresses: vector<address>,   // Tokens to transfer
    token_amounts: vector<u64>,         // Amounts of each token
    token_store_addresses: vector<address>, // Source stores for tokens
    fee_token: address,                 // Token used to pay fees
    fee_token_store: address,           // Store containing fee tokens
    extra_args: vector<u8>              // Execution parameters
): vector<u8> // Returns message ID for tracking
```

### Parameter Details

#### 1. `caller: &signer`

- **Purpose**: The account initiating the cross-chain transaction
- **Requirements**: Must have sufficient balance for fees and token transfers
- **Example**: `&my_account_signer`

#### 2. `dest_chain_selector: u64`

- **Purpose**: Unique identifier for the destination blockchain

#### 3. `receiver: vector<u8>`

- **Purpose**: Recipient address on the destination chain
- **Format**:
  - **EVM chains**: 32 bytes (20-byte address padded with 12 leading zeros)
  - **Solana**: 32 bytes (native Solana address format)
  - **Other chains**: Chain-specific format, typically 32 bytes
- **EVM Example**:

  ```move
  // For EVM address 0x1234567890123456789012345678901234567890
  let evm_address = x"1234567890123456789012345678901234567890";
  let receiver = vector::empty<u8>();

  // Pad with 12 zero bytes
  eth_abi::encode_left_padded_bytes32(receiver, evm_address);
  vector::append(&mut receiver, evm_address);
  ```

#### 4. `data: vector<u8>`

- **Purpose**: Arbitrary message payload to send to the destination
- **Encoding**: Raw bytes, commonly BCS-encoded structures
- **Examples**:

  ```move
  // Simple text message
  let data = b"Hello, cross-chain world!";

  // Structured data
  struct MyMessage has drop {
      user_id: u64,
      action: vector<u8>,
      timestamp: u64,
  }
  let message = MyMessage { user_id: 123, action: b"transfer", timestamp: 1234567890 };
  let data = std::bcs::to_bytes(&message);

  // Empty for token-only transfers
  let data = vector::empty<u8>();
  ```

#### 5. `token_addresses: vector<address>`

- **Purpose**: List of token contract addresses to transfer
- **Format**: Aptos addresses of fungible asset metadata objects
- **Requirements**: Must correspond 1:1 with `token_amounts` and `token_store_addresses`
- **Examples**:

  ```move
  // Single token transfer
  let token_addresses = vector[@0x123...abc]; // USDC address

  // Multiple token transfer
  let token_addresses = vector[
      @0x123...abc, // USDC
      @0x456...def, // LINK
      @0x789...ghi  // Custom token
  ];

  // No tokens (message only)
  let token_addresses = vector::empty<address>();
  ```

#### 6. `token_amounts: vector<u64>`

- **Purpose**: Amounts of each token to transfer (in token's base units)
- **Format**: 64-bit unsigned integers
- **Requirements**: Must match length of `token_addresses`
- **Examples**:

  ```move
  // Single token: 100 USDC (6 decimals = 100,000,000 base units)
  let token_amounts = vector[100_000_000];

  // Multiple tokens
  let token_amounts = vector[
      100_000_000,  // 100 USDC (6 decimals)
      1_000_000_000_000_000_000, // 1 LINK (18 decimals)
      500_000      // 0.5 custom token (6 decimals)
  ];

  // No tokens
  let token_amounts = vector::empty<u64>();
  ```

#### 7. `token_store_addresses: vector<address>`

- **Purpose**: Source fungible stores containing the tokens
- **Format**: Aptos addresses of fungible stores
- **Special Value**: `@0x0` indicates "use primary store" (not the actual primary store address)
- **How it works**: When `@0x0` is provided, CCIP automatically resolves it to the actual primary store address using `primary_fungible_store::primary_store_address(owner, token)`
- **Requirements**: Must match length of `token_addresses`
- **Examples**:

  ```move
  // Use primary stores (most common) - @0x0 gets auto-resolved
  let token_store_addresses = vector[@0x0, @0x0, @0x0];

  // Mix of primary and custom stores
  let token_store_addresses = vector[
      @0x0,           // Auto-resolved to primary store
      @0xabc...123,   // Specific custom store address
      @0x0            // Auto-resolved to primary store
  ];

  // Get actual primary store address if needed
  let actual_primary_store = primary_fungible_store::primary_store_address(
      sender_address,
      token_metadata_object
  );
  ```

#### 8. `fee_token: address`

- **Purpose**: Token used to pay cross-chain transaction fees
- **Options**:
  - **LINK Token**: Chainlink's native token (often lower fees)
  - **Native Token**: Chain's native token (APT on Aptos)
  - **Other Supported Tokens**: Chain-specific fee tokens
- **Examples**:

  ```move
  // Pay with LINK token
  let fee_token = @0xlink_token_address;

  // Pay with native APT
  let fee_token = @0xA;
  ```

#### 9. `fee_token_store: address`

- **Purpose**: Fungible store containing fee tokens
- **Special Value**: `@0x0` indicates "use primary store" (auto-resolved by CCIP)
- **Requirements**: Must contain sufficient balance for fees
- **Example**:
  ```move
  let fee_token_store = @0x0; // Auto-resolved to primary store
  ```

#### 10. `extra_args: vector<u8>`

- **Purpose**: Execution parameters for destination chain
- **Encoding**: BCS-encoded execution settings
- **Components**:
  - **Gas Limit**: Maximum gas for execution on destination
  - **Allow Out-of-Order**: Passed in extra_args but **ignored** by the contract; Aptos CCIP always uses out-of-order execution regardless of the value (no revert if you set `false`).
- **Generation**:

  ```move
  use ccip::client;

  // For EVM chains (generic extra args v2)
  let gas_limit = 200000u256;
  let allow_out_of_order = true; // optional; contract ignores and always uses out-of-order
  let extra_args = client::encode_generic_extra_args_v2(gas_limit, allow_out_of_order);

  // For Solana chains (SVM extra args v1)
  let compute_units = 100000u32;
  let account_bitmap = 0u64;
  let allow_out_of_order = true; // optional; contract ignores and always uses out-of-order
  let token_receiver = x"1234..."; // 32-byte Solana address
  let accounts = vector[x"5678..."]; // Additional accounts
  let extra_args = client::encode_svm_extra_args_v1(
      compute_units,
      account_bitmap,
      allow_out_of_order,
      token_receiver,
      accounts
  );
  ```

### Return Value

- **Type**: `vector<u8>`
- **Purpose**: Unique message identifier for tracking
- **Usage**: Store for status monitoring and debugging
- **Example**:
  ```move
  let message_id = router::ccip_send(/* parameters */);
  // Store message_id for later tracking
  emit_message_sent_event(message_id, dest_chain_selector);
  ```

### Out-of-Order Execution

**Aptos CCIP always uses out-of-order execution.** The `allow_out_of_order` flag in extra_args is **ignored**: the contract parses it but always treats execution as out-of-order (nonce = 0). You are not reverted if you pass `false` or omit it; the contract overrides to true. You can pass `true` or `false` when building extra_args; behavior is the same.

## Message Sending Examples

### Simple Text Message

```move
module my_app::simple_messenger {
    use ccip_router::router;
    use ccip::client;
    use ccip::eth_abi;

    public entry fun send_hello_world(
        sender: &signer,
        destination_chain: u64,
        receiver: vector<u8>,
        fee_token: address,
        fee_token_store: address,
    ) {
        let message = b"Hello, Cross-Chain World!";
        let extra_args = client::encode_generic_extra_args_v2(200000, true);

        router::ccip_send(
            sender,
            destination_chain,
            receiver,
            message,
            vector::empty(), // No tokens
            vector::empty(), // No amounts
            vector::empty(), // No stores
            fee_token,
            fee_token_store,
            extra_args,
        );
    }

    public entry fun send_to_ethereum_sepolia(
        sender: &signer,
        evm_receiver: vector<u8>, // Must be 20 bytes
        message: vector<u8>,
        fee_token: address,
    ) {
        // Pad EVM address to 32 bytes
        assert!(vector::length(&evm_receiver) == 20, E_INVALID_EVM_ADDRESS);
        let padded_receiver = vector::empty<u8>();
        eth_abi::encode_left_padded_bytes32(receiver, evm_address);

        let extra_args = client::encode_generic_extra_args_v2(300000, true);

        router::ccip_send(
            sender,
            16015286601757825753, // Ethereum Sepolia
            padded_receiver,
            message,
            vector::empty(),
            vector::empty(),
            vector::empty(),
            fee_token,
            @0x0, // Primary store
            extra_args,
        );
    }
}
```

### Structured Data Messages

```move
module my_app::structured_messenger {
    use std::string::String;
    use ccip_router::router;
    use ccip::client;

    struct CrossChainOrder has drop {
        order_id: u64,
        customer: address,
        amount: u64,
        token: address,
        deadline: u64,
    }

    struct UserAction has drop {
        user_id: u64,
        action_type: u8, // 1=deposit, 2=withdraw, 3=swap
        amount: u64,
        timestamp: u64,
    }

    public entry fun send_order(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        order_id: u64,
        customer: address,
        amount: u64,
        token: address,
        deadline: u64,
        fee_token: address,
    ) {
        let order = CrossChainOrder {
            order_id,
            customer,
            amount,
            token,
            deadline,
        };

        let data = std::bcs::to_bytes(&order);
        let extra_args = client::encode_generic_extra_args_v2(400000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            data,
            vector::empty(),
            vector::empty(),
            vector::empty(),
            fee_token,
            @0x0,
            extra_args,
        );
    }

    public entry fun send_user_action(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        user_id: u64,
        action_type: u8,
        amount: u64,
        fee_token: address,
    ) {
        let action = UserAction {
            user_id,
            action_type,
            amount,
            timestamp: aptos_framework::timestamp::now_seconds(),
        };

        let data = std::bcs::to_bytes(&action);
        let extra_args = client::encode_generic_extra_args_v2(250000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            data,
            vector::empty(),
            vector::empty(),
            vector::empty(),
            fee_token,
            @0x0,
            extra_args,
        );
    }
}
```

## Token Transfer Examples

### Single Token Transfer

```move
module my_app::token_sender {
    use ccip_router::router;
    use ccip::client;

    public entry fun send_usdc(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        amount: u64, // Amount in USDC base units (6 decimals)
        fee_token: address,
    ) {
        let usdc_address = @0x123; // Replace with actual USDC address
        let extra_args = client::encode_generic_extra_args_v2(500000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            vector::empty(), // No message data
            vector[usdc_address],
            vector[amount],
            vector[@0x0], // Primary store
            fee_token,
            @0x0,
            extra_args,
        );
    }

    public entry fun send_multiple_tokens(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        usdc_amount: u64,
        link_amount: u64,
        fee_token: address,
    ) {
        let usdc_address = @0x123;
        let link_address = @0x456;
        let extra_args = client::encode_generic_extra_args_v2(800000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            vector::empty(),
            vector[usdc_address, link_address],
            vector[usdc_amount, link_amount],
            vector[@0x0, @0x0], // Both from primary stores
            fee_token,
            @0x0,
            extra_args,
        );
    }
}
```

### Token Transfer with Message

```move
module my_app::token_with_message {
    use ccip_router::router;
    use ccip::client;

    struct PaymentInstruction has drop {
        invoice_id: u64,
        recipient_info: vector<u8>,
        payment_reference: vector<u8>,
    }

    public entry fun send_payment_with_instruction(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        token_address: address,
        amount: u64,
        invoice_id: u64,
        recipient_info: vector<u8>,
        payment_reference: vector<u8>,
        fee_token: address,
    ) {
        // Create payment instruction
        let instruction = PaymentInstruction {
            invoice_id,
            recipient_info,
            payment_reference,
        };

        let data = std::bcs::to_bytes(&instruction);
        let extra_args = client::encode_generic_extra_args_v2(600000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            data,                    // Message with payment instruction
            vector[token_address],   // Transfer token
            vector[amount],          // Transfer amount
            vector[@0x0],           // From primary store
            fee_token,
            @0x0,
            extra_args,
        );
    }
}
```

## Advanced Features

### Fee Estimation

```move
module my_app::fee_calculator {
    use ccip_router::router;
    use ccip::client;

    /// Estimate fees before sending
    public fun estimate_message_fee(
        dest_chain: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        fee_token: address,
    ): u64 {
        let extra_args = client::encode_generic_extra_args_v2(200000, true);

        router::get_fee(
            dest_chain,
            receiver,
            data,
            vector::empty(), // No tokens
            vector::empty(), // No amounts
            vector::empty(), // No stores
            fee_token,
            @0x0,
            extra_args,
        )
    }

    /// Estimate fees for token transfer
    public fun estimate_token_transfer_fee(
        dest_chain: u64,
        receiver: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        fee_token: address,
    ): u64 {
        let extra_args = client::encode_generic_extra_args_v2(500000, true);
        let stores = vector::empty<address>();
        for (i in 0..token_addresses.length()) {
            vector::push_back(&mut stores, @0x0);
        };

        router::get_fee(
            dest_chain,
            receiver,
            vector::empty(), // No message data
            token_addresses,
            token_amounts,
            stores,
            fee_token,
            @0x0,
            extra_args,
        )
    }

    /// Send with fee validation
    public entry fun send_with_max_fee(
        sender: &signer,
        dest_chain: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        max_fee: u64,
        fee_token: address,
    ) {
        // Estimate fee first
        let estimated_fee = estimate_message_fee(dest_chain, receiver, data, fee_token);
        assert!(estimated_fee <= max_fee, 1); // E_FEE_TOO_HIGH

        let extra_args = client::encode_generic_extra_args_v2(200000, true);

        router::ccip_send(
            sender,
            dest_chain,
            receiver,
            data,
            vector::empty(),
            vector::empty(),
            vector::empty(),
            fee_token,
            @0x0,
            extra_args,
        );
    }
}
```

## Troubleshooting

### Common Issues and Solutions

1. **Transaction Fails with "Insufficient Fee"**

   - **Cause**: Fee estimation too low or gas limit insufficient
   - **Solution**: Increase gas limit in extra_args or add fee buffer
   - **Example**:

     ```move
     // Increase gas limit
     let extra_args = client::encode_generic_extra_args_v2(500000, true); // Instead of 200000

     // Add fee buffer
     let estimated_fee = router::get_fee(/* params */);
     let fee_with_buffer = estimated_fee + (estimated_fee / 5); // 20% buffer
     ```

2. **Message Not Received**

   - **Cause**: Invalid receiver address format or unsupported chain
   - **Solution**: Verify address padding and chain support
   - **Example**:

     ```move
     // Verify chain is supported
     assert!(router::is_chain_supported(dest_chain), 1);

     // Verify EVM address padding
     assert!(vector::length(&receiver) == 32, 2); // Must be 32 bytes for EVM
     ```

3. **Token Transfer Fails**

   - **Cause**: Insufficient token balance or unsupported token
   - **Solution**: Check balances and token pool configuration
   - **Example**:
     ```move
     // Check token balance before transfer
     let balance = primary_fungible_store::balance(sender_addr, token_metadata);
     assert!(balance >= amount, 3); // E_INSUFFICIENT_BALANCE
     ```

4. **Invalid Extra Args**

   - **Cause**: Incorrect encoding for destination chain type
   - **Solution**: Use the appropriate encoding function for the destination (generic v2 for EVM/Aptos/Sui, SVM v1 for Solana). The out-of-order value is ignored; the contract always uses out-of-order execution.
   - **Example**:

     ```move
     // For EVM chains
     let extra_args = client::encode_generic_extra_args_v2(gas_limit, true);

     // For Solana chains
     let extra_args = client::encode_svm_extra_args_v1(
         compute_units, bitmap, true, token_receiver, accounts
     );
     ```

## Additional Resources

- [CCIP Documentation](https://docs.chain.link/ccip)
- [Aptos Move Documentation](https://aptos.dev/move/move-on-aptos)
- [CCIP Supported Networks](https://docs.chain.link/ccip/supported-networks)
- [Chain Selector Reference](https://docs.chain.link/ccip/supported-networks/testnet)

---
