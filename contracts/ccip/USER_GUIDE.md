# Chainlink CCIP on Aptos: User Guide

This guide explains how to use Chainlink Cross-Chain Interoperability Protocol (CCIP) on Aptos to send and receive messages across different blockchains.

## Table of Contents

1. [Introduction](#introduction)
2. [Sending Messages from Aptos](#sending-messages-from-aptos)
   - [Understanding the Router](#understanding-the-router)
   - [Preparing to Send a Message](#preparing-to-send-a-message)
   - [Calling ccip_send](#calling-ccip_send)
   - [Message Parameters Explained](#message-parameters-explained)
   - [Handling Fees](#handling-fees)
3. [Receiving Messages on Aptos](#receiving-messages-on-aptos)
   - [Creating a Receiver Module](#creating-a-receiver-module)
   - [Registering with the Receiver Registry](#registering-with-the-receiver-registry)
   - [Implementing the ccip_receive Function](#implementing-the-ccip_receive-function)
   - [Processing Received Messages](#processing-received-messages)
4. [Example Implementation](#example-implementation)
5. [Troubleshooting](#troubleshooting)

## Introduction

Chainlink CCIP enables secure cross-chain messaging and token transfers between Aptos and other supported blockchains. This guide focuses on the two primary operations:

- **Sending messages from Aptos** to other chains using the Router's `ccip_send` function
- **Receiving messages on Aptos** by implementing and registering a receiver module

## Sending Messages from Aptos

### Understanding the Router

The CCIP Router is the main entry point for sending messages from Aptos to other chains. It handles message routing, fee calculation, and ensures messages are properly formatted for the destination chain.

### Preparing to Send a Message

Before sending a message, you need to:

1. Determine the destination chain selector (a unique identifier for the target blockchain)
2. Prepare the receiver address on the destination chain
3. Format your message data
4. Decide if you want to include token transfers
5. Choose a fee token

### Calling ccip_send

To send a message, call the `ccip_send` function on the Router module:

```move
use ccip_router::router;

// Basic message without tokens
public entry fun send_message(
    caller: &signer,
    dest_chain_selector: u64,
    receiver: vector<u8>,
    message_data: vector<u8>,
    fee_token: address,
    fee_token_store: address,
    extra_args: vector<u8>
) {
    router::ccip_send(
        caller,
        dest_chain_selector,
        receiver,
        message_data,
        vector::empty<address>(),  // No token transfers
        vector::empty<u64>(),      // No token amounts
        vector::empty<address>(),  // No token stores
        fee_token,
        fee_token_store,
        extra_args
    );
}

// Message with token transfers
public entry fun send_message_with_tokens(
    caller: &signer,
    dest_chain_selector: u64,
    receiver: vector<u8>,
    message_data: vector<u8>,
    token_addresses: vector<address>,
    token_amounts: vector<u64>,
    token_store_addresses: vector<address>,
    fee_token: address,
    fee_token_store: address,
    extra_args: vector<u8>
) {
    router::ccip_send(
        caller,
        dest_chain_selector,
        receiver,
        message_data,
        token_addresses,
        token_amounts,
        token_store_addresses,
        fee_token,
        fee_token_store,
        extra_args
    );
}
```

### Message Parameters Explained

- `caller`: The signer initiating the transaction
- `dest_chain_selector`: Unique identifier for the destination chain
- `receiver`: Address of the receiver on the destination chain (encoded as bytes)
- `message_data`: The payload to be delivered to the receiver
- `token_addresses`: Addresses of tokens to transfer (empty if no tokens)
- `token_amounts`: Amounts of each token to transfer (empty if no tokens)
- `token_store_addresses`: Store addresses for each token (empty if no tokens)
- `fee_token`: Address of the token used to pay CCIP fees
- `fee_token_store`: Store address for the fee token
- `extra_args`: Additional arguments for the destination chain (e.g., gas limit)

### Handling Fees

CCIP charges fees for cross-chain message delivery. You can estimate fees before sending:

```move
let fee = router::get_fee(
    dest_chain_selector,
    receiver,
    message_data,
    token_addresses,
    token_amounts,
    token_store_addresses,
    fee_token,
    fee_token_store,
    extra_args
);
```

Ensure your account has sufficient balance of the fee token before sending.

## Receiving Messages on Aptos

### Creating a Receiver Module

To receive messages on Aptos, you need to create a module that implements the CCIP receiver interface. Here's a template:

```move
module your_address::your_receiver {
    use std::account;
    use std::event;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};

    use ccip::client;
    use ccip::receiver_registry;

    struct ReceiverState has key {
        received_message_events: event::EventHandle<ReceivedMessage>
    }

    #[event]
    struct ReceivedMessage has store, drop {
        data: vector<u8>,
        sender: vector<u8>,
        source_chain_selector: u64
        // Add other fields you want to track
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"YourReceiver 1.0.0")
    }

    fun init_module(publisher: &signer) {
        // Create an account for event handles
        account::create_account_if_does_not_exist(@your_address);

        let handle = account::new_event_handle(publisher);

        move_to(publisher, ReceiverState { received_message_events: handle });

        // Register with the CCIP receiver registry
        receiver_registry::register_receiver(
            publisher, b"your_receiver", YourReceiverProof {}
        );
    }

    struct YourReceiverProof has drop {}

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires ReceiverState {
        // Get the message from the registry
        let message = receiver_registry::get_receiver_input(
            @your_address, YourReceiverProof {}
        );
        
        // Extract message data
        let data = client::get_data(&message);
        let sender = client::get_sender(&message);
        let source_chain_selector = client::get_source_chain_selector(&message);
        
        // Process token transfers if any
        let token_amounts = client::get_dest_token_amounts(&message);
        
        // Your custom message handling logic here
        // ...

        // Emit event
        let state = borrow_global_mut<ReceiverState>(@your_address);
        event::emit_event(
            &mut state.received_message_events,
            ReceivedMessage { 
                data,
                sender,
                source_chain_selector
            }
        );

        option::none()
    }
}
```

### Registering with the Receiver Registry

Your module must register with the CCIP Receiver Registry during initialization. This is done in the `init_module` function:

```move
receiver_registry::register_receiver(
    publisher, b"your_receiver", YourReceiverProof {}
);
```

The registration requires:
- The publisher signer
- The module name as bytes
- A proof type that will be used to authenticate message retrieval

### Implementing the ccip_receive Function

The `ccip_receive` function is called by CCIP when a message arrives for your module. It must:

1. Retrieve the message using `receiver_registry::get_receiver_input`
2. Process the message data and any token transfers
3. Implement your custom logic
4. Return `option::none()` (or a value if needed)

### Processing Received Messages

Inside `ccip_receive`, you can access message components using the client module:

```move
// Get message data
let data = client::get_data(&message);

// Get sender address from source chain
let sender = client::get_sender(&message);

// Get source chain identifier
let source_chain_selector = client::get_source_chain_selector(&message);

// Get token transfers
let token_amounts = client::get_dest_token_amounts(&message);
```

## Example Implementation

The `ccip_dummy_receiver` module provides a complete example:

```move
module ccip_dummy_receiver::dummy_receiver {
    use std::account;
    use std::event;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};

    use ccip::client;
    use ccip::receiver_registry;

    #[event]
    struct ReceivedMessage has store, drop {
        data: vector<u8>
    }

    struct CCIPReceiverState has key {
        received_message_events: event::EventHandle<ReceivedMessage>
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"DummyReceiver 1.6.0")
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @ccip_dummy_receiver, 1);

        // Create an account on the object for event handles
        account::create_account_if_does_not_exist(@ccip_dummy_receiver);

        let handle = account::new_event_handle(publisher);

        move_to(publisher, CCIPReceiverState { received_message_events: handle });

        receiver_registry::register_receiver(
            publisher, b"dummy_receiver", DummyReceiverProof {}
        );
    }

    struct DummyReceiverProof has drop {}

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires CCIPReceiverState {
        let message = receiver_registry::get_receiver_input(
            @ccip_dummy_receiver, DummyReceiverProof {}
        );
        let data = client::get_data(&message);
        
        // Simple abort condition for testing
        if (data == b"abort") {
            abort 1
        };

        let state = borrow_global_mut<CCIPReceiverState>(@ccip_dummy_receiver);

        event::emit(ReceivedMessage { data });
        event::emit_event(&mut state.received_message_events, ReceivedMessage { data });

        option::none()
    }
}
```

## Troubleshooting

Common issues and solutions:

1. **Message not received**: Ensure your receiver is properly registered with the correct module name and proof type.

2. **Fee estimation errors**: Make sure all parameters match between fee estimation and actual sending.

3. **Token transfer failures**: Verify that:
   - The tokens are supported by CCIP
   - You have sufficient balance
   - The token stores are correctly specified

4. **Execution errors in ccip_receive**: Handle potential errors gracefully to avoid transaction failures.

5. **Allowlist restrictions**: Some chains may have allowlists for senders. Contact the CCIP team if you need to be added to an allowlist.
