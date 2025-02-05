/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use std::error;
    use std::vector;

    friend ccip::offramp;
    friend ccip::onramp;
    friend ccip::fee_quoter;

    const E_TOKEN_ARGUMENTS_MISMATCH: u64 = 1;

    struct Aptos2AnyMessage has drop {
        receiver: vector<u8>,
        data: vector<u8>,
        token_amounts: vector<Aptos2AnyTokenAmount>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    }

    struct Aptos2AnyTokenAmount has drop {
        token: address,
        amount: u64,
        token_store: address
    }

    struct Any2AptosMessage has store, drop, copy {
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<Any2AptosTokenAmount>
    }

    struct Any2AptosTokenAmount has store, drop, copy {
        token: address,
        amount: u64
    }

    public(friend) fun new_aptos2any_message(
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): Aptos2AnyMessage {
        let tokens_len = vector::length(&token_addresses);
        assert!(
            tokens_len == vector::length(&token_amounts),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        assert!(
            tokens_len == vector::length(&token_store_addresses),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        let i = 0;
        let converted_token_amounts = vector[];
        while (i < tokens_len) {
            let token = *vector::borrow(&token_addresses, i);
            let amount = *vector::borrow(&token_amounts, i);
            let token_store = *vector::borrow(&token_store_addresses, i);
            vector::push_back(
                &mut converted_token_amounts,
                Aptos2AnyTokenAmount { token, amount, token_store }
            );
            i = i + 1;
        };
        Aptos2AnyMessage {
            receiver,
            data,
            token_amounts: converted_token_amounts,
            fee_token,
            fee_token_store,
            extra_args
        }
    }

    // Any2AptosMessage accessors
    public fun get_message_id(input: &Any2AptosMessage): vector<u8> {
        input.message_id
    }

    public fun get_source_chain_selector(input: &Any2AptosMessage): u64 {
        input.source_chain_selector
    }

    public fun get_sender(input: &Any2AptosMessage): vector<u8> {
        input.sender
    }

    public fun get_data(input: &Any2AptosMessage): vector<u8> {
        input.data
    }

    public fun get_dest_token_amounts(input: &Any2AptosMessage): vector<Any2AptosTokenAmount> {
        input.dest_token_amounts
    }

    // Any2AptosTokenAmount accessors
    public fun get_token(input: &Any2AptosTokenAmount): address {
        input.token
    }

    public fun get_amount(input: &Any2AptosTokenAmount): u64 {
        input.amount
    }

    public(friend) fun new_any2aptos_message(
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<Any2AptosTokenAmount>
    ): Any2AptosMessage {
        Any2AptosMessage {
            message_id,
            source_chain_selector,
            sender,
            data,
            dest_token_amounts
        }
    }

    public(friend) fun new_dest_token_amounts(
        token_addresses: vector<address>, token_amounts: vector<u64>
    ): vector<Any2AptosTokenAmount> {
        vector::zip_map_ref(
            &token_addresses,
            &token_amounts,
            |token_address, token_amount| {
                Any2AptosTokenAmount { token: *token_address, amount: *token_amount }
            }
        )
    }

    /// Returns all fields except for FungibleAsset
    public(friend) fun get_aptos2any_fields(
        message: &Aptos2AnyMessage
    ): (vector<u8>, vector<u8>, address, address, vector<u8>) {
        (
            message.receiver,
            message.data,
            message.fee_token,
            message.fee_token_store,
            message.extra_args
        )
    }

    public(friend) fun get_aptos2any_token_transfers(
        message: &Aptos2AnyMessage
    ): (vector<address>, vector<u64>) {
        let token_addresses = vector[];
        let token_amounts = vector[];
        vector::for_each_ref(
            &message.token_amounts,
            |token_amount| {
                vector::push_back(&mut token_addresses, token_amount.token);
                vector::push_back(&mut token_amounts, token_amount.amount);
            }
        );
        (token_addresses, token_amounts)
    }
}
