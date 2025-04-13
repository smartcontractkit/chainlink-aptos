/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use std::error;

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

    const E_TOKEN_ARGUMENTS_MISMATCH: u64 = 1;

    public fun new_aptos2any_message(
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): Aptos2AnyMessage {
        let tokens_len = token_addresses.length();
        assert!(
            tokens_len == token_amounts.length(),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        assert!(
            tokens_len == token_store_addresses.length(),
            error::invalid_argument(E_TOKEN_ARGUMENTS_MISMATCH)
        );
        let converted_token_amounts = vector[];
        for (i in 0..tokens_len) {
            let token = token_addresses[i];
            let amount = token_amounts[i];
            let token_store = token_store_addresses[i];
            converted_token_amounts.push_back(
                Aptos2AnyTokenAmount { token, amount, token_store }
            );
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

    public fun new_any2aptos_message(
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

    public fun new_dest_token_amounts(
        token_addresses: vector<address>, token_amounts: vector<u64>
    ): vector<Any2AptosTokenAmount> {
        token_addresses.zip_map_ref(
            &token_amounts,
            |token_address, token_amount| {
                Any2AptosTokenAmount { token: *token_address, amount: *token_amount }
            }
        )
    }

    // Aptos2AnyMessage accessors

    public fun get_aptos2any_fields(
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

    public fun get_aptos2any_token_transfers(
        message: &Aptos2AnyMessage
    ): (vector<address>, vector<u64>) {
        let token_addresses = vector[];
        let token_amounts = vector[];
        message.token_amounts.for_each_ref(|token_amount| {
            let token_amount: &Aptos2AnyTokenAmount = token_amount;
            token_addresses.push_back(token_amount.token);
            token_amounts.push_back(token_amount.amount);
        });
        (token_addresses, token_amounts)
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
}
