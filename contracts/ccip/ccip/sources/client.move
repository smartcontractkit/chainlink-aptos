/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use ccip::eth_abi;

    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";

    #[view]
    public fun generic_extra_args_v2_tag(): vector<u8> {
        GENERIC_EXTRA_ARGS_V2_TAG
    }

    #[view]
    public fun svm_extra_args_v1_tag(): vector<u8> {
        SVM_EXTRA_ARGS_V1_TAG
    }

    #[view]
    public fun encode_generic_extra_args_v2(
        gas_limit: u256, allow_out_of_order_execution: bool
    ): vector<u8> {
        let extra_args = vector[];
        eth_abi::encode_selector(&mut extra_args, GENERIC_EXTRA_ARGS_V2_TAG);
        eth_abi::encode_u256(&mut extra_args, gas_limit);
        eth_abi::encode_bool(&mut extra_args, allow_out_of_order_execution);
        extra_args
    }

    #[view]
    public fun encode_svm_extra_args_v1(
        compute_units: u32,
        account_is_writable_bitmap: u64,
        allow_out_of_order_execution: bool,
        token_receiver: vector<u8>,
        accounts: vector<vector<u8>>
    ): vector<u8> {
        let extra_args = vector[];
        eth_abi::encode_selector(&mut extra_args, SVM_EXTRA_ARGS_V1_TAG);
        eth_abi::encode_u32(&mut extra_args, compute_units);
        eth_abi::encode_u64(&mut extra_args, account_is_writable_bitmap);
        eth_abi::encode_bool(&mut extra_args, allow_out_of_order_execution);
        eth_abi::encode_left_padded_bytes32(&mut extra_args, token_receiver);

        // Encode offset to dynamic data
        // Offset = 5*32 (4 fixed fields + offset field) = 160 bytes from args_data start
        eth_abi::encode_u256(&mut extra_args, 160 as u256);
        eth_abi::encode_u256(&mut extra_args, accounts.length() as u256);
        for (i in 0..accounts.length()) {
            eth_abi::encode_left_padded_bytes32(&mut extra_args, accounts[i]);
        };
        extra_args
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
