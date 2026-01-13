/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use std::bcs;

    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";

    const E_INVALID_SVM_TOKEN_RECEIVER_LENGTH: u64 = 1;
    const E_INVALID_SVM_ACCOUNT_LENGTH: u64 = 2;

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
        extra_args.append(GENERIC_EXTRA_ARGS_V2_TAG);
        extra_args.append(bcs::to_bytes(&gas_limit));
        extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));
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
        extra_args.append(SVM_EXTRA_ARGS_V1_TAG);
        extra_args.append(bcs::to_bytes(&compute_units));
        extra_args.append(bcs::to_bytes(&account_is_writable_bitmap));
        extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));

        assert!(token_receiver.length() == 32, E_INVALID_SVM_TOKEN_RECEIVER_LENGTH);
        accounts.for_each_ref(
            |account| {
                assert!(account.length() == 32, E_INVALID_SVM_ACCOUNT_LENGTH);
            }
        );

        extra_args.append(bcs::to_bytes(&token_receiver));
        extra_args.append(bcs::to_bytes(&accounts));
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

    public fun get_dest_token_amounts(input: &Any2AptosMessage)
        : vector<Any2AptosTokenAmount> {
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
