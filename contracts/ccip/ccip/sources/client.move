module ccip::client;

use std::bcs;

const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";

const EInvalidSVMTokenReceiverLength: u64 = 1;
const EInvalidSVMAccountLength: u64 = 2;

public fun generic_extra_args_v2_tag(): vector<u8> {
    GENERIC_EXTRA_ARGS_V2_TAG
}

public fun svm_extra_args_v1_tag(): vector<u8> {
    SVM_EXTRA_ARGS_V1_TAG
}

public fun encode_generic_extra_args_v2(
    gas_limit: u256, allow_out_of_order_execution: bool
): vector<u8> {
    let mut extra_args = vector[];
    extra_args.append(GENERIC_EXTRA_ARGS_V2_TAG);
    extra_args.append(bcs::to_bytes(&gas_limit));
    extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));
    extra_args
}

public fun encode_svm_extra_args_v1(
    compute_units: u32,
    account_is_writable_bitmap: u64,
    allow_out_of_order_execution: bool,
    token_receiver: vector<u8>,
    accounts: vector<vector<u8>>
): vector<u8> {
    let mut extra_args = vector[];
    extra_args.append(SVM_EXTRA_ARGS_V1_TAG);
    extra_args.append(bcs::to_bytes(&compute_units));
    extra_args.append(bcs::to_bytes(&account_is_writable_bitmap));
    extra_args.append(bcs::to_bytes(&allow_out_of_order_execution));

    assert!(token_receiver.length() == 32, EInvalidSVMTokenReceiverLength);
    // Check that all accounts have length 32
    accounts.do_ref!(|account| {
        assert!(account.length() == 32, EInvalidSVMAccountLength);
    });

    extra_args.append(bcs::to_bytes(&token_receiver));
    extra_args.append(bcs::to_bytes(&accounts));
    extra_args
}

public struct Any2SuiMessage has store, drop, copy {
    message_id: vector<u8>,
    source_chain_selector: u64,
    sender: vector<u8>,
    data: vector<u8>,
    dest_token_amounts: vector<Any2SuiTokenAmount>
}

public struct Any2SuiTokenAmount has store, drop, copy {
    token: address,
    amount: u64
}

public fun new_any2sui_message(
    message_id: vector<u8>,
    source_chain_selector: u64,
    sender: vector<u8>,
    data: vector<u8>,
    dest_token_amounts: vector<Any2SuiTokenAmount>
): Any2SuiMessage {
    Any2SuiMessage {
        message_id,
        source_chain_selector,
        sender,
        data,
        dest_token_amounts
    }
}

public fun new_dest_token_amounts(
    token_addresses: vector<address>, token_amounts: vector<u64>
): vector<Any2SuiTokenAmount> {
    token_addresses.zip_map_ref!(
        &token_amounts,
        |token_address, token_amount| {
            Any2SuiTokenAmount { token: *token_address, amount: *token_amount }
        }
    )
}

public fun get_message_id(input: &Any2SuiMessage): vector<u8> {
    input.message_id
}

public fun get_source_chain_selector(input: &Any2SuiMessage): u64 {
    input.source_chain_selector
}

public fun get_sender(input: &Any2SuiMessage): vector<u8> {
    input.sender
}

public fun get_data(input: &Any2SuiMessage): vector<u8> {
    input.data
}

public fun get_dest_token_amounts(input: &Any2SuiMessage): vector<Any2SuiTokenAmount> {
    input.dest_token_amounts
}

public fun get_token(input: &Any2SuiTokenAmount): address {
    input.token
}

public fun get_amount(input: &Any2SuiTokenAmount): u64 {
    input.amount
}
