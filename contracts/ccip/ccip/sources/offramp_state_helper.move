module ccip::offramp_state_helper;

use std::type_name;

use sui::coin::{Self, Coin};

use ccip::client;
use ccip::receiver_registry;
use ccip::state_object::CCIPObjectRef;
use ccip::token_admin_registry as registry;

const EWrongIndexInReceiverParams: u64 = 1;
const ETokenTransferAlreadyCompleted: u64 = 2;
const ETokenPoolAddressMismatch: u64 = 3;
const ETypeProofMismatch: u64 = 4;
const ETokenTypeMismatch: u64 = 5;
const ETokenTransferFailed: u64 = 6;
const ECCIPReceiveFailed: u64 = 7;

public struct OFFRAMP_STATE_HELPER has drop {}

public struct ReceiverParams {
    // if this CCIP message contains token transfers, this vector will be non-empty.
    params: vector<DestTokenTransfer>,
    // if this CCIP message needs to call a function on the receiver, this will be populated.
    message: Option<client::Any2SuiMessage>,
    source_chain_selector: u64,
}

/// the cap to be stored in the offramp state to control the updates to ReceiverParams
public struct DestTransferCap has key, store {
    id: UID,
}

public struct DestTokenTransfer has copy, drop {
    receiver: address,
    // the amount of token to transfer, denoted from the source chain
    source_amount: u64,
    // the amount of token to unlock/mint, denoted from the destination chain (SUI)
    local_amount: u64,
    // the token's coin metadata object id on SUI
    dest_token_address: address,
    // the token pool state object id on SUI
    token_pool_address: address,
    // the source pool address on the source chain
    source_pool_address: vector<u8>,
    source_pool_data: vector<u8>,
    offchain_token_data: vector<u8>,
    // whether the token transfer has been completed
    completed: bool
}

fun init(_witness: OFFRAMP_STATE_HELPER, ctx: &mut TxContext) {
    let dest_cap = DestTransferCap {
        id: object::new(ctx),
    };

    transfer::transfer(dest_cap, ctx.sender());
}

public fun create_receiver_params(_: &DestTransferCap, source_chain_selector: u64): ReceiverParams {
    ReceiverParams {
        params: vector[],
        message: option::none(),
        source_chain_selector,
    }
}

public fun get_source_chain_selector(receiver_params: &ReceiverParams): u64 {
    receiver_params.source_chain_selector
}

/// add a new token transfer to the ReceiverParams object, which is done within offramp.
/// this is permissioned by the DestTransferCap, which is stored in the offramp state.
public fun add_dest_token_transfer(
    _: &DestTransferCap,
    receiver_params: &mut ReceiverParams,
    receiver: address,
    source_amount: u64,
    dest_token_address: address,
    token_pool_address: address,
    source_pool_address: vector<u8>,
    source_pool_data: vector<u8>,
    offchain_data: vector<u8>,
) {
    receiver_params.params.push_back(
        DestTokenTransfer {
            receiver,
            source_amount,
            local_amount: 0, // to be calculated by the destination token pool
            dest_token_address,
            token_pool_address,
            source_pool_address,
            source_pool_data,
            offchain_token_data: offchain_data,
            completed: false, // to be set to true by the destination token pool
        }
    );
}

/// if this CCIP message requires calling a function on a receiver in SUI, this function
/// should be called to populate the message field in the ReceiverParams object.
/// this is permissioned by the DestTransferCap, which is stored in the offramp state.
public fun populate_message(
    _: &DestTransferCap,
    receiver_params: &mut ReceiverParams,
    any2sui_message: client::Any2SuiMessage,
) {
    receiver_params.message.fill(any2sui_message);
}

public fun get_token_param_data(
    receiver_params: &ReceiverParams, index: u64
): (address, u64, address, vector<u8>, vector<u8>, vector<u8>) {
    assert!(
        index < receiver_params.params.length(),
        EWrongIndexInReceiverParams
    );
    let token_param = receiver_params.params[index];

    (
        token_param.receiver,
        token_param.source_amount,
        token_param.dest_token_address,
        token_param.source_pool_address,
        token_param.source_pool_data, // this is the encoded decimals
        token_param.offchain_token_data,
    )
}

/// only the token pool with a proper type proof can mark the corresponding token transfer as completed
/// and set the local amount.
public fun complete_token_transfer<T, TypeProof: drop>(
    ref: &CCIPObjectRef,
    mut receiver_params: ReceiverParams,
    index: u64,
    c: Coin<T>,
    _: TypeProof,
): ReceiverParams {
    assert!(
        index < receiver_params.params.length(),
        EWrongIndexInReceiverParams,
    );

    let token_transfer = receiver_params.params[index];
    assert!(!token_transfer.completed, ETokenTransferAlreadyCompleted);
    let (token_pool_package_id, _, _, coin_type, _,  _, type_proof) = registry::get_token_config(ref, token_transfer.dest_token_address);
    assert!(
        token_transfer.token_pool_address == token_pool_package_id,
        ETokenPoolAddressMismatch,
    );
    let proof_tn = type_name::get<TypeProof>();
    let proof_tn_str = type_name::into_string(proof_tn);
    assert!(type_proof == proof_tn_str, ETypeProofMismatch);

    assert!(
        coin_type == type_name::into_string(type_name::get<T>()),
        ETokenTypeMismatch
    );

    let local_amount = coin::value(&c);
    transfer::public_transfer(c, token_transfer.receiver);
    receiver_params.params[index].completed = true;
    receiver_params.params[index].local_amount = local_amount;

    receiver_params
}

/// called by ccip receiver directly, permissioned by the type proof of the receiver.
public fun extract_any2sui_message<TypeProof: drop>(
    ref: &CCIPObjectRef,
    mut receiver_params: ReceiverParams,
    package_id: address,
    _: TypeProof,
): (Option<client::Any2SuiMessage>, ReceiverParams) {
    let receiver_config = receiver_registry::get_receiver_config(ref, package_id);
    let proof_tn = type_name::get<TypeProof>();
    let (_, _, _, proof_typename) = receiver_registry::get_receiver_config_fields(receiver_config);
    assert!(
        proof_typename == proof_tn,
        ETypeProofMismatch
    );

    let message = receiver_params.message;
    receiver_params.message = option::none();

    (message, receiver_params)
}

/// deconstruct the ReceiverParams object and evaluate the token transfers are completed
/// and the message is extracted.
public fun deconstruct_receiver_params(
    _: &DestTransferCap,
    receiver_params: ReceiverParams,
) {
    let ReceiverParams {
        params,
        message,
        source_chain_selector: _,
    } = receiver_params;

    // make sure all token transfers are completed
    let mut i = 0;
    let number_of_tokens_in_msg = params.length();
    while (i < number_of_tokens_in_msg) {
        assert!(params[i].completed, ETokenTransferFailed);
        i = i + 1;
    };

    // make sure the any2sui message is extracted
    assert!(message.is_none(), ECCIPReceiveFailed);
}

// =========================== Test Functions =========================== //

#[test_only]
public fun test_init(ctx: &mut TxContext) {
    init(OFFRAMP_STATE_HELPER {}, ctx);
}

#[test_only]
public fun deconstruct_receiver_params_for_test(
    _: &DestTransferCap,
    receiver_params: ReceiverParams,
) {
    let ReceiverParams {
        params: _,
        message: _,
        source_chain_selector: _,
    } = receiver_params;
}
