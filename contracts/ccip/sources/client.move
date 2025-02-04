/// This module defines messages for end users to interact with Aptos CCIP.
module ccip::client {
    use std::fungible_asset::{Self, FungibleAsset, FungibleStore, Metadata};
    use std::object::{Self, Object};
    use std::vector;

    friend ccip::offramp;
    friend ccip::onramp;
    friend ccip::fee_quoter;

    struct Aptos2AnyMessage {
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_transfers: vector<FungibleAsset>,
        fee_token: Object<Metadata>,
        fee_token_store: Object<FungibleStore>,
        extra_args: vector<u8>
    }

    struct Any2AptosMessage has store, drop, copy {
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<AptosTokenAmount>
    }

    struct AptosTokenAmount has store, drop, copy {
        token: address,
        amount: u64
    }

    public fun new_aptos2any_message(
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_transfers: vector<FungibleAsset>,
        fee_token: Object<Metadata>,
        fee_token_store: Object<FungibleStore>,
        extra_args: vector<u8>
    ): Aptos2AnyMessage {
        Aptos2AnyMessage {
            dest_chain_selector,
            receiver,
            data,
            token_transfers,
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

    public fun get_dest_token_amounts(input: &Any2AptosMessage): vector<AptosTokenAmount> {
        input.dest_token_amounts
    }

    // AptosTokenAmount accessors
    public fun get_token(input: &AptosTokenAmount): address {
        input.token
    }

    public fun get_amount(input: &AptosTokenAmount): u64 {
        input.amount
    }

    public(friend) fun new_any2aptos_message(
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_amounts: vector<AptosTokenAmount>
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
    ): vector<AptosTokenAmount> {
        vector::zip_map_ref(
            &token_addresses,
            &token_amounts,
            |token_address, token_amount| {
                AptosTokenAmount { token: *token_address, amount: *token_amount }
            }
        )
    }

    /// Returns all fields except for FungibleAsset
    public(friend) fun get_aptos2any_fields(
        message: &Aptos2AnyMessage
    ): (u64, vector<u8>, vector<u8>, Object<Metadata>, Object<FungibleStore>, vector<u8>) {
        (
            message.dest_chain_selector,
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
            &message.token_transfers,
            |token_transfer| {
                let fa_metadata = fungible_asset::metadata_from_asset(token_transfer);
                let fa_amount = fungible_asset::amount(token_transfer);
                vector::push_back(
                    &mut token_addresses, object::object_address(&fa_metadata)
                );
                vector::push_back(&mut token_amounts, fa_amount);
            }
        );
        (token_addresses, token_amounts)
    }

    public(friend) fun unwrap_token_transfers(message: Aptos2AnyMessage):
        vector<FungibleAsset> {
        let Aptos2AnyMessage { token_transfers,.. } = message;
        token_transfers
    }
}
