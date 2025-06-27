module ccip_dummy_receiver::dummy_receiver {
    use std::string::{Self, String};
    use sui::event;

    use ccip::client;
    use ccip::offramp_state_helper as osh;
    use ccip::receiver_registry;
    use ccip::state_object::CCIPObjectRef;

    public struct OwnerCap has key, store {
        id: UID,
        receiver_address: address,
    }

    public struct ReceivedMessage has copy, drop {
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_transfer_length: u64,
    }

    public struct CCIPReceiverState has key {
        id: UID,
        counter: u64,
        message_id: vector<u8>,
        source_chain_selector: u64,
        sender: vector<u8>,
        data: vector<u8>,
        dest_token_transfer_length: u64,
    }

    public struct DummyReceiverProof has drop {}

    public fun type_and_version(): String {
        string::utf8(b"DummyReceiver 1.6.0")
    }

    fun init(ctx: &mut TxContext) {
       let state = CCIPReceiverState {
           id: object::new(ctx),
           counter: 0,
           message_id: vector[],
           source_chain_selector: 0,
           sender: vector[],
           data: vector[],
           dest_token_transfer_length: 0,
        };

        let owner_cap = OwnerCap {
            id: object::new(ctx),
            receiver_address: object::id_to_address(object::borrow_id(&state)),
        };

        transfer::share_object(state);
        transfer::transfer(owner_cap, ctx.sender());
    }

    public fun register_receiver(ref: &mut CCIPObjectRef, receiver_state_id: address) {
        receiver_registry::register_receiver(ref, receiver_state_id, DummyReceiverProof {});
    }

    public fun get_counter(state: &CCIPReceiverState): u64 {
        state.counter
    }

    // PTB needs the package id from execution report (msg.receiver) & the module name to call the receiver
    // any ccip receiver must implement this function with the same signature
    public fun ccip_receive(ref: &CCIPObjectRef, package_id: address, receiver_params: osh::ReceiverParams): osh::ReceiverParams {
        let (message_op, receiver_params) = osh::extract_any2sui_message(ref, receiver_params, package_id, DummyReceiverProof {});
        if (message_op.is_none()) {
            return receiver_params
        };
        let message = message_op.borrow();
        let message_id = client::get_message_id(message);
        let source_chain_selector = client::get_source_chain_selector(message);
        let sender = client::get_sender(message);
        let data = client::get_data(message);
        let dest_token_transfer_length = client::get_dest_token_amounts(message).length();

        event::emit(
            ReceivedMessage {
                message_id,
                source_chain_selector,
                sender,
                data,
                dest_token_transfer_length,
            }
        );
        receiver_params
    }

    public fun ccip_receive_1(ref: &CCIPObjectRef, state: &mut CCIPReceiverState, package_id: address, receiver_params: osh::ReceiverParams): osh::ReceiverParams {
        let (message_op, receiver_params) = osh::extract_any2sui_message(ref, receiver_params, package_id, DummyReceiverProof {});
        if (message_op.is_none()) {
            return receiver_params
        };
        let message = message_op.borrow();
        let message_id = client::get_message_id(message);
        let source_chain_selector = client::get_source_chain_selector(message);
        let sender = client::get_sender(message);
        let data = client::get_data(message);
        let dest_token_transfer_length = client::get_dest_token_amounts(message).length();
        state.counter = state.counter + 1;
        state.message_id = message_id;
        state.source_chain_selector = source_chain_selector;
        state.sender = sender;
        state.data = data;
        state.dest_token_transfer_length = dest_token_transfer_length;

        event::emit(
            ReceivedMessage {
                message_id,
                source_chain_selector,
                sender,
                data,
                dest_token_transfer_length,
            }
        );
        receiver_params
    }
}
