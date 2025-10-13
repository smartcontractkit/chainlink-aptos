module ccip::receiver_registry {
    use std::account;
    use std::bcs;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::function_info::{Self, FunctionInfo};
    use std::table::{Self, Table};
    use std::type_info::{Self, TypeInfo};
    use std::fungible_asset::{Self, Metadata};
    use std::object::{Self, ExtendRef, Object, TransferRef, ObjectCore};
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};

    use ccip::auth;
    use ccip::client;
    use ccip::state_object;

    friend ccip::receiver_dispatcher;

    struct ReceiverRegistryState has key, store {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,
        receiver_registered_events: EventHandle<ReceiverRegistered>
    }

    struct CCIPReceiverRegistration has key {
        ccip_receive_function: FunctionInfo,
        proof_typeinfo: TypeInfo,
        dispatch_metadata: Object<Metadata>,
        dispatch_extend_ref: ExtendRef,
        dispatch_transfer_ref: TransferRef,
        executing_input: Option<client::Any2AptosMessage>
    }

    struct CCIPReceiveState has key {
        executing_receivers: Table<address, bool>
    }

    #[event]
    struct ReceiverRegistered has store, drop {
        receiver_address: address,
        receiver_module_name: vector<u8>
    }

    const E_ALREADY_REGISTERED: u64 = 1;
    const E_UNKNOWN_RECEIVER: u64 = 2;
    const E_UNKNOWN_PROOF_TYPE: u64 = 3;
    const E_MISSING_INPUT: u64 = 4;
    const E_NON_EMPTY_INPUT: u64 = 5;
    const E_PROOF_TYPE_ACCOUNT_MISMATCH: u64 = 6;
    const E_PROOF_TYPE_MODULE_MISMATCH: u64 = 7;
    const E_UNAUTHORIZED: u64 = 8;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"ReceiverRegistry 1.6.0")
    }

    fun init_module(_publisher: &signer) {
        let state_object_signer = state_object::object_signer();
        let constructor_ref =
            object::create_named_object(&state_object_signer, b"CCIPReceiverRegistry");
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);

        let state = ReceiverRegistryState {
            extend_ref,
            transfer_ref,
            receiver_registered_events: account::new_event_handle(&state_object_signer)
        };

        move_to(&state_object_signer, state);

        move_to(
            &state_object_signer, CCIPReceiveState { executing_receivers: table::new() }
        );
    }

    public fun register_receiver<ProofType: drop>(
        receiver_account: &signer, receiver_module_name: vector<u8>, _proof: ProofType
    ) acquires ReceiverRegistryState {
        let receiver_address = signer::address_of(receiver_account);
        assert!(
            !exists<CCIPReceiverRegistration>(receiver_address),
            error::invalid_argument(E_ALREADY_REGISTERED)
        );

        let ccip_receive_function =
            function_info::new_function_info(
                receiver_account,
                string::utf8(receiver_module_name),
                string::utf8(b"ccip_receive")
            );
        let proof_typeinfo = type_info::type_of<ProofType>();
        assert!(
            proof_typeinfo.account_address() == receiver_address,
            E_PROOF_TYPE_ACCOUNT_MISMATCH
        );
        assert!(
            proof_typeinfo.module_name() == receiver_module_name,
            E_PROOF_TYPE_MODULE_MISMATCH
        );

        let state = borrow_state_mut();
        let dispatch_signer = object::generate_signer_for_extending(&state.extend_ref);

        let dispatch_object_seed = bcs::to_bytes(&receiver_address);
        dispatch_object_seed.append(b"CCIPReceiverRegistration");

        let dispatch_constructor_ref =
            object::create_named_object(&dispatch_signer, dispatch_object_seed);
        let dispatch_extend_ref = object::generate_extend_ref(&dispatch_constructor_ref);
        let dispatch_transfer_ref =
            object::generate_transfer_ref(&dispatch_constructor_ref);
        let dispatch_metadata =
            fungible_asset::add_fungibility(
                &dispatch_constructor_ref,
                option::none(),
                // max name length is 32 chars
                string::utf8(b"CCIPReceiverRegistration"),
                // max symbol length is 10 chars
                string::utf8(b"CCIPRR"),
                0,
                string::utf8(b""),
                string::utf8(b"")
            );

        dispatchable_fungible_asset::register_derive_supply_dispatch_function(
            &dispatch_constructor_ref, option::some(ccip_receive_function)
        );

        move_to(
            receiver_account,
            CCIPReceiverRegistration {
                ccip_receive_function,
                proof_typeinfo,
                dispatch_metadata,
                dispatch_extend_ref,
                dispatch_transfer_ref,
                executing_input: option::none()
            }
        );

        event::emit_event(
            &mut state.receiver_registered_events,
            ReceiverRegistered { receiver_address, receiver_module_name }
        );
    }

    #[view]
    public fun is_registered_receiver(receiver_address: address): bool {
        exists<CCIPReceiverRegistration>(receiver_address)
    }

    #[view]
    public fun is_executing_receiver_in_progress(
        receiver_address: address
    ): bool acquires CCIPReceiveState {
        borrow_ccip_receive_state_mut().executing_receivers.contains(receiver_address)
    }

    public fun get_receiver_input<ProofType: drop>(
        receiver_address: address, _proof: ProofType
    ): client::Any2AptosMessage acquires CCIPReceiverRegistration {
        let registration = get_registration_mut(receiver_address);

        assert!(
            registration.proof_typeinfo == type_info::type_of<ProofType>(),
            error::permission_denied(E_UNKNOWN_PROOF_TYPE)
        );

        assert!(
            registration.executing_input.is_some(),
            error::invalid_state(E_MISSING_INPUT)
        );

        registration.executing_input.extract()
    }

    public(friend) fun start_receive(
        receiver_address: address, message: client::Any2AptosMessage
    ): Object<Metadata> acquires CCIPReceiverRegistration, CCIPReceiveState {
        let registration = get_registration_mut(receiver_address);

        assert!(
            registration.executing_input.is_none(),
            error::invalid_state(E_NON_EMPTY_INPUT)
        );

        registration.executing_input.fill(message);

        borrow_ccip_receive_state_mut().executing_receivers.add(receiver_address, true);

        registration.dispatch_metadata
    }

    public(friend) fun finish_receive(
        receiver_address: address
    ) acquires CCIPReceiverRegistration, CCIPReceiveState {
        let registration = get_registration_mut(receiver_address);

        assert!(
            registration.executing_input.is_none(),
            error::invalid_state(E_NON_EMPTY_INPUT)
        );

        borrow_ccip_receive_state_mut().executing_receivers.remove(receiver_address);
    }

    inline fun borrow_state(): &ReceiverRegistryState {
        borrow_global<ReceiverRegistryState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut ReceiverRegistryState {
        borrow_global_mut<ReceiverRegistryState>(state_object::object_address())
    }

    inline fun borrow_ccip_receive_state_mut(): &mut CCIPReceiveState {
        borrow_global_mut<CCIPReceiveState>(state_object::object_address())
    }

    inline fun get_registration_mut(receiver_address: address): &mut CCIPReceiverRegistration {
        assert!(
            exists<CCIPReceiverRegistration>(receiver_address),
            error::invalid_argument(E_UNKNOWN_RECEIVER)
        );
        borrow_global_mut<CCIPReceiverRegistration>(receiver_address)
    }

    // ============================= Migrations =============================

    public fun initialize_ccip_receive_state(caller: &signer) {
        auth::assert_only_owner(signer::address_of(caller));

        move_to(
            &state_object::object_signer(),
            CCIPReceiveState { executing_receivers: table::new() }
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
