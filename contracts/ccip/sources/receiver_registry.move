module ccip::receiver_registry {
    use std::account;
    use std::bcs;
    use std::dispatchable_fungible_asset;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::function_info::{Self, FunctionInfo};
    use std::type_info::{Self, TypeInfo};
    use std::fungible_asset::{Self, Metadata};
    use std::object::{Self, ExtendRef, Object, TransferRef};
    use std::option::{Self, Option};
    use std::signer;
    use std::string;
    use std::vector;

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

    #[event]
    struct ReceiverRegistered has store, drop {
        receiver_address: address,
        receiver_module_name: vector<u8>
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_ALREADY_REGISTERED: u64 = 2;
    const E_UNKNOWN_RECEIVER: u64 = 3;
    const E_UNKNOWN_PROOF_TYPE: u64 = 4;
    const E_MISSING_INPUT: u64 = 5;
    const E_NON_EMPTY_INPUT: u64 = 6;

    public fun initialize(caller: &signer) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            !exists<ReceiverRegistryState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

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

        let state = borrow_state_mut();
        let dispatch_signer = object::generate_signer_for_extending(&state.extend_ref);

        let dispatch_object_seed = bcs::to_bytes(&receiver_address);
        vector::append(&mut dispatch_object_seed, b"CCIPReceiverRegistration");

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

        event::emit(ReceiverRegistered { receiver_address, receiver_module_name });
        event::emit_event(
            &mut state.receiver_registered_events,
            ReceiverRegistered { receiver_address, receiver_module_name }
        );
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
            option::is_some(&registration.executing_input),
            error::invalid_state(E_MISSING_INPUT)
        );

        option::extract(&mut registration.executing_input)
    }

    public(friend) fun start_receive(
        receiver_address: address, message: client::Any2AptosMessage
    ): Object<Metadata> acquires CCIPReceiverRegistration {
        let registration = get_registration_mut(receiver_address);

        assert!(
            option::is_none(&registration.executing_input),
            error::invalid_state(E_NON_EMPTY_INPUT)
        );

        option::fill(&mut registration.executing_input, message);

        registration.dispatch_metadata
    }

    public(friend) fun finish_receive(receiver_address: address) acquires CCIPReceiverRegistration {
        let registration = get_registration_mut(receiver_address);

        assert!(
            option::is_none(&registration.executing_input),
            error::invalid_state(E_NON_EMPTY_INPUT)
        );
    }

    inline fun borrow_state(): &ReceiverRegistryState {
        borrow_global<ReceiverRegistryState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut ReceiverRegistryState {
        borrow_global_mut<ReceiverRegistryState>(state_object::object_address())
    }

    inline fun get_registration_mut(receiver_address: address): &mut CCIPReceiverRegistration {
        assert!(
            exists<CCIPReceiverRegistration>(receiver_address),
            error::invalid_argument(E_UNKNOWN_RECEIVER)
        );
        borrow_global_mut<CCIPReceiverRegistration>(receiver_address)
    }
}
