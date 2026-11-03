/// Minimal stand-in for platform::forwarder used to prove MCMS control via an adapter.
/// Ownership model (owner_address / pending_owner_address, 2-step transfer) mirrors the real forwarder.
/// Intentionally has no MCMS dependency.
module dummy_forwarder::forwarder {
    use aptos_framework::object::{Self, ExtendRef, TransferRef};

    use std::error;
    use std::event;
    use std::signer;

    const E_NOT_OWNER: u64 = 7;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 13;
    const E_NOT_PROPOSED_OWNER: u64 = 14;

    const APP_OBJECT_SEED: vector<u8> = b"FORWARDER";

    struct State has key {
        owner_address: address,
        pending_owner_address: address,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,

        value: u64
    }

    #[event]
    struct ValueSet has drop, store {
        value: u64
    }

    #[event]
    struct OwnershipTransferRequested has drop, store {
        from: address,
        to: address
    }

    #[event]
    struct OwnershipTransferred has drop, store {
        from: address,
        to: address
    }

    inline fun assert_is_owner(state: &State, target_address: address) {
        assert!(
            state.owner_address == target_address,
            error::permission_denied(E_NOT_OWNER)
        );
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @dummy_forwarder, 1);

        let constructor_ref = object::create_named_object(publisher, APP_OBJECT_SEED);

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let app_signer = &object::generate_signer(&constructor_ref);

        move_to(
            app_signer,
            State {
                owner_address: @owner,
                pending_owner_address: @0x0,
                extend_ref,
                transfer_ref,
                value: 0
            }
        );
    }

    inline fun get_state_addr(): address {
        object::create_object_address(&@dummy_forwarder, APP_OBJECT_SEED)
    }

    public entry fun set_value(authority: &signer, value: u64) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        assert_is_owner(state, signer::address_of(authority));

        state.value = value;

        event::emit(ValueSet { value });
    }

    #[view]
    public fun get_value(): u64 acquires State {
        borrow_global<State>(get_state_addr()).value
    }

    #[view]
    public fun get_owner(): address acquires State {
        borrow_global<State>(get_state_addr()).owner_address
    }

    #[view]
    public fun get_pending_owner(): address acquires State {
        borrow_global<State>(get_state_addr()).pending_owner_address
    }

    public entry fun transfer_ownership(authority: &signer, to: address) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());
        assert_is_owner(state, signer::address_of(authority));
        assert!(
            state.owner_address != to,
            error::invalid_argument(E_CANNOT_TRANSFER_TO_SELF)
        );

        state.pending_owner_address = to;

        event::emit(OwnershipTransferRequested { from: state.owner_address, to });
    }

    public entry fun accept_ownership(authority: &signer) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());
        assert!(
            state.pending_owner_address == signer::address_of(authority),
            error::permission_denied(E_NOT_PROPOSED_OWNER)
        );

        let old_owner_address = state.owner_address;
        state.owner_address = state.pending_owner_address;
        state.pending_owner_address = @0x0;

        event::emit(
            OwnershipTransferred { from: old_owner_address, to: state.owner_address }
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }

    #[test(owner = @owner, publisher = @dummy_forwarder)]
    fun test_set_get_value(owner: &signer, publisher: &signer) acquires State {
        init_module(publisher);
        assert!(get_value() == 0, 1);
        set_value(owner, 42);
        assert!(get_value() == 42, 2);
    }

    #[test(publisher = @dummy_forwarder, unknown_user = @0xbeef)]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder::forwarder)]
    fun test_set_value_not_owner(
        publisher: &signer, unknown_user: &signer
    ) acquires State {
        init_module(publisher);
        set_value(unknown_user, 42);
    }

    #[test(owner = @owner, publisher = @dummy_forwarder, new_owner = @0xbeef)]
    fun test_transfer_ownership(
        owner: &signer, publisher: &signer, new_owner: &signer
    ) acquires State {
        init_module(publisher);
        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, @0xbeef);
        assert!(get_pending_owner() == @0xbeef, 2);
        accept_ownership(new_owner);

        assert!(get_owner() == @0xbeef, 3);
        set_value(new_owner, 7);
        assert!(get_value() == 7, 4);
    }

    #[test(owner = @owner, publisher = @dummy_forwarder)]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder::forwarder)]
    fun test_old_owner_rejected_after_transfer(
        owner: &signer, publisher: &signer
    ) acquires State {
        init_module(publisher);
        transfer_ownership(owner, @0xbeef);
        accept_ownership(&aptos_framework::account::create_signer_for_test(@0xbeef));
        set_value(owner, 1);
    }
}
