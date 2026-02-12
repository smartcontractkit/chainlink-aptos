module ccip::auth {
    use std::error;
    use std::object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string;

    use ccip::allowlist;
    use ccip::ownable;
    use ccip::state_object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    struct AuthState has key {
        ownable_state: ownable::OwnableState,
        allowed_onramps: allowlist::AllowlistState,
        allowed_offramps: allowlist::AllowlistState
    }

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_NOT_ALLOWED_ONRAMP: u64 = 2;
    const E_NOT_ALLOWED_OFFRAMP: u64 = 3;
    const E_NOT_OWNER_OR_CCIP: u64 = 4;

    fun init_module(publisher: &signer) {
        let state_object_signer = &state_object::object_signer();

        let allowed_onramps =
            allowlist::new_with_name(
                state_object_signer, vector[], string::utf8(b"onramps")
            );
        allowlist::set_allowlist_enabled(&mut allowed_onramps, true);

        let allowed_offramps =
            allowlist::new_with_name(
                state_object_signer, vector[], string::utf8(b"offramps")
            );
        allowlist::set_allowlist_enabled(&mut allowed_offramps, true);

        move_to(
            state_object_signer,
            AuthState {
                ownable_state: ownable::new(state_object_signer, @ccip),
                allowed_onramps,
                allowed_offramps
            }
        );

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };
    }

    #[view]
    public fun get_allowed_onramps(): vector<address> acquires AuthState {
        allowlist::get_allowlist(&borrow_state().allowed_onramps)
    }

    #[view]
    public fun get_allowed_offramps(): vector<address> acquires AuthState {
        allowlist::get_allowlist(&borrow_state().allowed_offramps)
    }

    #[view]
    public fun is_onramp_allowed(onramp_address: address): bool acquires AuthState {
        allowlist::is_allowed(&borrow_state().allowed_onramps, onramp_address)
    }

    #[view]
    public fun is_offramp_allowed(offramp_address: address): bool acquires AuthState {
        allowlist::is_allowed(&borrow_state().allowed_offramps, offramp_address)
    }

    public entry fun apply_allowed_onramp_updates(
        caller: &signer, onramps_to_remove: vector<address>, onramps_to_add: vector<address>
    ) acquires AuthState {
        let state = borrow_state_mut();

        assert_is_owner_or_ccip(signer::address_of(caller), &state.ownable_state);

        allowlist::apply_allowlist_updates(
            &mut state.allowed_onramps, onramps_to_remove, onramps_to_add
        );
    }

    public entry fun apply_allowed_offramp_updates(
        caller: &signer,
        offramps_to_remove: vector<address>,
        offramps_to_add: vector<address>
    ) acquires AuthState {
        let state = borrow_state_mut();

        assert_is_owner_or_ccip(signer::address_of(caller), &state.ownable_state);

        allowlist::apply_allowlist_updates(
            &mut state.allowed_offramps, offramps_to_remove, offramps_to_add
        );
    }

    inline fun borrow_state(): &AuthState {
        borrow_global<AuthState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut AuthState {
        borrow_global_mut<AuthState>(state_object::object_address())
    }

    inline fun assert_is_owner_or_ccip(
        caller: address, ownable_state: &ownable::OwnableState
    ) {
        assert!(
            caller == @ccip || caller == ownable::owner(ownable_state),
            error::permission_denied(E_NOT_OWNER_OR_CCIP)
        );
    }

    public fun assert_is_allowed_onramp(caller: address) acquires AuthState {
        assert!(
            allowlist::is_allowed(&borrow_state().allowed_onramps, caller),
            error::permission_denied(E_NOT_ALLOWED_ONRAMP)
        );
    }

    public fun assert_is_allowed_offramp(caller: address) acquires AuthState {
        assert!(
            allowlist::is_allowed(&borrow_state().allowed_offramps, caller),
            error::permission_denied(E_NOT_ALLOWED_OFFRAMP)
        );
    }

    // ================================================================
    // |                          Ownable                             |
    // ================================================================
    #[view]
    public fun owner(): address acquires AuthState {
        ownable::owner(&borrow_state().ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires AuthState {
        ownable::has_pending_transfer(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires AuthState {
        ownable::pending_transfer_from(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires AuthState {
        ownable::pending_transfer_to(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires AuthState {
        ownable::pending_transfer_accepted(&borrow_state().ownable_state)
    }

    public fun assert_only_owner(caller: address) acquires AuthState {
        ownable::assert_only_owner(caller, &borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires AuthState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires AuthState {
        let state = borrow_state_mut();
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires AuthState {
        let state = borrow_state_mut();
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires AuthState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"apply_allowed_onramp_updates") {
            let onramps_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let onramps_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_allowed_onramp_updates(&caller, onramps_to_remove, onramps_to_add)
        } else if (function_bytes == b"apply_allowed_offramp_updates") {
            let offramps_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let offramps_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_allowed_offramp_updates(&caller, offramps_to_remove, offramps_to_add)
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            transfer_ownership(&caller, to)
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);
            accept_ownership(&caller)
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            execute_ownership_transfer(&caller, to)
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"auth"), McmsCallback {}
        );
    }

    // ========================== TEST ONLY ==========================
    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun test_register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"auth"), McmsCallback {}
        );
    }
}
