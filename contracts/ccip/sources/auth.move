module ccip::auth {
    use std::error;
    use std::object;
    use std::option;
    use std::signer;
    use std::string;

    use ccip::ownable;
    use ccip::state_object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    struct AuthState has key {
        ownable_state: ownable::OwnableState
        // TODO: add allowlists here
    }

    const E_UNKNOWN_FUNCTION: u64 = 1;

    fun init_module(publisher: &signer) {
        let state_object_signer = &state_object::object_signer();

        move_to(
            state_object_signer,
            AuthState { ownable_state: ownable::new(state_object_signer, @ccip) }
        );

        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"auth"), McmsCallback {}
            );
        };
    }

    inline fun borrow_state(): &AuthState {
        borrow_global<AuthState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut AuthState {
        borrow_global_mut<AuthState>(state_object::object_address())
    }

    //
    // ccip::ownable functions
    //

    #[view]
    public fun owner(): address acquires AuthState {
        ownable::owner(&borrow_state().ownable_state)
    }

    public fun assert_only_owner(caller: address) acquires AuthState {
        ownable::assert_only_owner(caller, &borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires AuthState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut state.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires AuthState {
        let state = borrow_state_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires AuthState {
        let state = borrow_state_mut();
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    //
    // MCMS entrypoint
    //

    struct McmsCallback {}
    has drop;

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires AuthState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *string::bytes(&function);
        let stream = bcs_stream::new(data);

        if (function_bytes == b"transfer_ownership") {
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
}
