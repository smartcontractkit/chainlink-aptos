module ccip::auth {
    use std::account::{Self, SignerCapability};
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
        ownable_state: ownable::OwnableState,
        router_address: address
    }

    struct PendingRouterSignerCapability has key {
        signer_capability: SignerCapability
    }

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_NOT_CCIP: u64 = 2;
    const E_SIGNER_CAP_NOT_FOUND: u64 = 3;
    const E_NOT_CCIP_ROUTER: u64 = 4;

    fun init_module(publisher: &signer) {
        let state_object_signer = &state_object::object_signer();

        let (router_signer, signer_capability) =
            account::create_resource_account(
                state_object_signer, b"CHAINLINK_CCIP_ROUTER"
            );

        move_to(
            state_object_signer,
            AuthState {
                ownable_state: ownable::new(state_object_signer, @ccip),
                router_address: signer::address_of(&router_signer)
            }
        );

        move_to(publisher, PendingRouterSignerCapability { signer_capability });

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"auth"), McmsCallback {}
            );
        };
    }

    public fun retrieve_router_signer_cap(
        caller: &signer
    ): SignerCapability acquires PendingRouterSignerCapability {
        assert!(
            signer::address_of(caller) == @ccip, error::permission_denied(E_NOT_CCIP)
        );
        assert!(
            exists<PendingRouterSignerCapability>(@ccip),
            error::not_found(E_SIGNER_CAP_NOT_FOUND)
        );

        let PendingRouterSignerCapability { signer_capability } =
            move_from<PendingRouterSignerCapability>(@ccip);
        signer_capability
    }

    inline fun borrow_state(): &AuthState {
        borrow_global<AuthState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut AuthState {
        borrow_global_mut<AuthState>(state_object::object_address())
    }

    // ================================================================
    // |                          Ownable                             |
    // ================================================================

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

    public entry fun assert_is_router(caller: address) acquires AuthState {
        assert!(
            caller == borrow_state().router_address,
            error::permission_denied(E_NOT_CCIP_ROUTER)
        );
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    struct McmsCallback {}
    has drop;

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires AuthState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
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
