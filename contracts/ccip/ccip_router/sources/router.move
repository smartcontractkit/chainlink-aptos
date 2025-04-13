module ccip_router::router {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event;
    use std::object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};
    use std::event::EventHandle;

    use ccip::ownable;
    use ccip_onramp::onramp;

    use mcms::mcms_registry;
    use mcms::bcs_stream;

    const STATE_SEED: vector<u8> = b"CHAINLINK_CCIP_ROUTER";

    struct RouterState has key {
        state_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        on_ramp_versions: SmartTable<u64, vector<u8>>,
        on_ramp_set_events: EventHandle<OnRampSet>
    }

    #[event]
    struct OnRampSet has store, drop {
        dest_chain_selector: u64,
        on_ramp_version: vector<u8>
    }

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_UNKNOWN_CHAIN: u64 = 2;
    const E_UNKNOWN_ON_RAMP: u64 = 3;
    const E_INVALID_ON_RAMP_VERSION: u64 = 4;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"Router 1.6.0")
    }

    fun init_module(publisher: &signer) {
        let (state_signer, state_signer_cap) =
            account::create_resource_account(publisher, STATE_SEED);

        move_to(
            &state_signer,
            RouterState {
                state_signer_cap,
                ownable_state: ownable::new(&state_signer, @ccip_router),
                on_ramp_versions: smart_table::new(),
                on_ramp_set_events: account::new_event_handle(&state_signer)
            }
        );

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"router"), McmsCallback {}
            );
        };
    }

    #[view]
    public fun get_state_address(): address {
        get_state_address_internal()
    }

    #[view]
    public fun is_chain_supported(dest_chain_selector: u64): bool {
        onramp::is_chain_supported(dest_chain_selector)
    }

    #[view]
    public fun get_fee(
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): u64 {
        onramp::get_fee(
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            token_store_addresses,
            fee_token,
            fee_token_store,
            extra_args
        )
    }

    public entry fun ccip_send(
        caller: &signer,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ) acquires RouterState {
        ccip_send_with_message_id(
            caller,
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            token_store_addresses,
            fee_token,
            fee_token_store,
            extra_args
        );
    }

    public fun ccip_send_with_message_id(
        caller: &signer,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>,
        token_amounts: vector<u64>,
        token_store_addresses: vector<address>,
        fee_token: address,
        fee_token_store: address,
        extra_args: vector<u8>
    ): vector<u8> acquires RouterState {
        let state = borrow_state();

        assert!(
            state.on_ramp_versions.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_CHAIN)
        );

        let on_ramp_version = *state.on_ramp_versions.borrow(dest_chain_selector);

        let state_signer =
            account::create_signer_with_capability(&state.state_signer_cap);

        if (on_ramp_version == vector[1, 6, 0]) {
            onramp::ccip_send(
                &state_signer,
                caller,
                dest_chain_selector,
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            )
        } else {
            abort error::invalid_argument(E_UNKNOWN_ON_RAMP)
        }
    }

    inline fun get_state_address_internal(): address {
        account::create_resource_address(&@ccip_router, STATE_SEED)
    }

    inline fun borrow_state(): &RouterState {
        borrow_global<RouterState>(get_state_address_internal())
    }

    inline fun borrow_state_mut(): &mut RouterState {
        borrow_global_mut<RouterState>(get_state_address_internal())
    }

    // ================================================================
    // |                       OnRamp Routing                         |
    // ================================================================

    #[view]
    public fun get_on_ramp_versions(
        dest_chain_selectors: vector<u64>
    ): vector<vector<u8>> acquires RouterState {
        let state = borrow_state();
        dest_chain_selectors.map((|dest_chain_selector| {
            *state.on_ramp_versions.borrow(dest_chain_selector)
        }))
    }

    public entry fun set_on_ramp_versions(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        on_ramp_versions: vector<vector<u8>>
    ) acquires RouterState {
        let state = borrow_state_mut();

        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        dest_chain_selectors.zip(
            on_ramp_versions,
            |dest_chain_selector, on_ramp_version| {
                let version_len = on_ramp_version.length();
                if (version_len == 0) {
                    if (state.on_ramp_versions.contains(dest_chain_selector)) {
                        state.on_ramp_versions.remove(dest_chain_selector);
                    };
                } else {
                    assert!(
                        version_len == 3,
                        error::invalid_argument(E_INVALID_ON_RAMP_VERSION)
                    );
                    state.on_ramp_versions.upsert(dest_chain_selector, on_ramp_version);
                };

                event::emit_event(
                    &mut state.on_ramp_set_events,
                    OnRampSet { dest_chain_selector, on_ramp_version }
                );
                event::emit(OnRampSet { dest_chain_selector, on_ramp_version });
            }
        );
    }

    //
    // ccip::ownable functions
    //

    #[view]
    public fun owner(): address acquires RouterState {
        ownable::owner(&borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires RouterState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut state.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires RouterState {
        let state = borrow_state_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires RouterState {
        let state = borrow_state_mut();
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    // ================================================================
    // |                      MCMS entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): Option<u128> acquires RouterState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"set_on_ramp_versions") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let ramps_to_use =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );

            set_on_ramp_versions(&caller, dest_chain_selectors, ramps_to_use);
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
}
