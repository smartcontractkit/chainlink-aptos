module ccip_router::router {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::object;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};
    use std::event::EventHandle;

    use ccip::auth;
    use ccip::onramp;

    use mcms::mcms_registry;
    use mcms::bcs_stream;

    struct RouterState has key {
        signer_capability: SignerCapability,
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
        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"router"), McmsCallback {}
            );
        };

        let signer_capability = auth::retrieve_router_signer_cap(publisher);

        move_to(
            publisher,
            RouterState {
                signer_capability,
                on_ramp_versions: smart_table::new(),
                on_ramp_set_events: account::new_event_handle(publisher)
            }
        );
    }

    #[view]
    public fun get_state_address(): address acquires RouterState {
        signer::address_of(&get_signer())
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
        if (!state.on_ramp_versions.contains(dest_chain_selector)) {
            abort error::invalid_argument(E_UNKNOWN_CHAIN)
        };

        let on_ramp_version = *state.on_ramp_versions.borrow(dest_chain_selector);

        if (on_ramp_version == vector[1, 6, 0]) {
            onramp::ccip_send(
                &get_signer(),
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

    inline fun get_signer(): signer {
        account::create_signer_with_capability(&borrow_state().signer_capability)
    }

    inline fun borrow_state(): &RouterState {
        borrow_global<RouterState>(@ccip_router)
    }

    inline fun borrow_state_mut(): &mut RouterState {
        borrow_global_mut<RouterState>(@ccip)
    }

    // ================================================================
    // |                       OnRamp Routing                         |
    // ================================================================

    public fun get_on_ramp_versions(
        dest_chain_selectors: vector<u64>
    ): vector<vector<u8>> acquires RouterState {
        let state = borrow_state();
        dest_chain_selectors.map((|dest_chain_selector| {
            *state.on_ramp_versions.borrow(dest_chain_selector)
        }))
    }

    public fun set_on_ramp_versions(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        on_ramp_versions: vector<vector<u8>>
    ) acquires RouterState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        dest_chain_selectors.zip(
            on_ramp_versions,
            |dest_chain_selector, on_ramp_version| {
                assert!(
                    on_ramp_version.length() == 3,
                    error::invalid_argument(E_INVALID_ON_RAMP_VERSION)
                );

                state.on_ramp_versions.upsert(dest_chain_selector, on_ramp_version);
            }
        );
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

        let function_bytes = *string::bytes(&function);
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
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }
}
