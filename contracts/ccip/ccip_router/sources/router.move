/// The CCIP Router is the entrypoint for all CCIP messages.
/// To add support for a new onRamp version, the following steps are required:
/// 1. Develop and deploy a new OnRamp contract.
/// 2. Upgrade the Router contract in place to add support for the new OnRamp version with a hard coded address.
/// 3. Call the `set_on_ramp_versions` function to set the new OnRamp version for the destination chain.
/// The Router will now route messages to the new OnRamp contract for the given destination chain(s). This method
/// allows for lane-by-lane, config-based upgrades and even supports rollbacks to previous onRamp versions if needed.
/// Customers are unaware of the onRamp versions being used.
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
    use ccip_onramp::onramp as onramp_1_6_0;

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
    const E_UNSUPPORTED_DESTINATION_CHAIN: u64 = 2;
    const E_UNSUPPORTED_ON_RAMP_VERSION: u64 = 3;
    const E_INVALID_ON_RAMP_VERSION: u64 = 4;
    const E_SET_ON_RAMP_VERSIONS_MISMATCH: u64 = 5;

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
        if (@mcms_register_entrypoints == @0x1) {
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
    /// Returns whether the chain is supported.
    /// @param dest_chain_selector The destination chain selector.
    /// @return True if the chain is supported, false otherwise.
    public fun is_chain_supported(dest_chain_selector: u64): bool acquires RouterState {
        let state = borrow_state();
        state.on_ramp_versions.contains(dest_chain_selector)
    }

    #[view]
    /// Returns the address of the onRamp contract for the given destination chain.
    /// Multiple destination chains can share the same onRamp contract.
    /// @param dest_chain_selector The destination chain selector.
    /// @return The address of the onRamp contract.
    public fun get_on_ramp(dest_chain_selector: u64): address acquires RouterState {
        let state = borrow_state();

        assert!(
            state.on_ramp_versions.contains(dest_chain_selector),
            error::invalid_argument(E_UNSUPPORTED_DESTINATION_CHAIN)
        );

        let on_ramp_version = *state.on_ramp_versions.borrow(dest_chain_selector);

        if (on_ramp_version == vector[1, 6, 0]) {
            @ccip_onramp
        } else {
            // Returning 0x0 is inconsistent with the rest of the code but required for the offchain logic.
            @0x0
        }
    }

    #[view]
    /// Returns the fee to send a message with the given parameters, quoted in the given fee token.
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
    ): u64 acquires RouterState {
        let state = borrow_state();

        assert!(
            state.on_ramp_versions.contains(dest_chain_selector),
            error::invalid_argument(E_UNSUPPORTED_DESTINATION_CHAIN)
        );

        let on_ramp_version = *state.on_ramp_versions.borrow(dest_chain_selector);

        if (on_ramp_version == vector[1, 6, 0]) {
            onramp_1_6_0::get_fee(
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
            // If the onRamp version is not supported, we abort.
            abort error::invalid_state(E_UNSUPPORTED_ON_RAMP_VERSION)
        }
    }

    /// Sends a message to the given destination chain.
    /// This entry function does not return any value to make it compatible with EOA calls.
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

    /// Sends a message to the given destination chain.
    /// This entry function returns a message ID for calls from other programs.
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
            error::invalid_argument(E_UNSUPPORTED_DESTINATION_CHAIN)
        );

        let on_ramp_version = *state.on_ramp_versions.borrow(dest_chain_selector);

        let state_signer =
            account::create_signer_with_capability(&state.state_signer_cap);

        if (on_ramp_version == vector[1, 6, 0]) {
            onramp_1_6_0::ccip_send(
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
            // If the onRamp version is not supported, we abort.
            abort error::invalid_state(E_UNSUPPORTED_ON_RAMP_VERSION)
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
    /// Returns the onRamp versions for the given destination chains.
    /// For chain selectors that do not exist, an empty vector is returned.
    public fun get_on_ramp_versions(
        dest_chain_selectors: vector<u64>
    ): vector<vector<u8>> acquires RouterState {
        let state = borrow_state();
        dest_chain_selectors.map((
            |dest_chain_selector| {
                *state.on_ramp_versions.borrow_with_default(
                    dest_chain_selector, &vector[]
                )
            }
        ))
    }

    #[view]
    /// Returns the address of the onRamp that's set for the specified version.
    /// Aborts if an invalid or unknown version is specified.
    public fun get_on_ramp_for_version(on_ramp_version: vector<u8>): address {
        if (on_ramp_version == vector[1, 6, 0]) {
            return @ccip_onramp;
        };
        abort error::invalid_argument(E_INVALID_ON_RAMP_VERSION)
    }

    #[view]
    /// Returns a list of configured destination chain selectors.
    public fun get_dest_chains(): vector<u64> acquires RouterState {
        borrow_state().on_ramp_versions.keys()
    }

    /// Sets the onRamp versions for the given destination chains.
    /// This function will overwrite the existing versions.
    /// This function can only be called by the owner of the contract.
    /// @param dest_chain_selectors The destination chain selectors.
    /// @param on_ramp_versions The onRamp versions, the inner vector must be of length 0 or 3. 0 indicates
    /// the destination chain is no longer supported. Length 3 encodes the version of the onRamp contract.
    public entry fun set_on_ramp_versions(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        on_ramp_versions: vector<vector<u8>>
    ) acquires RouterState {
        assert!(
            dest_chain_selectors.length() == on_ramp_versions.length(),
            error::invalid_argument(E_SET_ON_RAMP_VERSIONS_MISMATCH)
        );

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
            }
        );
    }

    // ================================================================
    // |                          Ownable                             |
    // ================================================================
    #[view]
    public fun owner(): address acquires RouterState {
        ownable::owner(&borrow_state().ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires RouterState {
        ownable::has_pending_transfer(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires RouterState {
        ownable::pending_transfer_from(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires RouterState {
        ownable::pending_transfer_to(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires RouterState {
        ownable::pending_transfer_accepted(&borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires RouterState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires RouterState {
        let state = borrow_state_mut();
        ownable::accept_ownership(caller, &mut state.ownable_state)
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
            bcs_stream::assert_is_consumed(&stream);
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

    // ================================================================
    // |                          Tests                               |
    // ================================================================
    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }
}
