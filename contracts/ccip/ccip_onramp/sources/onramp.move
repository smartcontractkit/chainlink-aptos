module ccip_onramp::onramp {
    use std::account::{Self, SignerCapability};
    use std::aptos_hash;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::dispatchable_fungible_asset;
    use std::fungible_asset::{Self, Metadata, FungibleStore};
    use std::object::{Self, Object};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};

    use ccip::address;
    use ccip::auth;
    use ccip::eth_abi;
    use ccip::fee_quoter;
    use ccip::merkle_proof;
    use ccip::nonce_manager;
    use ccip::ownable;
    use ccip::rmn_remote;
    use ccip::token_admin_dispatcher;
    use ccip::token_admin_registry;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const STATE_SEED: vector<u8> = b"CHAINLINK_CCIP_ONRAMP";

    struct OnRampDeployment has key, store {
        state_signer_cap: SignerCapability
    }

    struct OnRampState has key, store {
        state_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        chain_selector: u64,
        fee_aggregator: address,
        allowlist_admin: address,

        // dest chain selector -> config
        dest_chain_configs: SmartTable<u64, DestChainConfig>,
        config_set_events: EventHandle<ConfigSet>,
        dest_chain_config_set_events: EventHandle<DestChainConfigSet>,
        ccip_message_sent_events: EventHandle<CCIPMessageSent>,
        allowlist_senders_added_events: EventHandle<AllowlistSendersAdded>,
        allowlist_senders_removed_events: EventHandle<AllowlistSendersRemoved>,
        fee_token_withdrawn_events: EventHandle<FeeTokenWithdrawn>
    }

    struct DestChainConfigsV2 has key, store {
        dest_chain_configs: SmartTable<u64, DestChainConfigV2>,
        dest_chain_config_v2_set_events: EventHandle<DestChainConfigSetV2>
    }

    struct DestChainConfig has store, drop {
        sequence_number: u64,
        allowlist_enabled: bool,
        router: address,
        allowed_senders: vector<address>
    }

    struct DestChainConfigV2 has store, drop {
        sequence_number: u64,
        allowlist_enabled: bool,
        /// The address of the `router` module, used for offchain discovery.
        router: address,
        /// The address of the expected signer when the `router` calls `onramp`
        router_state_address: address,
        allowed_senders: vector<address>
    }

    struct RampMessageHeader has store, drop, copy {
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64
    }

    struct Aptos2AnyRampMessage has store, drop, copy {
        header: RampMessageHeader,
        sender: address,
        data: vector<u8>,
        receiver: vector<u8>,
        extra_args: vector<u8>,
        fee_token: address,
        fee_token_amount: u64,
        fee_value_juels: u256,
        token_amounts: vector<Aptos2AnyTokenTransfer>
    }

    struct Aptos2AnyTokenTransfer has store, drop, copy {
        source_pool_address: address,
        dest_token_address: vector<u8>,
        extra_data: vector<u8>,
        amount: u64,
        dest_exec_data: vector<u8>
    }

    struct StaticConfig has store, drop, copy {
        chain_selector: u64
    }

    struct DynamicConfig has store, drop, copy {
        fee_aggregator: address,
        allowlist_admin: address
    }

    #[event]
    struct ConfigSet has store, drop {
        static_config: StaticConfig,
        dynamic_config: DynamicConfig
    }

    #[event]
    struct DestChainConfigSet has store, drop {
        dest_chain_selector: u64,
        sequence_number: u64,
        router: address,
        allowlist_enabled: bool
    }

    #[event]
    struct DestChainConfigSetV2 has store, drop {
        dest_chain_selector: u64,
        sequence_number: u64,
        /// The address of the `router` module, used for offchain discovery.
        router: address,
        /// The address of the expected signer when the `router` calls `onramp`
        router_state_address: address,
        allowlist_enabled: bool
    }

    #[event]
    struct CCIPMessageSent has store, drop {
        dest_chain_selector: u64,
        sequence_number: u64,
        message: Aptos2AnyRampMessage
    }

    #[event]
    struct AllowlistSendersAdded has store, drop {
        dest_chain_selector: u64,
        senders: vector<address>
    }

    #[event]
    struct AllowlistSendersRemoved has store, drop {
        dest_chain_selector: u64,
        senders: vector<address>
    }

    #[event]
    struct FeeTokenWithdrawn has store, drop {
        fee_aggregator: address,
        fee_token: address,
        amount: u64
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_DEST_CHAIN_ARGUMENT_MISMATCH: u64 = 2;
    const E_INVALID_DEST_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_DEST_CHAIN_SELECTOR: u64 = 4;
    const E_UNKNOWN_FUNCTION: u64 = 5;
    const E_SENDER_NOT_ALLOWED: u64 = 6;
    const E_ONLY_CALLABLE_BY_OWNER_OR_ALLOWLIST_ADMIN: u64 = 7;
    const E_INVALID_ALLOWLIST_REQUEST: u64 = 8;
    const E_INVALID_ALLOWLIST_ADDRESS: u64 = 9;
    const E_UNSUPPORTED_TOKEN: u64 = 10;
    const E_INVALID_FEE_TOKEN: u64 = 11;
    const E_CURSED_BY_RMN: u64 = 12;
    const E_INVALID_TOKEN: u64 = 13;
    const E_INVALID_TOKEN_STORE: u64 = 14;
    const E_UNEXPECTED_WITHDRAW_AMOUNT: u64 = 15;
    const E_UNEXPECTED_FUNGIBLE_ASSET: u64 = 16;
    const E_FEE_AGGREGATOR_NOT_SET: u64 = 17;
    const E_MUST_BE_CALLED_BY_ROUTER: u64 = 18;
    const E_TOKEN_AMOUNT_MISMATCH: u64 = 19;
    const E_CANNOT_SEND_ZERO_TOKENS: u64 = 20;
    /// Chain selector cannot be zero
    const E_ZERO_CHAIN_SELECTOR: u64 = 21;
    /// Invalid arguments provided for message hash calculation
    const E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS: u64 = 22;
    /// V2 destination chain configs have already been initialized
    const E_DEST_CHAIN_CONFIGS_V2_ALREADY_INITIALIZED: u64 = 23;
    /// V2 destination chain configs have not been initialized
    const E_DEST_CHAIN_CONFIGS_V2_NOT_INITIALIZED: u64 = 24;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"OnRamp 1.6.0")
    }

    fun init_module(publisher: &signer) {
        let (state_signer, state_signer_cap) =
            account::create_resource_account(publisher, STATE_SEED);

        move_to(publisher, OnRampDeployment { state_signer_cap });

        if (@ccip_onramp == @ccip) {
            // if we're deployed on the same code object, self-register as an allowed onramp.
            auth::apply_allowed_onramp_updates(
                publisher,
                vector[],
                vector[signer::address_of(&state_signer)]
            );
        };

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };
    }

    #[view]
    public fun get_state_address(): address {
        get_state_address_internal()
    }

    public entry fun initialize(
        caller: &signer,
        chain_selector: u64,
        fee_aggregator: address,
        allowlist_admin: address,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) acquires OnRampDeployment {
        assert!(chain_selector != 0, E_ZERO_CHAIN_SELECTOR);
        assert!(
            exists<OnRampDeployment>(@ccip_onramp),
            error::invalid_state(E_ALREADY_INITIALIZED)
        );

        let OnRampDeployment { state_signer_cap } =
            move_from<OnRampDeployment>(@ccip_onramp);

        let state_signer = &account::create_signer_with_capability(&state_signer_cap);

        let ownable_state = ownable::new(state_signer, @ccip_onramp);

        ownable::assert_only_owner(signer::address_of(caller), &ownable_state);

        let state = OnRampState {
            state_signer_cap,
            ownable_state,
            chain_selector,
            fee_aggregator: @0x0,
            allowlist_admin: @0x0,
            dest_chain_configs: smart_table::new(),
            config_set_events: account::new_event_handle(state_signer),
            dest_chain_config_set_events: account::new_event_handle(state_signer),
            ccip_message_sent_events: account::new_event_handle(state_signer),
            allowlist_senders_added_events: account::new_event_handle(state_signer),
            allowlist_senders_removed_events: account::new_event_handle(state_signer),
            fee_token_withdrawn_events: account::new_event_handle(state_signer)
        };

        set_dynamic_config_internal(&mut state, fee_aggregator, allowlist_admin);

        let dest_chain_configs_v2 = DestChainConfigsV2 {
            dest_chain_configs: smart_table::new(),
            dest_chain_config_v2_set_events: account::new_event_handle(state_signer)
        };

        // Since we cannot change initialize function signature, we need to set router state addresses to @0x0
        // To update, call apply_dest_chain_config_updates_v2 with the new router state addresses
        let router_state_addresses = dest_chain_routers.map_ref((|_| { @0x0 }));

        // Initialize V2 configs using routers for both module and state addresses
        apply_dest_chain_config_updates_v2_internal(
            &mut state,
            &mut dest_chain_configs_v2,
            dest_chain_selectors,
            dest_chain_routers, // router module addresses
            router_state_addresses,
            dest_chain_allowlist_enabled
        );

        move_to(state_signer, state);
        move_to(state_signer, dest_chain_configs_v2);
    }

    #[view]
    public fun is_chain_supported(
        dest_chain_selector: u64
    ): bool acquires OnRampState, DestChainConfigsV2 {
        // TODO: delete this clause after migration completes
        if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
            let state = borrow_state();
            state.dest_chain_configs.contains(dest_chain_selector)
        } else {
            let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
            dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector)
        }
    }

    #[view]
    public fun get_expected_next_sequence_number(
        dest_chain_selector: u64
    ): u64 acquires OnRampState, DestChainConfigsV2 {
        // TODO: delete this clause after migration completes
        if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
            let state = borrow_state();
            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );
            let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);
            return dest_chain_config.sequence_number + 1
        };

        let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
        assert!(
            dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        let dest_chain_config =
            dest_chain_configs_v2.dest_chain_configs.borrow(dest_chain_selector);
        dest_chain_config.sequence_number + 1
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
        get_fee_internal(
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

    inline fun get_fee_internal(
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
        assert!(
            !rmn_remote::is_cursed_u128(dest_chain_selector as u128),
            error::permission_denied(E_CURSED_BY_RMN)
        );
        fee_quoter::get_validated_fee(
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

    inline fun resolve_fungible_asset(token: address): Object<Metadata> {
        assert!(
            object::object_exists<Metadata>(token),
            error::invalid_argument(E_INVALID_TOKEN)
        );
        object::address_to_object<Metadata>(token)
    }

    inline fun resolve_fungible_store(
        owner: address, token: Object<Metadata>, store_address: address
    ): Object<FungibleStore> {
        let resolved_address =
            if (store_address == @0x0) {
                primary_fungible_store::primary_store_address(owner, token)
            } else {
                store_address
            };
        assert!(
            object::object_exists<FungibleStore>(resolved_address),
            error::invalid_argument(E_INVALID_TOKEN_STORE)
        );
        object::address_to_object<FungibleStore>(resolved_address)
    }

    public fun ccip_send(
        router: &signer,
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
    ): vector<u8> acquires OnRampState, DestChainConfigsV2 {
        // get_fee_internal checks for curse status
        let fee_token_amount =
            get_fee_internal(
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
        if (fee_token_amount != 0) {
            // deposit the fee in the state object's primary fungible store.
            let fa_metadata = resolve_fungible_asset(fee_token);
            let resolved_store =
                resolve_fungible_store(
                    signer::address_of(caller), fa_metadata, fee_token_store
                );

            let fa =
                dispatchable_fungible_asset::withdraw(
                    caller, resolved_store, fee_token_amount
                );
            // validate the withdrawn asset since we're potentially calling dispatchable fungible asset functions.
            assert!(
                fa_metadata == fungible_asset::metadata_from_asset(&fa),
                error::invalid_state(E_UNEXPECTED_FUNGIBLE_ASSET)
            );
            assert!(
                fee_token_amount == fungible_asset::amount(&fa),
                error::invalid_state(E_UNEXPECTED_WITHDRAW_AMOUNT)
            );

            primary_fungible_store::deposit(get_state_address_internal(), fa);
        };

        let state = borrow_state_mut();

        // TODO: delete this clause after migration completes
        if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);
            if (dest_chain_config.allowlist_enabled) {
                assert!(
                    dest_chain_config.allowed_senders.contains(
                        &signer::address_of(caller)
                    ),
                    error::permission_denied(E_SENDER_NOT_ALLOWED)
                );
            };

            assert!(
                dest_chain_config.router == signer::address_of(router),
                error::permission_denied(E_MUST_BE_CALLED_BY_ROUTER)
            );
        } else {
            let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
            assert!(
                dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );
            let dest_chain_config_v2 =
                dest_chain_configs_v2.dest_chain_configs.borrow(dest_chain_selector);

            if (dest_chain_config_v2.allowlist_enabled) {
                assert!(
                    dest_chain_config_v2.allowed_senders.contains(
                        &signer::address_of(caller)
                    ),
                    error::permission_denied(E_SENDER_NOT_ALLOWED)
                );
            };

            assert!(
                dest_chain_config_v2.router_state_address == signer::address_of(router),
                error::permission_denied(E_MUST_BE_CALLED_BY_ROUTER)
            );
        };

        let sender = signer::address_of(caller);

        let dest_token_addresses = vector[];
        let dest_pool_datas = vector[];

        let state_signer =
            account::create_signer_with_capability(&state.state_signer_cap);

        let tokens_len = token_addresses.length();
        assert!(
            tokens_len == token_amounts.length()
                && tokens_len == token_store_addresses.length(),
            error::invalid_argument(E_TOKEN_AMOUNT_MISMATCH)
        );

        let token_receiver =
            fee_quoter::get_token_receiver(dest_chain_selector, extra_args, receiver);

        let token_transfers = vector[];
        for (i in 0..tokens_len) {
            let token = token_addresses[i];
            let amount = token_amounts[i];
            let token_store = token_store_addresses[i];

            assert!(amount > 0, error::invalid_argument(E_CANNOT_SEND_ZERO_TOKENS));

            let fa_metadata = resolve_fungible_asset(token);
            let resolved_store = resolve_fungible_store(sender, fa_metadata, token_store);

            let fa = dispatchable_fungible_asset::withdraw(
                caller, resolved_store, amount
            );

            // validate the withdrawn asset since we're potentially calling dispatchable fungible asset functions.
            assert!(
                fa_metadata == fungible_asset::metadata_from_asset(&fa),
                error::invalid_state(E_UNEXPECTED_FUNGIBLE_ASSET)
            );
            assert!(
                amount == fungible_asset::amount(&fa),
                error::invalid_state(E_UNEXPECTED_WITHDRAW_AMOUNT)
            );

            let token_pool_address = token_admin_registry::get_pool(token);
            assert!(
                token_pool_address != @0x0,
                error::invalid_argument(E_UNSUPPORTED_TOKEN)
            );

            let (dest_token_address, dest_pool_data) =
                token_admin_dispatcher::dispatch_lock_or_burn(
                    &state_signer,
                    token_pool_address,
                    fa,
                    sender,
                    dest_chain_selector,
                    token_receiver
                );

            dest_token_addresses.push_back(dest_token_address);
            dest_pool_datas.push_back(dest_pool_data);

            token_transfers.push_back(
                Aptos2AnyTokenTransfer {
                    source_pool_address: token_pool_address,
                    dest_token_address,
                    extra_data: dest_pool_data,
                    amount,
                    dest_exec_data: vector[]
                }
            );
        };

        // TODO: delete this clause after migration completes
        let sequence_number =
            if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
                let dest_chain_config =
                    state.dest_chain_configs.borrow_mut(dest_chain_selector);
                dest_chain_config.sequence_number += 1;
                dest_chain_config.sequence_number
            } else {
                let dest_chain_configs_v2 = borrow_dest_chain_configs_v2_mut();
                let dest_chain_config_v2 =
                    dest_chain_configs_v2.dest_chain_configs.borrow_mut(
                        dest_chain_selector
                    );
                dest_chain_config_v2.sequence_number += 1;
                dest_chain_config_v2.sequence_number
            };

        let (
            fee_value_juels,
            _is_out_of_order_execution,
            converted_extra_args,
            dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                dest_chain_selector,
                fee_token,
                fee_token_amount,
                extra_args,
                token_addresses,
                dest_token_addresses,
                dest_pool_datas
            );

        token_transfers.zip_mut(
            &mut dest_exec_data_per_token,
            |token_amount, dest_exec_data| {
                let token_amount: &mut Aptos2AnyTokenTransfer = token_amount;
                token_amount.dest_exec_data = *dest_exec_data;
            }
        );

        // Aptos CCIP always uses out-of-order execution (nonce = 0).
        let nonce = 0;

        let message = Aptos2AnyRampMessage {
            header: RampMessageHeader {
                // populated on completion
                message_id: vector[],
                source_chain_selector: state.chain_selector,
                dest_chain_selector,
                sequence_number,
                nonce
            },
            sender,
            data,
            receiver,
            extra_args: converted_extra_args,
            fee_token,
            fee_token_amount,
            fee_value_juels,
            token_amounts: token_transfers
        };
        let metadata_hash =
            calculate_metadata_hash_inlined(state.chain_selector, dest_chain_selector);
        let message_id = calculate_message_hash_inlined(&message, metadata_hash);
        message.header.message_id = message_id;

        event::emit_event(
            &mut state.ccip_message_sent_events,
            CCIPMessageSent { dest_chain_selector, sequence_number, message }
        );

        message_id
    }

    public entry fun set_dynamic_config(
        caller: &signer, fee_aggregator: address, allowlist_admin: address
    ) acquires OnRampState {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);
        set_dynamic_config_internal(state, fee_aggregator, allowlist_admin)
    }

    public entry fun apply_dest_chain_config_updates_v2(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_router_state_addresses: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) acquires OnRampState, DestChainConfigsV2 {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        apply_dest_chain_config_updates_v2_internal(
            state,
            borrow_dest_chain_configs_v2_mut(),
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_router_state_addresses,
            dest_chain_allowlist_enabled
        )
    }

    public entry fun apply_dest_chain_config_updates(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) acquires OnRampState, DestChainConfigsV2 {
        // Route to V2 when available, V1 for legacy deployments
        if (exists<DestChainConfigsV2>(get_state_address_internal())) {
            // Use V2 function with routers for both module and state addresses
            apply_dest_chain_config_updates_v2(
                caller,
                dest_chain_selectors,
                dest_chain_routers,
                dest_chain_routers, // use same addresses for router_state_address
                dest_chain_allowlist_enabled
            );
        } else {
            // Original V1 logic for legacy deployments
            let state = borrow_state_mut();
            ownable::assert_only_owner(
                signer::address_of(caller), &state.ownable_state
            );

            apply_dest_chain_config_updates_internal(
                state,
                dest_chain_selectors,
                dest_chain_routers,
                dest_chain_allowlist_enabled
            );
        }
    }

    #[view]
    public fun get_dest_chain_config_v2(
        dest_chain_selector: u64
    ): (u64, bool, address, address) acquires DestChainConfigsV2 {
        let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
        assert!(
            dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );

        let dest_chain_config_v2 =
            dest_chain_configs_v2.dest_chain_configs.borrow(dest_chain_selector);
        (
            dest_chain_config_v2.sequence_number,
            dest_chain_config_v2.allowlist_enabled,
            dest_chain_config_v2.router,
            dest_chain_config_v2.router_state_address
        )
    }

    #[view]
    public fun get_dest_chain_config(
        dest_chain_selector: u64
    ): (u64, bool, address) acquires OnRampState, DestChainConfigsV2 {
        // If V2 exists, read from V2 but return only V1-compatible fields
        if (exists<DestChainConfigsV2>(get_state_address_internal())) {
            let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
            assert!(
                dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let dest_chain_config_v2 =
                dest_chain_configs_v2.dest_chain_configs.borrow(dest_chain_selector);
            (
                dest_chain_config_v2.sequence_number,
                dest_chain_config_v2.allowlist_enabled,
                dest_chain_config_v2.router
            )
        } else {
            let state = borrow_state();
            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);
            (
                dest_chain_config.sequence_number,
                dest_chain_config.allowlist_enabled,
                dest_chain_config.router
            )
        }
    }

    #[view]
    public fun get_allowed_senders_list(
        dest_chain_selector: u64
    ): (bool, vector<address>) acquires OnRampState, DestChainConfigsV2 {
        // TODO: delete this clause after migration completes
        if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
            let state = borrow_state();
            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);

            (dest_chain_config.allowlist_enabled, dest_chain_config.allowed_senders)
        } else {
            let dest_chain_configs_v2 = borrow_dest_chain_configs_v2();
            assert!(
                dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let dest_chain_config_v2 =
                dest_chain_configs_v2.dest_chain_configs.borrow(dest_chain_selector);
            (
                dest_chain_config_v2.allowlist_enabled,
                dest_chain_config_v2.allowed_senders
            )
        }
    }

    public entry fun apply_allowlist_updates(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        dest_chain_allowlist_enabled: vector<bool>,
        dest_chain_add_allowed_senders: vector<vector<address>>,
        dest_chain_remove_allowed_senders: vector<vector<address>>
    ) acquires OnRampState, DestChainConfigsV2 {
        let state = borrow_state_mut();
        assert!(
            signer::address_of(caller) == ownable::owner(&state.ownable_state)
                || signer::address_of(caller) == state.allowlist_admin,
            error::permission_denied(E_ONLY_CALLABLE_BY_OWNER_OR_ALLOWLIST_ADMIN)
        );

        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_allowlist_enabled.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );
        assert!(
            dest_chains_len == dest_chain_add_allowed_senders.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );
        assert!(
            dest_chains_len == dest_chain_remove_allowed_senders.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );

        for (i in 0..dest_chains_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            // TODO: delete this clause after migration completes
            if (!exists<DestChainConfigsV2>(get_state_address_internal())) {
                assert!(
                    state.dest_chain_configs.contains(dest_chain_selector),
                    error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
                );

                let allowlist_enabled = dest_chain_allowlist_enabled[i];
                let add_allowed_senders = dest_chain_add_allowed_senders[i];
                let remove_allowed_senders = dest_chain_remove_allowed_senders[i];

                let dest_chain_config =
                    state.dest_chain_configs.borrow_mut(dest_chain_selector);
                dest_chain_config.allowlist_enabled = allowlist_enabled;

                if (add_allowed_senders.length() > 0) {
                    assert!(
                        allowlist_enabled,
                        error::invalid_argument(E_INVALID_ALLOWLIST_REQUEST)
                    );
                    add_allowed_senders.for_each_ref(
                        |sender_address| {
                            let sender_address: address = *sender_address;
                            assert!(
                                sender_address != @0x0,
                                error::invalid_argument(E_INVALID_ALLOWLIST_ADDRESS)
                            );

                            let (found, _) =
                                dest_chain_config.allowed_senders.index_of(
                                    &sender_address
                                );
                            if (!found) {
                                dest_chain_config.allowed_senders.push_back(
                                    sender_address
                                );
                            };
                        }
                    );

                    event::emit_event(
                        &mut state.allowlist_senders_added_events,
                        AllowlistSendersAdded {
                            dest_chain_selector,
                            senders: add_allowed_senders
                        }
                    );
                };

                if (remove_allowed_senders.length() > 0) {
                    remove_allowed_senders.for_each_ref(
                        |sender_address| {
                            let (found, i) =
                                dest_chain_config.allowed_senders.index_of(sender_address);
                            if (found) {
                                dest_chain_config.allowed_senders.swap_remove(i);
                            }
                        }
                    );

                    event::emit_event(
                        &mut state.allowlist_senders_removed_events,
                        AllowlistSendersRemoved {
                            dest_chain_selector,
                            senders: remove_allowed_senders
                        }
                    );
                };
            } else {
                let dest_chain_configs_v2 = borrow_dest_chain_configs_v2_mut();
                assert!(
                    dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector),
                    error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
                );

                let allowlist_enabled = dest_chain_allowlist_enabled[i];
                let add_allowed_senders = dest_chain_add_allowed_senders[i];
                let remove_allowed_senders = dest_chain_remove_allowed_senders[i];

                let dest_chain_config_v2 =
                    dest_chain_configs_v2.dest_chain_configs.borrow_mut(
                        dest_chain_selector
                    );
                dest_chain_config_v2.allowlist_enabled = allowlist_enabled;

                if (add_allowed_senders.length() > 0) {
                    assert!(
                        allowlist_enabled,
                        error::invalid_argument(E_INVALID_ALLOWLIST_REQUEST)
                    );
                    add_allowed_senders.for_each_ref(
                        |sender_address| {
                            let sender_address: address = *sender_address;
                            assert!(
                                sender_address != @0x0,
                                error::invalid_argument(E_INVALID_ALLOWLIST_ADDRESS)
                            );

                            let (found, _) =
                                dest_chain_config_v2.allowed_senders.index_of(
                                    &sender_address
                                );
                            if (!found) {
                                dest_chain_config_v2.allowed_senders.push_back(
                                    sender_address
                                );
                            };
                        }
                    );

                    event::emit_event(
                        &mut state.allowlist_senders_added_events,
                        AllowlistSendersAdded {
                            dest_chain_selector,
                            senders: add_allowed_senders
                        }
                    );
                };

                if (remove_allowed_senders.length() > 0) {
                    remove_allowed_senders.for_each_ref(
                        |sender_address| {
                            let (found, i) =
                                dest_chain_config_v2.allowed_senders.index_of(
                                    sender_address
                                );
                            if (found) {
                                dest_chain_config_v2.allowed_senders.swap_remove(i);
                            }
                        }
                    );

                    event::emit_event(
                        &mut state.allowlist_senders_removed_events,
                        AllowlistSendersRemoved {
                            dest_chain_selector,
                            senders: remove_allowed_senders
                        }
                    );
                };
            }
        };
    }

    #[view]
    public fun get_outbound_nonce(
        dest_chain_selector: u64, sender: address
    ): u64 {
        nonce_manager::get_outbound_nonce(dest_chain_selector, sender)
    }

    #[view]
    public fun get_static_config(): StaticConfig acquires OnRampState {
        let state = borrow_state();
        StaticConfig { chain_selector: state.chain_selector }
    }

    #[view]
    public fun get_dynamic_config(): DynamicConfig acquires OnRampState {
        let state = borrow_state();
        DynamicConfig {
            fee_aggregator: state.fee_aggregator,
            allowlist_admin: state.allowlist_admin
        }
    }

    #[view]
    public fun dest_chain_configs_v2_exists(): bool {
        exists<DestChainConfigsV2>(get_state_address_internal())
    }

    public entry fun withdraw_fee_tokens(fee_tokens: vector<address>) acquires OnRampState {
        let state = borrow_state_mut();

        assert!(
            state.fee_aggregator != @0x0,
            error::invalid_state(E_FEE_AGGREGATOR_NOT_SET)
        );

        let state_address = get_state_address_internal();
        let state_signer =
            &account::create_signer_with_capability(&state.state_signer_cap);

        for (i in 0..fee_tokens.length()) {
            let fee_token = fee_tokens[i];

            assert!(
                object::object_exists<Metadata>(fee_token),
                error::invalid_argument(E_INVALID_FEE_TOKEN)
            );

            let fee_token_metadata = object::address_to_object<Metadata>(fee_token);

            let balance =
                primary_fungible_store::balance(state_address, fee_token_metadata);
            if (balance == 0) {
                continue;
            };

            primary_fungible_store::transfer(
                state_signer,
                fee_token_metadata,
                state.fee_aggregator,
                balance
            );

            event::emit_event(
                &mut state.fee_token_withdrawn_events,
                FeeTokenWithdrawn {
                    fee_aggregator: state.fee_aggregator,
                    fee_token,
                    amount: balance
                }
            );
        };
    }

    inline fun set_dynamic_config_internal(
        state: &mut OnRampState, fee_aggregator: address, allowlist_admin: address
    ) {
        address::assert_non_zero_address(fee_aggregator);

        state.fee_aggregator = fee_aggregator;
        state.allowlist_admin = allowlist_admin;

        let static_config = StaticConfig { chain_selector: state.chain_selector };

        let dynamic_config = DynamicConfig { fee_aggregator, allowlist_admin };

        event::emit_event(
            &mut state.config_set_events,
            ConfigSet { static_config, dynamic_config }
        );
    }

    inline fun calculate_metadata_hash_inlined(
        source_chain_selector: u64, dest_chain_selector: u64
    ): vector<u8> {
        let packed = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut packed, aptos_hash::keccak256(b"Aptos2AnyMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_address(&mut packed, @ccip_onramp);
        aptos_hash::keccak256(packed)
    }

    #[view]
    public fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64
    ): vector<u8> {
        calculate_metadata_hash_inlined(source_chain_selector, dest_chain_selector)
    }

    #[view]
    public fun calculate_message_hash(
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64,
        sender: address,
        receiver: vector<u8>,
        data: vector<u8>,
        fee_token: address,
        fee_token_amount: u64,
        source_pool_addresses: vector<address>,
        dest_token_addresses: vector<vector<u8>>,
        extra_datas: vector<vector<u8>>,
        amounts: vector<u64>,
        dest_exec_datas: vector<vector<u8>>,
        extra_args: vector<u8>
    ): vector<u8> {
        let source_pool_addresses_len = source_pool_addresses.length();
        assert!(
            source_pool_addresses_len == dest_token_addresses.length()
                && source_pool_addresses_len == extra_datas.length()
                && source_pool_addresses_len == amounts.length()
                && source_pool_addresses_len == dest_exec_datas.length(),
            error::invalid_argument(E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS)
        );

        let metadata_hash =
            calculate_metadata_hash_inlined(source_chain_selector, dest_chain_selector);

        let token_amounts = vector[];
        for (i in 0..source_pool_addresses_len) {
            token_amounts.push_back(
                Aptos2AnyTokenTransfer {
                    source_pool_address: source_pool_addresses[i],
                    dest_token_address: dest_token_addresses[i],
                    extra_data: extra_datas[i],
                    amount: amounts[i],
                    dest_exec_data: dest_exec_datas[i]
                }
            );
        };

        let message = Aptos2AnyRampMessage {
            header: RampMessageHeader {
                message_id,
                source_chain_selector,
                dest_chain_selector,
                sequence_number,
                nonce
            },
            sender,
            data,
            receiver,
            extra_args,
            fee_token,
            fee_token_amount,
            fee_value_juels: 0, // Not used in hashing
            token_amounts
        };

        calculate_message_hash_inlined(&message, metadata_hash)
    }

    inline fun calculate_message_hash_inlined(
        message: &Aptos2AnyRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let outer_hash = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, merkle_proof::leaf_domain_separator()
        );
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, metadata_hash);

        let inner_hash = vector[];
        eth_abi::encode_address(&mut inner_hash, message.sender);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_address(&mut inner_hash, message.fee_token);
        eth_abi::encode_u64(&mut inner_hash, message.fee_token_amount);
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(inner_hash)
        );

        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.receiver)
        );
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.data)
        );

        let token_hash = vector[];
        eth_abi::encode_u256(&mut token_hash, message.token_amounts.length() as u256);
        message.token_amounts.for_each_ref(
            |token_transfer| {
                let token_transfer: &Aptos2AnyTokenTransfer = token_transfer;
                eth_abi::encode_address(
                    &mut token_hash, token_transfer.source_pool_address
                );
                eth_abi::encode_bytes(
                    &mut token_hash, token_transfer.dest_token_address
                );
                eth_abi::encode_bytes(&mut token_hash, token_transfer.extra_data);
                eth_abi::encode_u64(&mut token_hash, token_transfer.amount);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.dest_exec_data);
            }
        );
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(token_hash)
        );

        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.extra_args)
        );

        aptos_hash::keccak256(outer_hash)
    }

    inline fun apply_dest_chain_config_updates_v2_internal(
        state: &mut OnRampState,
        dest_chain_configs_v2: &mut DestChainConfigsV2,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_router_state_addresses: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_routers.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );
        assert!(
            dest_chains_len == dest_chain_allowlist_enabled.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );
        assert!(
            dest_chains_len == dest_chain_router_state_addresses.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );

        for (i in 0..dest_chains_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            assert!(
                dest_chain_selector != 0,
                error::invalid_argument(E_INVALID_DEST_CHAIN_SELECTOR)
            );

            if (!dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector)) {
                dest_chain_configs_v2.dest_chain_configs.add(
                    dest_chain_selector,
                    DestChainConfigV2 {
                        sequence_number: 0,
                        router: @0x0,
                        router_state_address: @0x0,
                        allowlist_enabled: false,
                        allowed_senders: vector[]
                    }
                );
            };

            let dest_chain_config =
                dest_chain_configs_v2.dest_chain_configs.borrow_mut(dest_chain_selector);

            dest_chain_config.router = dest_chain_routers[i];
            dest_chain_config.router_state_address = dest_chain_router_state_addresses[i];
            dest_chain_config.allowlist_enabled = dest_chain_allowlist_enabled[i];

            event::emit_event(
                &mut state.dest_chain_config_set_events,
                DestChainConfigSet {
                    dest_chain_selector,
                    sequence_number: dest_chain_config.sequence_number,
                    allowlist_enabled: dest_chain_config.allowlist_enabled,
                    router: dest_chain_config.router
                }
            );

            event::emit_event(
                &mut dest_chain_configs_v2.dest_chain_config_v2_set_events,
                DestChainConfigSetV2 {
                    dest_chain_selector,
                    sequence_number: dest_chain_config.sequence_number,
                    router: dest_chain_config.router,
                    router_state_address: dest_chain_config.router_state_address,
                    allowlist_enabled: dest_chain_config.allowlist_enabled
                }
            );
        };
    }

    inline fun apply_dest_chain_config_updates_internal(
        state: &mut OnRampState,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_routers.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );
        assert!(
            dest_chains_len == dest_chain_allowlist_enabled.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );

        for (i in 0..dest_chains_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            assert!(
                dest_chain_selector != 0,
                error::invalid_argument(E_INVALID_DEST_CHAIN_SELECTOR)
            );

            let router = dest_chain_routers[i];
            let allowlist_enabled = dest_chain_allowlist_enabled[i];

            if (!state.dest_chain_configs.contains(dest_chain_selector)) {
                state.dest_chain_configs.add(
                    dest_chain_selector,
                    DestChainConfig {
                        sequence_number: 0,
                        router: @0x0,
                        allowlist_enabled: false,
                        allowed_senders: vector[]
                    }
                );
            };

            let dest_chain_config =
                state.dest_chain_configs.borrow_mut(dest_chain_selector);

            dest_chain_config.router = router;
            dest_chain_config.allowlist_enabled = allowlist_enabled;

            event::emit_event(
                &mut state.dest_chain_config_set_events,
                DestChainConfigSet {
                    dest_chain_selector,
                    router,
                    sequence_number: dest_chain_config.sequence_number,
                    allowlist_enabled: dest_chain_config.allowlist_enabled
                }
            );
        };
    }

    inline fun get_state_address_internal(): address {
        account::create_resource_address(&@ccip_onramp, STATE_SEED)
    }

    inline fun borrow_state(): &OnRampState {
        borrow_global<OnRampState>(get_state_address_internal())
    }

    inline fun borrow_state_mut(): &mut OnRampState {
        borrow_global_mut<OnRampState>(get_state_address_internal())
    }

    inline fun borrow_dest_chain_configs_v2(): &DestChainConfigsV2 {
        assert!(
            exists<DestChainConfigsV2>(get_state_address_internal()),
            error::invalid_state(E_DEST_CHAIN_CONFIGS_V2_NOT_INITIALIZED)
        );
        borrow_global<DestChainConfigsV2>(get_state_address_internal())
    }

    inline fun borrow_dest_chain_configs_v2_mut(): &mut DestChainConfigsV2 {
        assert!(
            exists<DestChainConfigsV2>(get_state_address_internal()),
            error::invalid_state(E_DEST_CHAIN_CONFIGS_V2_NOT_INITIALIZED)
        );
        borrow_global_mut<DestChainConfigsV2>(get_state_address_internal())
    }

    //
    // ccip::ownable functions
    //
    #[view]
    public fun owner(): address acquires OnRampState {
        ownable::owner(&borrow_state().ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires OnRampState {
        ownable::has_pending_transfer(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires OnRampState {
        ownable::pending_transfer_from(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires OnRampState {
        ownable::pending_transfer_to(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires OnRampState {
        ownable::pending_transfer_accepted(&borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires OnRampState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires OnRampState {
        let state = borrow_state_mut();
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires OnRampState {
        let state = borrow_state_mut();
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: Object<T>
    ): option::Option<u128> acquires OnRampDeployment, OnRampState, DestChainConfigsV2 {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip_onramp, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let fee_aggregator = bcs_stream::deserialize_address(&mut stream);
            let allowlist_admin = bcs_stream::deserialize_address(&mut stream);
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_routers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            initialize(
                &caller,
                chain_selector,
                fee_aggregator,
                allowlist_admin,
                dest_chain_selectors,
                dest_chain_routers,
                dest_chain_allowlist_enabled
            );
        } else if (function_bytes == b"set_dynamic_config") {
            let fee_aggregator = bcs_stream::deserialize_address(&mut stream);
            let allowlist_admin = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_dynamic_config(&caller, fee_aggregator, allowlist_admin);
        } else if (function_bytes == b"apply_dest_chain_config_updates_v2") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_routers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let dest_chain_router_state_addresses =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_dest_chain_config_updates_v2(
                &caller,
                dest_chain_selectors,
                dest_chain_routers,
                dest_chain_router_state_addresses,
                dest_chain_allowlist_enabled
            );
        } else if (function_bytes == b"apply_dest_chain_config_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_routers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_dest_chain_config_updates(
                &caller,
                dest_chain_selectors,
                dest_chain_routers,
                dest_chain_allowlist_enabled
            );
        } else if (function_bytes == b"apply_allowlist_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_add_allowed_senders =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector(
                        stream, |stream| bcs_stream::deserialize_address(stream)
                    )
                );
            let dest_chain_remove_allowed_senders =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector(
                        stream, |stream| bcs_stream::deserialize_address(stream)
                    )
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_allowlist_updates(
                &caller,
                dest_chain_selectors,
                dest_chain_allowlist_enabled,
                dest_chain_add_allowed_senders,
                dest_chain_remove_allowed_senders
            );
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
        } else if (function_bytes == b"migrate_dest_chain_configs_to_v2") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let router_module_addresses =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            migrate_dest_chain_configs_to_v2(
                &caller, dest_chain_selectors, router_module_addresses
            )
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"onramp"), McmsCallback {}
        );
    }

    public fun dynamic_config_fee_aggregator(config: &DynamicConfig): address {
        config.fee_aggregator
    }

    public fun dynamic_config_allowlist_admin(config: &DynamicConfig): address {
        config.allowlist_admin
    }

    public fun static_config_chain_selector(config: &StaticConfig): u64 {
        config.chain_selector
    }

    // ========================= MIGRATION ==========================
    public entry fun migrate_dest_chain_configs_to_v2(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        router_module_addresses: vector<address>
    ) acquires OnRampState, DestChainConfigsV2 {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        let state_address = get_state_address_internal();

        let state_signer =
            &account::create_signer_with_capability(&state.state_signer_cap);

        if (!exists<DestChainConfigsV2>(state_address)) {
            let dest_chain_configs_v2 = DestChainConfigsV2 {
                dest_chain_configs: smart_table::new(),
                dest_chain_config_v2_set_events: account::new_event_handle(state_signer)
            };
            move_to(state_signer, dest_chain_configs_v2);
        };

        migrate_dest_chain_configs_v2_internal(
            state,
            borrow_dest_chain_configs_v2_mut(),
            dest_chain_selectors,
            router_module_addresses
        );
    }

    inline fun migrate_dest_chain_configs_v2_internal(
        state: &mut OnRampState,
        dest_chain_configs_v2: &mut DestChainConfigsV2,
        dest_chain_selectors: vector<u64>,
        router_module_addresses: vector<address>
    ) {
        assert!(
            dest_chain_selectors.length() == router_module_addresses.length(),
            error::invalid_argument(E_DEST_CHAIN_ARGUMENT_MISMATCH)
        );

        // Migrate V1 configs to V2 for provided parameters
        for (i in 0..dest_chain_selectors.length()) {
            let dest_chain_selector = dest_chain_selectors[i];
            let router_module_address = router_module_addresses[i];

            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
            );

            let DestChainConfig {
                sequence_number,
                allowlist_enabled,
                router: router_state_address,
                allowed_senders
            } = state.dest_chain_configs.remove(dest_chain_selector);

            let dest_chain_config_v2 = DestChainConfigV2 {
                sequence_number,
                allowlist_enabled,
                router: router_module_address,
                router_state_address,
                allowed_senders
            };

            // Only add if it doesn't exist in V2
            if (!dest_chain_configs_v2.dest_chain_configs.contains(dest_chain_selector)) {
                dest_chain_configs_v2.dest_chain_configs.add(
                    dest_chain_selector, dest_chain_config_v2
                );

                event::emit_event(
                    &mut state.dest_chain_config_set_events,
                    DestChainConfigSet {
                        dest_chain_selector,
                        sequence_number,
                        allowlist_enabled,
                        router: router_module_address
                    }
                );
                event::emit_event(
                    &mut dest_chain_configs_v2.dest_chain_config_v2_set_events,
                    DestChainConfigSetV2 {
                        dest_chain_selector,
                        sequence_number,
                        router: router_module_address,
                        router_state_address,
                        allowlist_enabled
                    }
                );
            }
        };
    }

    // ========================== TEST ONLY ==========================
    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun test_register_mcms_entrypoint(publisher: &signer) {
        register_mcms_entrypoint(publisher);
    }

    #[test_only]
    public fun get_dest_chain_config_set_events(): vector<DestChainConfigSet> acquires OnRampState {
        event::emitted_events_by_handle<DestChainConfigSet>(
            &borrow_state().dest_chain_config_set_events
        )
    }

    #[test_only]
    public fun get_dest_chain_config_v2_set_events(): vector<DestChainConfigSetV2> acquires DestChainConfigsV2 {
        event::emitted_events_by_handle<DestChainConfigSetV2>(
            &borrow_dest_chain_configs_v2().dest_chain_config_v2_set_events
        )
    }

    #[test_only]
    public entry fun initialize_v1(
        caller: &signer,
        chain_selector: u64,
        fee_aggregator: address,
        allowlist_admin: address,
        dest_chain_selectors: vector<u64>,
        dest_chain_routers: vector<address>,
        dest_chain_allowlist_enabled: vector<bool>
    ) acquires OnRampDeployment {
        assert!(chain_selector != 0, E_ZERO_CHAIN_SELECTOR);
        assert!(
            exists<OnRampDeployment>(@ccip_onramp),
            error::invalid_state(E_ALREADY_INITIALIZED)
        );

        let OnRampDeployment { state_signer_cap } =
            move_from<OnRampDeployment>(@ccip_onramp);

        let state_signer = &account::create_signer_with_capability(&state_signer_cap);

        let ownable_state = ownable::new(state_signer, @ccip_onramp);

        ownable::assert_only_owner(signer::address_of(caller), &ownable_state);

        let state = OnRampState {
            state_signer_cap,
            ownable_state,
            chain_selector,
            fee_aggregator: @0x0,
            allowlist_admin: @0x0,
            dest_chain_configs: smart_table::new(),
            config_set_events: account::new_event_handle(state_signer),
            dest_chain_config_set_events: account::new_event_handle(state_signer),
            ccip_message_sent_events: account::new_event_handle(state_signer),
            allowlist_senders_added_events: account::new_event_handle(state_signer),
            allowlist_senders_removed_events: account::new_event_handle(state_signer),
            fee_token_withdrawn_events: account::new_event_handle(state_signer)
        };

        set_dynamic_config_internal(&mut state, fee_aggregator, allowlist_admin);

        apply_dest_chain_config_updates_internal(
            &mut state,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        move_to(state_signer, state);
    }
}
