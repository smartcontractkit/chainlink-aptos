module ccip::onramp {
    use std::account;
    use std::aptos_hash;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::dispatchable_fungible_asset;
    use std::fungible_asset::{Self, Metadata, FungibleStore};
    use std::object::{Self, Object};
    use std::option;
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};

    use ccip::auth;
    use ccip::eth_abi;
    use ccip::fee_quoter;
    use ccip::internal;
    use ccip::merkle_proof;
    use ccip::nonce_manager;
    use ccip::rmn_remote;
    use ccip::state_object;
    use ccip::token_admin_dispatcher;
    use ccip::token_admin_registry;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    struct OnRampState has key, store {
        chain_selector: u64,
        allowlist_admin: address,

        // TODO: consider a single smart table of dest chain selector -> all data
        // dest chain selector -> config
        dest_chain_configs: SmartTable<u64, DestChainConfig>,
        config_set_events: EventHandle<ConfigSet>,
        dest_chain_config_set_events: EventHandle<DestChainConfigSet>,
        ccip_message_sent_events: EventHandle<CCIPMessageSent>,
        allowlist_senders_added_events: EventHandle<AllowlistSendersAdded>,
        allowlist_senders_removed_events: EventHandle<AllowlistSendersRemoved>
    }

    struct DestChainConfig has store, drop {
        // on EVM, transfers can be stopped by zeroing the router address,
        // since we don't have a router address here, we add an is_enabled flag.
        // ref: https://github.com/smartcontractkit/chainlink/blob/62a9b78e1c32174ccec11f1ed487edf3b0b4e8fd/contracts/src/v0.8/ccip/onRamp/OnRamp.sol#L181
        is_enabled: bool,
        sequence_number: u64,
        allowlist_enabled: bool,
        // TODO: should we use a Table/SmartTable here?
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
        fee_value_juels: u64,
        token_amounts: vector<Aptos2AnyTokenTransfer>
    }

    struct Aptos2AnyTokenTransfer has store, drop, copy {
        source_pool_address: address,
        dest_token_address: vector<u8>,
        extra_data: vector<u8>,
        amount: u64,
        dest_exec_data: vector<u8>
    }

    struct StaticConfig has store, drop {
        chain_selector: u64
    }

    struct DynamicConfig has store, drop {
        allowlist_admin: address
    }

    #[event]
    struct ConfigSet has store, drop {
        chain_selector: u64,
        allowlist_admin: address
    }

    #[event]
    struct DestChainConfigSet has store, drop {
        dest_chain_selector: u64,
        is_enabled: bool,
        sequence_number: u64,
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

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_DEST_CHAIN_ARGUMENT_MISMATCH: u64 = 2;
    const E_INVALID_DEST_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_DEST_CHAIN_SELECTOR: u64 = 4;
    const E_DEST_CHAIN_NOT_ENABLED: u64 = 5;
    const E_SENDER_NOT_ALLOWED: u64 = 6;
    const E_ONLY_CALLABLE_BY_OWNER_OR_ALLOWLIST_ADMIN: u64 = 7;
    const E_INVALID_ALLOWLIST_REQUEST: u64 = 8;
    const E_INVALID_ALLOWLIST_ADDRESS: u64 = 9;
    const E_UNSUPPORTED_TOKEN: u64 = 10;
    const E_INVALID_FEE_TOKEN: u64 = 11;
    const E_CURSED_BY_RMN: u64 = 12;
    const E_BAD_RMN_SIGNAL: u64 = 13;
    const E_INVALID_TOKEN: u64 = 14;
    const E_INVALID_TOKEN_STORE: u64 = 15;
    const E_UNEXPECTED_WITHDRAW_AMOUNT: u64 = 16;
    const E_UNEXPECTED_FUNGIBLE_ASSET: u64 = 17;
    const E_UNKNOWN_FUNCTION: u64 = 18;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"OnRamp 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"onramp"), McmsCallback {}
            );
        };
    }

    public entry fun initialize(
        caller: &signer,
        chain_selector: u64,
        allowlist_admin: address,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            !exists<OnRampState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let state_object_signer = state_object::object_signer();

        let state = OnRampState {
            chain_selector,
            allowlist_admin: @0x0,
            dest_chain_configs: smart_table::new(),
            config_set_events: account::new_event_handle(&state_object_signer),
            dest_chain_config_set_events: account::new_event_handle(&state_object_signer),
            ccip_message_sent_events: account::new_event_handle(&state_object_signer),
            allowlist_senders_added_events: account::new_event_handle(&state_object_signer),
            allowlist_senders_removed_events: account::new_event_handle(
                &state_object_signer
            )
        };

        set_dynamic_config_internal(&mut state, allowlist_admin);

        apply_dest_chain_config_updates_internal(
            &mut state,
            dest_chain_selectors,
            dest_chain_enabled,
            dest_chain_allowlist_enabled
        );

        move_to(&state_object_signer, state);
    }

    #[view]
    public fun is_chain_supported(dest_chain_selector: u64): bool acquires OnRampState {
        let state = borrow_state();
        state.dest_chain_configs.contains(dest_chain_selector)
    }

    #[view]
    public fun get_expected_next_sequence_number(dest_chain_selector: u64): u64 acquires OnRampState {
        let state = borrow_state();
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);
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
        let message =
            internal::new_aptos2any_message(
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );
        get_fee_internal(dest_chain_selector, &message)
    }

    inline fun get_fee_internal(
        dest_chain_selector: u64, message: &internal::Aptos2AnyMessage
    ): u64 {
        assert!(
            !rmn_remote::is_cursed_u128(dest_chain_selector as u128),
            error::permission_denied(E_CURSED_BY_RMN)
        );
        fee_quoter::get_validated_fee(dest_chain_selector, message)
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
    ): vector<u8> acquires OnRampState {
        auth::assert_is_router(signer::address_of(router));

        assert!(
            !rmn_remote::is_cursed_global(),
            error::permission_denied(E_BAD_RMN_SIGNAL)
        );

        let message =
            internal::new_aptos2any_message(
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );

        let fee_token_amount = get_fee_internal(dest_chain_selector, &message);
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

            primary_fungible_store::deposit(state_object::object_address(), fa);
        };

        let state = borrow_state_mut();
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );

        let dest_chain_config = state.dest_chain_configs.borrow_mut(dest_chain_selector);
        assert!(
            dest_chain_config.is_enabled,
            error::permission_denied(E_DEST_CHAIN_NOT_ENABLED)
        );

        if (dest_chain_config.allowlist_enabled) {
            assert!(
                dest_chain_config.allowed_senders.contains(&signer::address_of(caller)),
                error::permission_denied(E_SENDER_NOT_ALLOWED)
            );
        };

        let sender = signer::address_of(caller);

        let dest_token_addresses = vector[];
        let dest_pool_datas = vector[];

        let tokens_len = token_addresses.length();
        let token_transfers = vector[];
        for (i in 0..tokens_len) {
            let token = token_addresses[i];
            let amount = token_amounts[i];
            let token_store = token_store_addresses[i];

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
                    token_pool_address,
                    fa,
                    sender,
                    dest_chain_selector,
                    receiver
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

        dest_chain_config.sequence_number += 1;

        let sequence_number = dest_chain_config.sequence_number;

        let (
            fee_value_juels,
            is_out_of_order_execution,
            converted_extra_args,
            dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                dest_chain_selector,
                fee_token,
                fee_token_amount,
                extra_args,
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

        let nonce =
            if (is_out_of_order_execution) { 0 }
            else {
                nonce_manager::get_incremented_outbound_nonce(
                    dest_chain_selector, sender
                )
            };

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
            calculate_metadata_hash(state.chain_selector, dest_chain_selector);
        let message_id = calculate_message_hash(&message, metadata_hash);
        message.header.message_id = message_id;

        event::emit(CCIPMessageSent { dest_chain_selector, sequence_number, message });
        event::emit_event(
            &mut state.ccip_message_sent_events,
            CCIPMessageSent { dest_chain_selector, sequence_number, message }
        );

        message_id
    }

    public entry fun set_dynamic_config(
        caller: &signer, allowlist_admin: address
    ) acquires OnRampState {
        auth::assert_only_owner(signer::address_of(caller));

        set_dynamic_config_internal(borrow_state_mut(), allowlist_admin)
    }

    public entry fun apply_dest_chain_config_updates(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>
    ) acquires OnRampState {
        auth::assert_only_owner(signer::address_of(caller));

        apply_dest_chain_config_updates_internal(
            borrow_state_mut(),
            dest_chain_selectors,
            dest_chain_enabled,
            dest_chain_allowlist_enabled
        )
    }

    #[view]
    public fun get_dest_chain_config(dest_chain_selector: u64): (bool, u64, bool) acquires OnRampState {
        let state = borrow_state();

        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );

        let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);

        (
            dest_chain_config.is_enabled,
            dest_chain_config.sequence_number,
            dest_chain_config.allowlist_enabled
        )
    }

    #[view]
    public fun get_allowed_senders_list(
        dest_chain_selector: u64
    ): (bool, vector<address>) acquires OnRampState {
        let state = borrow_state();

        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );

        let dest_chain_config = state.dest_chain_configs.borrow(dest_chain_selector);

        (dest_chain_config.allowlist_enabled, dest_chain_config.allowed_senders)
    }

    public entry fun apply_allowlist_updates(
        caller: &signer,
        dest_chain_selectors: vector<u64>,
        dest_chain_allowlist_enabled: vector<bool>,
        dest_chain_add_allowed_senders: vector<vector<address>>,
        dest_chain_remove_allowed_senders: vector<vector<address>>
    ) acquires OnRampState {
        let state = borrow_state_mut();
        assert!(
            signer::address_of(caller) == auth::owner()
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
                add_allowed_senders.for_each_ref(|sender_address| {
                    let sender_address: address = *sender_address;
                    assert!(
                        sender_address != @0x0,
                        error::invalid_argument(E_INVALID_ALLOWLIST_ADDRESS)
                    );

                    let (found, _) =
                        dest_chain_config.allowed_senders.index_of(&sender_address);
                    if (!found) {
                        dest_chain_config.allowed_senders.push_back(sender_address);
                    };
                });

                event::emit(
                    AllowlistSendersAdded {
                        dest_chain_selector,
                        senders: add_allowed_senders
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
                remove_allowed_senders.for_each_ref(|sender_address| {
                    let (found, i) =
                        dest_chain_config.allowed_senders.index_of(sender_address);
                    if (found) {
                        dest_chain_config.allowed_senders.swap_remove(i);
                    }
                });

                event::emit(
                    AllowlistSendersRemoved {
                        dest_chain_selector,
                        senders: remove_allowed_senders
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
        DynamicConfig { allowlist_admin: state.allowlist_admin }
    }

    inline fun set_dynamic_config_internal(
        state: &mut OnRampState, allowlist_admin: address
    ) {
        state.allowlist_admin = allowlist_admin;

        event::emit(ConfigSet { chain_selector: state.chain_selector, allowlist_admin });
        event::emit_event(
            &mut state.config_set_events,
            ConfigSet { chain_selector: state.chain_selector, allowlist_admin }
        );
    }

    inline fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64
    ): vector<u8> {
        let packed = vector[];
        eth_abi::encode_bytes32(
            &mut packed, aptos_hash::keccak256(b"Aptos2AnyMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_address(&mut packed, @ccip);
        aptos_hash::keccak256(packed)
    }

    inline fun calculate_message_hash(
        message: &Aptos2AnyRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let outer_hash = vector[];
        eth_abi::encode_bytes32(&mut outer_hash, merkle_proof::leaf_domain_separator());
        eth_abi::encode_bytes32(&mut outer_hash, metadata_hash);

        let inner_hash = vector[];
        eth_abi::encode_address(&mut inner_hash, message.sender);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_address(&mut inner_hash, message.fee_token);
        eth_abi::encode_u64(&mut inner_hash, message.fee_token_amount);
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(inner_hash));

        eth_abi::encode_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.receiver)
        );
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(message.data));

        let token_hash = vector[];
        eth_abi::encode_u256(&mut token_hash, message.token_amounts.length() as u256);
        message.token_amounts.for_each_ref(
            |token_transfer| {
                let token_transfer: &Aptos2AnyTokenTransfer = token_transfer;
                eth_abi::encode_address(
                    &mut token_hash, token_transfer.source_pool_address
                );
                eth_abi::encode_bytes(&mut token_hash, token_transfer.dest_token_address);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.extra_data);
                eth_abi::encode_u64(&mut token_hash, token_transfer.amount);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.dest_exec_data);
            }
        );
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(token_hash));

        eth_abi::encode_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.extra_args)
        );

        aptos_hash::keccak256(outer_hash)
    }

    inline fun apply_dest_chain_config_updates_internal(
        state: &mut OnRampState,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_enabled.length(),
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

            let is_enabled = dest_chain_enabled[i];
            let allowlist_enabled = dest_chain_allowlist_enabled[i];

            if (!state.dest_chain_configs.contains(dest_chain_selector)) {
                state.dest_chain_configs.add(
                    dest_chain_selector,
                    DestChainConfig {
                        is_enabled: false,
                        sequence_number: 0,
                        allowlist_enabled: false,
                        allowed_senders: vector[]
                    }
                );
            };

            let dest_chain_config =
                state.dest_chain_configs.borrow_mut(dest_chain_selector);

            dest_chain_config.is_enabled = is_enabled;
            dest_chain_config.allowlist_enabled = allowlist_enabled;

            event::emit(
                DestChainConfigSet {
                    dest_chain_selector,
                    is_enabled,
                    sequence_number: dest_chain_config.sequence_number,
                    allowlist_enabled: dest_chain_config.allowlist_enabled
                }
            );
            event::emit_event(
                &mut state.dest_chain_config_set_events,
                DestChainConfigSet {
                    dest_chain_selector,
                    is_enabled,
                    sequence_number: dest_chain_config.sequence_number,
                    allowlist_enabled: dest_chain_config.allowlist_enabled
                }
            );
        };
    }

    inline fun borrow_state(): &OnRampState {
        borrow_global<OnRampState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut OnRampState {
        borrow_global_mut<OnRampState>(state_object::object_address())
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: Object<T>
    ): option::Option<u128> acquires OnRampState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let allowlist_admin = bcs_stream::deserialize_address(&mut stream);
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            initialize(
                &caller,
                chain_selector,
                allowlist_admin,
                dest_chain_selectors,
                dest_chain_enabled,
                dest_chain_allowlist_enabled
            );
        } else if (function_bytes == b"set_dynamic_config") {
            let allowlist_admin = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_dynamic_config(&caller, allowlist_admin);
        } else if (function_bytes == b"apply_dest_chain_config_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_dest_chain_config_updates(
                &caller,
                dest_chain_selectors,
                dest_chain_enabled,
                dest_chain_allowlist_enabled
            );
        } else if (function_bytes == b"apply_allowlist_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_add_allowed_senders =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector(
                        stream,
                        |stream| bcs_stream::deserialize_address(stream)
                    )
                );
            let dest_chain_remove_allowed_senders =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector(
                        stream,
                        |stream| bcs_stream::deserialize_address(stream)
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
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }
}
