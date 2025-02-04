module ccip::offramp {
    use std::account;
    use std::aptos_hash;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::option::Option;
    use std::primary_fungible_store;
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::timestamp;
    use std::vector;

    use ccip::client;
    use ccip::eth_abi;
    use ccip::fee_quoter;
    use ccip::merkle_multi_proof;
    use ccip::ownable;
    use ccip::ocr3_base;
    use ccip::receiver_dispatcher;
    use ccip::rmn_remote;
    use ccip::state_object;
    use ccip::token_admin_dispatcher;
    use ccip::token_admin_registry;

    const EXECUTION_STATE_UNTOUCHED: u8 = 1;
    const EXECUTION_STATE_SUCCESS: u8 = 2;

    const ZERO_MERKLE_ROOT: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ];

    struct OffRampState has key, store {
        ownable_state: ownable::OwnableState,
        ocr3_base_state: ocr3_base::OCR3BaseState,

        // static config
        chain_selector: u64,

        // dynamic config
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool,

        // TODO: consider a single smart table of source chain selector -> all data,
        // ie config + execution state + roots + inbound nonces.
        // source chain selector -> config
        source_chain_configs: SmartTable<u64, SourceChainConfig>,

        // source chain selector -> seq num -> execution state
        execution_states: SmartTable<u64, SmartTable<u64, u8>>,

        // source chain selector -> merkle root -> timestamp,
        roots: SmartTable<u64, SmartTable<vector<u8>, u64>>,

        // source chain selector -> sender -> nonce
        inbound_nonces: SmartTable<u64, SmartTable<vector<u8>, u64>>,
        latest_price_sequence_number: u64,
        static_config_set_events: EventHandle<StaticConfigSet>,
        dynamic_config_set_events: EventHandle<DynamicConfigSet>,
        source_chain_config_set_events: EventHandle<SourceChainConfigSet>,
        skipped_already_executed_events: EventHandle<SkippedAlreadyExecuted>,
        already_attempted_events: EventHandle<AlreadyAttempted>,
        execution_state_changed_events: EventHandle<ExecutionStateChanged>,
        commit_report_accepted_events: EventHandle<CommitReportAccepted>,
        skipped_incorrect_nonce_events: EventHandle<SkippedIncorrectNonce>,
        skipped_report_execution_events: EventHandle<SkippedReportExecution>
    }

    struct SourceChainConfig has store, drop {
        is_enabled: bool,
        min_sequence_number: u64
    }

    // report structs
    struct RampMessageHeader has drop {
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64
    }

    struct Any2AptosRampMessage has drop {
        header: RampMessageHeader,
        sender: vector<u8>,
        data: vector<u8>,
        receiver: address,
        gas_limit: u256,
        token_amounts: vector<Any2AptosTokenTransfer>
    }

    struct Any2AptosTokenTransfer has drop {
        source_pool_address: vector<u8>,
        dest_token_address: address,
        dest_gas_amount: u32,
        extra_data: vector<u8>,

        // This is the amount to transfer, as set on the source chain.
        amount: u256
    }

    struct ExecutionReport has drop {
        source_chain_selector: u64,
        messages: vector<Any2AptosRampMessage>,
        offchain_token_data: vector<vector<vector<u8>>>,
        proofs: vector<vector<u8>>,
        proof_flag_bits: u256
    }

    struct CommitReport has store, drop, copy {
        price_updates: PriceUpdates,
        merkle_roots: vector<MerkleRoot>,
        rmn_signatures: vector<vector<u8>>,

        // TODO: this was added so that the hashed/verified report contains the target address,
        // since we don't have onramp address fields. check if we need this.
        offramp_address: address
    }

    struct PriceUpdates has store, drop, copy {
        token_price_updates: vector<TokenPriceUpdate>,
        gas_price_updates: vector<GasPriceUpdate>
    }

    struct TokenPriceUpdate has store, drop, copy {
        // TODO: this is address on EVM, double check that this should be a local address.
        source_token: address,
        usd_per_token: u256
    }

    struct GasPriceUpdate has store, drop, copy {
        dest_chain_selector: u64,
        usd_per_unit_gas: u256
    }

    struct MerkleRoot has store, drop, copy {
        source_chain_selector: u64,
        min_sequence_number: u64,
        max_sequence_number: u64,
        merkle_root: vector<u8>
    }

    struct StaticConfig has store, drop {
        chain_selector: u64
    }

    struct DynamicConfig has store, drop {
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool
    }

    #[event]
    struct StaticConfigSet has store, drop {
        chain_selector: u64
    }

    #[event]
    struct DynamicConfigSet has store, drop {
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool
    }

    #[event]
    struct SourceChainConfigSet has store, drop {
        is_enabled: bool,
        min_sequence_number: u64
    }

    #[event]
    struct SkippedAlreadyExecuted has store, drop {
        source_chain_selector: u64,
        sequence_number: u64
    }

    #[event]
    struct AlreadyAttempted has store, drop {
        source_chain_selector: u64,
        sequence_number: u64
    }

    #[event]
    struct ExecutionStateChanged has store, drop {
        source_chain_selector: u64,
        sequence_number: u64,
        message_id: vector<u8>,
        message_hash: vector<u8>,
        return_data: Option<u128>
    }

    #[event]
    struct CommitReportAccepted has store, drop {
        commit_report: CommitReport
    }

    #[event]
    struct SkippedIncorrectNonce has store, drop {
        source_chain_selector: u64,
        nonce: u64,
        sender: vector<u8>
    }

    #[event]
    struct SkippedReportExecution has store, drop {
        source_chain_selector: u64
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_SOURCE_CHAIN_SELECTORS_MISMATCH: u64 = 2;
    const E_ZERO_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_SOURCE_CHAIN_SELECTOR: u64 = 4;
    const E_TOKEN_TRANSFER_DATA_MISMATCH: u64 = 5;
    const E_SOURCE_CHAIN_SELECTOR_MISMATCH: u64 = 6;
    const E_DEST_CHAIN_SELECTOR_MISMATCH: u64 = 7;
    const E_TOKEN_DATA_MISMATCH: u64 = 8;
    const E_ROOT_NOT_COMMITTED: u64 = 9;
    const E_MANUAL_EXECUTION_NOT_YET_ENABLED: u64 = 10;
    const E_SOURCE_CHAIN_NOT_ENABLED: u64 = 11;
    const E_INVALID_OFFRAMP_ADDRESS: u64 = 12;
    const E_INVALID_INTERVAL: u64 = 13;
    const E_INVALID_ROOT: u64 = 14;
    const E_ROOT_ALREADY_COMMITTED: u64 = 15;
    const E_STALE_COMMIT_REPORT: u64 = 16;
    const E_UNSUPPORTED_TOKEN: u64 = 17;
    const E_INVALID_REMOTE_CHAIN_DECIMALS: u64 = 18;
    const E_INVALID_ENCODED_AMOUNT: u64 = 19;
    const E_EMPTY_BATCH: u64 = 20;
    const E_EMPTY_REPORT: u64 = 21;
    const E_UNEXPECTED_TOKEN_DATA: u64 = 22;
    const E_CURSED_BY_RMN: u64 = 23;
    const E_BAD_RMN_SIGNAL: u64 = 24;

    public entry fun initialize(
        caller: &signer,
        chain_selector: u64,
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool,

        // pairs of (source chain selector, is enabled)
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) {
        state_object::assert_can_initialize(caller);

        assert!(
            !exists<OffRampState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );
        assert!(
            vector::length(&source_chain_selectors)
                == vector::length(&source_chain_is_enabled),
            error::invalid_argument(E_SOURCE_CHAIN_SELECTORS_MISMATCH)
        );

        let state_object_signer = state_object::object_signer();

        let state = OffRampState {
            ownable_state: ownable::new(
                &state_object_signer, signer::address_of(caller), @0x0
            ),
            ocr3_base_state: ocr3_base::new(&state_object_signer),
            chain_selector,
            permissionless_execution_threshold_secs: 0,
            is_rmn_verification_disabled: false,
            source_chain_configs: smart_table::new(),
            execution_states: smart_table::new(),
            roots: smart_table::new(),
            inbound_nonces: smart_table::new(),
            latest_price_sequence_number: 0,
            static_config_set_events: account::new_event_handle(&state_object_signer),
            dynamic_config_set_events: account::new_event_handle(&state_object_signer),
            source_chain_config_set_events: account::new_event_handle(&state_object_signer),
            skipped_already_executed_events: account::new_event_handle(
                &state_object_signer
            ),
            already_attempted_events: account::new_event_handle(&state_object_signer),
            execution_state_changed_events: account::new_event_handle(&state_object_signer),
            commit_report_accepted_events: account::new_event_handle(&state_object_signer),
            skipped_incorrect_nonce_events: account::new_event_handle(&state_object_signer),
            skipped_report_execution_events: account::new_event_handle(
                &state_object_signer
            )
        };

        event::emit(StaticConfigSet { chain_selector });
        event::emit_event(
            &mut state.static_config_set_events, StaticConfigSet { chain_selector }
        );

        set_dynamic_config_internal(
            &mut state,
            permissionless_execution_threshold_secs,
            is_rmn_verification_disabled
        );
        apply_source_chain_config_updates_internal(
            &mut state, source_chain_selectors, source_chain_is_enabled
        );

        move_to(&state_object_signer, state);
    }

    #[view]
    public fun get_execution_state(
        source_chain_selector: u64, sequence_number: u64
    ): u8 acquires OffRampState {
        let state = borrow_state();

        assert!(
            smart_table::contains(&state.execution_states, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_execution_states =
            smart_table::borrow(&state.execution_states, source_chain_selector);
        let execution_state =
            smart_table::borrow(source_chain_execution_states, sequence_number);
        *execution_state
    }

    public entry fun manually_execute(reports_bytes: vector<u8>) acquires OffRampState {
        let state = borrow_state_mut();
        ocr3_base::assert_chain_not_forked(&state.ocr3_base_state);
        let reports = deserialize_execution_reports(reports_bytes);
        batch_execute(state, reports, true);
    }

    inline fun batch_execute(
        state: &mut OffRampState, reports: vector<ExecutionReport>, manual_execution: bool
    ) {
        assert!(!vector::is_empty(&reports), error::invalid_argument(E_EMPTY_BATCH));
        vector::for_each(
            reports,
            |report| execute_single_report(state, report, manual_execution)
        );
    }

    fun execute_single_report(
        state: &mut OffRampState, execution_report: ExecutionReport, manual_execution: bool
    ) {
        let source_chain_selector = execution_report.source_chain_selector;

        if (rmn_remote::is_cursed_u128(source_chain_selector as u128)) {
            assert!(!manual_execution, error::permission_denied(E_CURSED_BY_RMN));

            event::emit(SkippedReportExecution { source_chain_selector });
            event::emit_event(
                &mut state.skipped_report_execution_events,
                SkippedReportExecution { source_chain_selector }
            );
            return
        };

        // assert that the source chain is enabled.
        assert!(
            smart_table::contains(&state.source_chain_configs, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_config =
            smart_table::borrow(&state.source_chain_configs, source_chain_selector);
        assert!(
            source_chain_config.is_enabled,
            error::permission_denied(E_SOURCE_CHAIN_NOT_ENABLED)
        );

        let messages_len = vector::length(&execution_report.messages);
        assert!(messages_len > 0, error::invalid_argument(E_EMPTY_REPORT));
        assert!(
            messages_len == vector::length(&execution_report.offchain_token_data),
            error::invalid_argument(E_UNEXPECTED_TOKEN_DATA)
        );

        let metadata_hash =
            calculate_metadata_hash(source_chain_selector, state.chain_selector);

        let hashed_leaves = vector::map_ref(
            &execution_report.messages,
            |message| {
                assert!(
                    message.header.source_chain_selector == source_chain_selector,
                    error::invalid_argument(E_SOURCE_CHAIN_SELECTOR_MISMATCH)
                );
                assert!(
                    message.header.dest_chain_selector == state.chain_selector,
                    error::invalid_argument(E_DEST_CHAIN_SELECTOR_MISMATCH)
                );

                calculate_message_hash(message, metadata_hash)
            }
        );

        let root =
            merkle_multi_proof::merkle_root(
                &hashed_leaves,
                &execution_report.proofs,
                execution_report.proof_flag_bits
            );

        // this should always exist because source_chain_selector exists in source_chain_configs
        let source_chain_roots = smart_table::borrow(
            &state.roots, source_chain_selector
        );

        assert!(
            smart_table::contains(source_chain_roots, root),
            error::invalid_argument(E_ROOT_NOT_COMMITTED)
        );
        let timestamp_committed_secs = *smart_table::borrow(source_chain_roots, root);

        let source_chain_execution_states =
            smart_table::borrow_mut(&mut state.execution_states, source_chain_selector);

        let i = 0;
        while (i < messages_len) {
            let message = vector::borrow(&execution_report.messages, i);
            let message_hash = vector::borrow(&hashed_leaves, i);
            let sequence_number = message.header.sequence_number;
            let execution_state_ref =
                smart_table::borrow_mut(source_chain_execution_states, sequence_number);
            let original_state = *execution_state_ref;

            if (original_state != EXECUTION_STATE_UNTOUCHED) {
                event::emit(
                    SkippedAlreadyExecuted { source_chain_selector, sequence_number }
                );
                event::emit_event(
                    &mut state.skipped_already_executed_events,
                    SkippedAlreadyExecuted { source_chain_selector, sequence_number }
                );
                continue
            };

            if (manual_execution) {
                let is_old_commit_report =
                    (timestamp::now_seconds() - timestamp_committed_secs)
                        > (state.permissionless_execution_threshold_secs as u64);
                assert!(
                    is_old_commit_report,
                    error::permission_denied(E_MANUAL_EXECUTION_NOT_YET_ENABLED)
                );
            } else {
                event::emit(AlreadyAttempted { source_chain_selector, sequence_number });
                event::emit_event(
                    &mut state.already_attempted_events,
                    AlreadyAttempted { source_chain_selector, sequence_number }
                );
                continue
            };

            if (message.header.nonce != 0) {
                if (original_state != EXECUTION_STATE_UNTOUCHED) {
                    if (!increment_inbound_nonce(
                        state,
                        source_chain_selector,
                        message.header.nonce,
                        message.sender
                    )) {
                        continue
                    };
                }
            };

            assert!(
                vector::length(&message.token_amounts)
                    == vector::length(&execution_report.offchain_token_data),
                error::invalid_argument(E_TOKEN_DATA_MISMATCH)
            );

            let message_offchain_token_data = vector::borrow(
                &execution_report.offchain_token_data, i
            );
            assert!(
                vector::length(&message.token_amounts)
                    == vector::length(message_offchain_token_data),
                error::invalid_argument(E_TOKEN_DATA_MISMATCH)
            );
            let return_data = execute_single_message(
                message, message_offchain_token_data
            );

            *execution_state_ref = EXECUTION_STATE_SUCCESS;

            event::emit(
                ExecutionStateChanged {
                    source_chain_selector,
                    sequence_number,
                    message_id: message.header.message_id,
                    message_hash: *message_hash,
                    return_data
                }
            );
            event::emit_event(
                &mut state.execution_state_changed_events,
                ExecutionStateChanged {
                    source_chain_selector,
                    sequence_number,
                    message_id: message.header.message_id,
                    message_hash: *message_hash,
                    return_data
                }
            );

            i = i + 1;
        };
    }

    public entry fun commit(
        caller: &signer,
        report_context: vector<vector<u8>>,
        report: vector<u8>,
        signatures: vector<vector<u8>>
    ) acquires OffRampState {
        let state = borrow_state_mut();

        let commit_report = deserialize_commit_report(report);
        assert!(
            commit_report.offramp_address == @ccip,
            error::invalid_argument(E_INVALID_OFFRAMP_ADDRESS)
        );

        if (!state.is_rmn_verification_disabled
            && !vector::is_empty(&commit_report.merkle_roots)) {
            let merkle_root_source_chain_selectors = vector[];
            let merkle_root_min_sequence_numbers = vector[];
            let merkle_root_max_sequence_numbers = vector[];
            let merkle_root_values = vector[];
            vector::for_each_ref(
                &commit_report.merkle_roots,
                |merkle_root| {
                    vector::push_back(
                        &mut merkle_root_source_chain_selectors,
                        merkle_root.source_chain_selector
                    );
                    vector::push_back(
                        &mut merkle_root_min_sequence_numbers,
                        merkle_root.min_sequence_number
                    );
                    vector::push_back(
                        &mut merkle_root_max_sequence_numbers,
                        merkle_root.max_sequence_number
                    );
                    vector::push_back(&mut merkle_root_values, merkle_root.merkle_root);
                }
            );

            rmn_remote::verify(
                merkle_root_source_chain_selectors,
                merkle_root_min_sequence_numbers,
                merkle_root_max_sequence_numbers,
                merkle_root_values,
                commit_report.rmn_signatures
            );
        };

        if (vector::length(&commit_report.price_updates.token_price_updates) > 0
            || vector::length(&commit_report.price_updates.gas_price_updates) > 0) {
            let ocr_sequence_number =
                ocr3_base::deserialize_sequence_bytes(
                    *vector::borrow(&report_context, 1)
                );
            if (state.latest_price_sequence_number < ocr_sequence_number) {
                state.latest_price_sequence_number = ocr_sequence_number;

                let source_tokens = vector[];
                let source_usd_per_token = vector[];
                vector::for_each_ref(
                    &commit_report.price_updates.token_price_updates,
                    |token_price_update| {
                        vector::push_back(
                            &mut source_tokens, token_price_update.source_token
                        );
                        vector::push_back(
                            &mut source_usd_per_token,
                            token_price_update.usd_per_token
                        );
                    }
                );

                let gas_dest_chain_selectors = vector[];
                let gas_usd_per_unit_gas = vector[];
                vector::for_each_ref(
                    &commit_report.price_updates.gas_price_updates,
                    |gas_price_update| {
                        vector::push_back(
                            &mut gas_dest_chain_selectors,
                            gas_price_update.dest_chain_selector
                        );
                        vector::push_back(
                            &mut gas_usd_per_unit_gas,
                            gas_price_update.usd_per_unit_gas
                        );
                    }
                );

                fee_quoter::update_prices(
                    source_tokens,
                    source_usd_per_token,
                    gas_dest_chain_selectors,
                    gas_usd_per_unit_gas
                );
            } else {
                assert!(
                    vector::length(&commit_report.merkle_roots) > 0,
                    error::invalid_argument(E_STALE_COMMIT_REPORT)
                );
            }
        };

        vector::for_each_ref(
            &commit_report.merkle_roots,
            |root| {
                let root: &MerkleRoot = root;
                let source_chain_selector = root.source_chain_selector;

                assert!(
                    !rmn_remote::is_cursed_u128(source_chain_selector as u128),
                    error::permission_denied(E_CURSED_BY_RMN)
                );

                assert!(
                    smart_table::contains(
                        &state.source_chain_configs, source_chain_selector
                    ),
                    error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
                );
                let source_chain_config =
                    smart_table::borrow_mut(
                        &mut state.source_chain_configs, source_chain_selector
                    );
                assert!(
                    source_chain_config.is_enabled,
                    error::permission_denied(E_SOURCE_CHAIN_NOT_ENABLED)
                );
                assert!(
                    source_chain_config.min_sequence_number == root.min_sequence_number
                        && root.min_sequence_number <= root.max_sequence_number,
                    error::invalid_argument(E_INVALID_INTERVAL)
                );

                let merkle_root = root.merkle_root;
                assert!(
                    vector::length(&merkle_root) == 32,
                    error::invalid_argument(E_INVALID_ROOT)
                );
                assert!(
                    merkle_root != ZERO_MERKLE_ROOT,
                    error::invalid_argument(E_INVALID_ROOT)
                );

                let source_chain_roots =
                    smart_table::borrow_mut(&mut state.roots, source_chain_selector);
                assert!(
                    !smart_table::contains(source_chain_roots, merkle_root),
                    error::invalid_argument(E_ROOT_ALREADY_COMMITTED)
                );

                source_chain_config.min_sequence_number = source_chain_config.min_sequence_number
                    + 1;
                smart_table::add(
                    source_chain_roots, merkle_root, timestamp::now_seconds()
                );
            }
        );

        event::emit(CommitReportAccepted { commit_report });
        event::emit_event(
            &mut state.commit_report_accepted_events,
            CommitReportAccepted { commit_report }
        );

        ocr3_base::transmit(
            &mut state.ocr3_base_state,
            signer::address_of(caller),
            ocr3_base::ocr_plugin_type_commit(),
            report_context,
            report,
            signatures
        )
    }

    public entry fun execute(
        caller: &signer, report_context: vector<vector<u8>>, report: vector<u8>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        let reports = deserialize_execution_reports(report);
        batch_execute(state, reports, true);
        ocr3_base::transmit(
            &mut state.ocr3_base_state,
            signer::address_of(caller),
            ocr3_base::ocr_plugin_type_execution(),
            report_context,
            report,
            vector::empty()
        )
    }

    #[view]
    public fun get_latest_price_sequence_number(): u64 acquires OffRampState {
        borrow_state().latest_price_sequence_number
    }

    #[view]
    public fun get_merkle_root(
        source_chain_selector: u64, root: vector<u8>
    ): u64 acquires OffRampState {
        let state = borrow_state();
        assert!(
            smart_table::contains(&state.roots, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );

        let source_chain_roots = smart_table::borrow(
            &state.roots, source_chain_selector
        );
        assert!(
            smart_table::contains(source_chain_roots, root),
            error::invalid_argument(E_INVALID_ROOT)
        );

        *smart_table::borrow(source_chain_roots, root)
    }

    #[view]
    public fun get_source_chain_config(source_chain_selector: u64): (bool, u64) acquires OffRampState {
        let state = borrow_state();
        assert!(
            smart_table::contains(&state.source_chain_configs, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );

        let source_chain_config =
            smart_table::borrow(&state.source_chain_configs, source_chain_selector);
        (source_chain_config.is_enabled, source_chain_config.min_sequence_number)
    }

    #[view]
    public fun get_inbound_nonce(
        source_chain_selector: u64, sender: vector<u8>
    ): u64 acquires OffRampState {
        let state = borrow_state();
        assert!(
            smart_table::contains(&state.inbound_nonces, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_nonces =
            smart_table::borrow(&state.inbound_nonces, source_chain_selector);
        *smart_table::borrow_with_default(source_chain_nonces, sender, &0)
    }

    public entry fun apply_source_chain_config_updates(
        caller: &signer,
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        apply_source_chain_config_updates_internal(
            state, source_chain_selectors, source_chain_is_enabled
        )
    }

    public entry fun set_dynamic_config(
        caller: &signer,
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        set_dynamic_config_internal(
            state,
            permissionless_execution_threshold_secs,
            is_rmn_verification_disabled
        )
    }

    #[view]
    public fun get_static_config(): StaticConfig acquires OffRampState {
        let state = borrow_state();
        StaticConfig { chain_selector: state.chain_selector }
    }

    #[view]
    public fun get_dynamic_config(): DynamicConfig acquires OffRampState {
        let state = borrow_state();
        DynamicConfig {
            permissionless_execution_threshold_secs: state.permissionless_execution_threshold_secs,
            is_rmn_verification_disabled: state.is_rmn_verification_disabled
        }
    }

    inline fun borrow_state(): &OffRampState {
        borrow_global<OffRampState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut OffRampState {
        borrow_global_mut<OffRampState>(state_object::object_address())
    }

    inline fun execute_single_message(
        message: &Any2AptosRampMessage, message_offchain_token_data: &vector<vector<u8>>
    ): Option<u128> {
        assert!(!rmn_remote::is_cursed_global(), error::permission_denied(E_BAD_RMN_SIGNAL));

        let (local_token_addresses, local_token_amounts) =
            release_or_mint_tokens(
                &message.token_amounts,
                message_offchain_token_data,
                message.sender,
                message.receiver,
                message.header.source_chain_selector
            );

        let dest_token_amounts =
            client::new_dest_token_amounts(local_token_addresses, local_token_amounts);

        let any2aptos_message =
            client::new_any2aptos_message(
                message.header.message_id,
                message.header.source_chain_selector,
                message.sender,
                message.data,
                dest_token_amounts
            );

        receiver_dispatcher::dispatch_receive(message.receiver, any2aptos_message)
    }

    inline fun release_or_mint_tokens(
        token_amounts: &vector<Any2AptosTokenTransfer>,
        message_offchain_token_data: &vector<vector<u8>>,
        sender: vector<u8>,
        receiver: address,
        source_chain_selector: u64
    ): (vector<address>, vector<u64>) {
        // execute_single_report already checks that the vector lengths match.
        let local_token_addresses = vector[];
        let local_token_amounts = vector[];

        vector::zip_ref(
            token_amounts,
            message_offchain_token_data,
            |token_transfer, current_offchain_token_data| {
                let (token_address, token_amount) =
                    release_or_mint_single_token(
                        token_transfer,
                        current_offchain_token_data,
                        sender,
                        receiver,
                        source_chain_selector
                    );
                vector::push_back(&mut local_token_addresses, token_address);
                vector::push_back(&mut local_token_amounts, token_amount);
            }
        );

        (local_token_addresses, local_token_amounts)
    }

    inline fun release_or_mint_single_token(
        token_transfer: &Any2AptosTokenTransfer,
        current_offchain_token_data: &vector<u8>,
        sender: vector<u8>,
        receiver: address,
        source_chain_selector: u64
    ): (address, u64) {
        let local_token = token_transfer.dest_token_address;
        let token_pool_address = token_admin_registry::get_pool(local_token);
        assert!(
            token_pool_address != @0x0,
            error::invalid_state(E_UNSUPPORTED_TOKEN)
        );

        let source_amount = token_transfer.amount;
        let source_pool_data = token_transfer.extra_data;

        let (fa, local_amount) =
            token_admin_dispatcher::dispatch_release_or_mint(
                token_pool_address,
                sender,
                receiver,
                source_amount,
                local_token,
                source_chain_selector,
                token_transfer.source_pool_address,
                source_pool_data,
                *current_offchain_token_data
            );

        // TODO: it's possible that the FungibleAsset's amount that is returned
        // is different than the amount specified by `local_amount`. is this
        // valid behavior, eg if this is a special token pool that deposits elsewhere?
        primary_fungible_store::deposit(receiver, fa);

        (local_token, local_amount)
    }


    inline fun set_dynamic_config_internal(
        state: &mut OffRampState,
        permissionless_execution_threshold_secs: u32,
        is_rmn_verification_disabled: bool
    ) {
        state.permissionless_execution_threshold_secs = permissionless_execution_threshold_secs;
        state.is_rmn_verification_disabled = is_rmn_verification_disabled;
        event::emit(
            DynamicConfigSet {
                permissionless_execution_threshold_secs,
                is_rmn_verification_disabled
            }
        );
        event::emit_event(
            &mut state.dynamic_config_set_events,
            DynamicConfigSet {
                permissionless_execution_threshold_secs,
                is_rmn_verification_disabled
            }
        );
    }

    inline fun apply_source_chain_config_updates_internal(
        state: &mut OffRampState,
        // pairs of (source chain selector, is enabled)
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) {
        vector::zip_ref(
            &source_chain_selectors,
            &source_chain_is_enabled,
            |source_chain_selector, is_enabled| {
                let source_chain_selector: u64 = *source_chain_selector;
                let is_enabled: bool = *is_enabled;

                assert!(
                    source_chain_selector != 0,
                    error::invalid_argument(E_ZERO_CHAIN_SELECTOR)
                );

                if (!smart_table::contains(
                    &state.source_chain_configs, source_chain_selector
                )) {
                    smart_table::add(
                        &mut state.source_chain_configs,
                        source_chain_selector,
                        SourceChainConfig { is_enabled: false, min_sequence_number: 1 }
                    );
                    smart_table::add(
                        &mut state.execution_states,
                        source_chain_selector,
                        smart_table::new()
                    );
                    smart_table::add(
                        &mut state.roots, source_chain_selector, smart_table::new()
                    );
                    smart_table::add(
                        &mut state.inbound_nonces,
                        source_chain_selector,
                        smart_table::new()
                    );
                };

                let config =
                    smart_table::borrow_mut(
                        &mut state.source_chain_configs, source_chain_selector
                    );
                config.is_enabled = is_enabled;

                event::emit(
                    SourceChainConfigSet {
                        is_enabled: config.is_enabled,
                        min_sequence_number: config.min_sequence_number
                    }
                );
                event::emit_event(
                    &mut state.source_chain_config_set_events,
                    SourceChainConfigSet {
                        is_enabled: config.is_enabled,
                        min_sequence_number: config.min_sequence_number
                    }
                );

            }
        );
    }

    inline fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64
    ): vector<u8> {
        let packed = vector[];
        eth_abi::encode_bytes32(
            &mut packed, aptos_hash::keccak256(b"Any2AptosMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_address(&mut packed, @ccip);
        aptos_hash::keccak256(packed)
    }

    inline fun calculate_message_hash(
        message: &Any2AptosRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let outer_hash = vector[];
        eth_abi::encode_bytes32(
            &mut outer_hash, merkle_multi_proof::leaf_domain_separator()
        );
        eth_abi::encode_bytes32(&mut outer_hash, metadata_hash);

        let inner_hash = vector[];
        eth_abi::encode_bytes32(&mut inner_hash, message.header.message_id);
        eth_abi::encode_address(&mut inner_hash, message.receiver);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u256(&mut inner_hash, message.gas_limit);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(inner_hash));

        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(message.sender));
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(message.data));

        let token_hash = vector[];
        eth_abi::encode_u256(
            &mut token_hash, vector::length(&message.token_amounts) as u256
        );
        vector::for_each_ref(
            &message.token_amounts,
            |token_transfer| {
                let token_transfer: &Any2AptosTokenTransfer = token_transfer;
                eth_abi::encode_bytes(
                    &mut token_hash, token_transfer.source_pool_address
                );
                eth_abi::encode_address(
                    &mut token_hash, token_transfer.dest_token_address
                );
                eth_abi::encode_u32(&mut token_hash, token_transfer.dest_gas_amount);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.extra_data);
                eth_abi::encode_u256(&mut token_hash, token_transfer.amount);
            }
        );
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(token_hash));

        aptos_hash::keccak256(outer_hash)
    }

    inline fun deserialize_commit_report(report_bytes: vector<u8>): CommitReport {
        let stream = eth_abi::new_stream(report_bytes);
        let token_price_updates =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    let source_token = eth_abi::decode_address(stream);
                    let usd_per_token = eth_abi::decode_u256(stream);
                    TokenPriceUpdate { source_token, usd_per_token }
                }
            );

        let gas_price_updates =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    let dest_chain_selector = eth_abi::decode_u64(stream);
                    let usd_per_unit_gas = eth_abi::decode_u256(stream);
                    GasPriceUpdate { dest_chain_selector, usd_per_unit_gas }
                }
            );

        let price_updates = PriceUpdates { token_price_updates, gas_price_updates };

        let merkle_roots =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    let source_chain_selector = eth_abi::decode_u64(stream);
                    let min_sequence_number = eth_abi::decode_u64(stream);
                    let max_sequence_number = eth_abi::decode_u64(stream);
                    let merkle_root = eth_abi::decode_bytes32(stream);

                    MerkleRoot {
                        source_chain_selector,
                        min_sequence_number,
                        max_sequence_number,
                        merkle_root
                    }
                }
            );

        let rmn_signatures =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    let r = eth_abi::decode_bytes32(stream);
                    let s = eth_abi::decode_bytes32(stream);
                    vector::append(&mut r, s);
                    r
                }
            );

        let offramp_address = eth_abi::decode_address(&mut stream);

        CommitReport { price_updates, merkle_roots, rmn_signatures, offramp_address }
    }

    inline fun deserialize_execution_reports(reports_bytes: vector<u8>):
        vector<ExecutionReport> {
        let stream = eth_abi::new_stream(reports_bytes);
        eth_abi::decode_vector(
            &mut stream,
            |stream| {
                let report_bytes = eth_abi::decode_bytes(stream);
                deserialize_execution_report(report_bytes)
            }
        )
    }

    inline fun deserialize_execution_report(report_bytes: vector<u8>): ExecutionReport {
        let stream = eth_abi::new_stream(report_bytes);

        let source_chain_selector = eth_abi::decode_u64(&mut stream);

        let messages =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    let message_id = eth_abi::decode_bytes32(stream);
                    let header_source_chain_selector = eth_abi::decode_u64(stream);
                    let dest_chain_selector = eth_abi::decode_u64(stream);
                    let sequence_number = eth_abi::decode_u64(stream);
                    let nonce = eth_abi::decode_u64(stream);

                    let header = RampMessageHeader {
                        message_id,
                        source_chain_selector: header_source_chain_selector,
                        dest_chain_selector,
                        sequence_number,
                        nonce
                    };

                    assert!(
                        source_chain_selector == header_source_chain_selector,
                        error::invalid_argument(E_SOURCE_CHAIN_SELECTOR_MISMATCH)
                    );

                    let sender = eth_abi::decode_bytes(stream);
                    let data = eth_abi::decode_bytes(stream);
                    let receiver = eth_abi::decode_address(stream);
                    let gas_limit = eth_abi::decode_u256(stream);

                    let token_amounts =
                        eth_abi::decode_vector(
                            stream,
                            |stream| {
                                let source_pool_address = eth_abi::decode_bytes(stream);
                                let dest_token_address = eth_abi::decode_address(stream);
                                let dest_gas_amount = eth_abi::decode_u32(stream);
                                let extra_data = eth_abi::decode_bytes(stream);
                                let amount = eth_abi::decode_u256(stream);

                                Any2AptosTokenTransfer {
                                    source_pool_address,
                                    dest_token_address,
                                    dest_gas_amount,
                                    extra_data,
                                    amount
                                }
                            }
                        );

                    Any2AptosRampMessage {
                        header,
                        sender,
                        data,
                        receiver,
                        gas_limit,
                        token_amounts
                    }
                }
            );

        let offchain_token_data =
            eth_abi::decode_vector(
                &mut stream,
                |stream| {
                    eth_abi::decode_vector(
                        stream, |stream| eth_abi::decode_bytes(stream)
                    )
                }
            );

        let proofs =
            eth_abi::decode_vector(
                &mut stream,
                |stream| eth_abi::decode_bytes32(stream)
            );

        let proof_flag_bits = eth_abi::decode_u256(&mut stream);

        ExecutionReport {
            source_chain_selector,
            messages,
            offchain_token_data,
            proofs,
            proof_flag_bits
        }
    }

    inline fun increment_inbound_nonce(
        state: &mut OffRampState,
        source_chain_selector: u64,
        expected_nonce: u64,
        sender: vector<u8>
    ): bool {
        assert!(
            smart_table::contains(&state.inbound_nonces, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_nonces =
            smart_table::borrow_mut(&mut state.inbound_nonces, source_chain_selector);
        let nonce_ref =
            smart_table::borrow_mut_with_default(source_chain_nonces, sender, 0);
        let incremented_nonce = *nonce_ref + 1;
        if (incremented_nonce != expected_nonce) {
            event::emit(
                SkippedIncorrectNonce {
                    source_chain_selector,
                    nonce: expected_nonce,
                    sender
                }
            );
            event::emit_event(
                &mut state.skipped_incorrect_nonce_events,
                SkippedIncorrectNonce {
                    source_chain_selector,
                    nonce: expected_nonce,
                    sender
                }
            );
            false
        } else {
            *nonce_ref = incremented_nonce;
            true
        }
    }

    //
    // ccip::ocr3_base functions
    //

    public entry fun set_ocr3_config(
        caller: &signer,
        config_digest: vector<u8>,
        ocr_plugin_type: u8,
        big_f: u8,
        is_signature_verification_enabled: bool,
        signers: vector<vector<u8>>,
        transmitters: vector<address>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ocr3_base::set_ocr3_config(
            signer::address_of(caller),
            &state.ownable_state,
            &mut state.ocr3_base_state,
            config_digest,
            ocr_plugin_type,
            big_f,
            is_signature_verification_enabled,
            signers,
            transmitters
        )
    }

    #[view]
    public fun latest_config_details(
        ocr_plugin_type: u8
    ): (vector<u8>, u8, u8, bool, vector<vector<u8>>, vector<address>) acquires OffRampState {
        let state = borrow_state();
        ocr3_base::latest_config_details(&state.ocr3_base_state, ocr_plugin_type)
    }

    //
    // ccip::ownable functions
    //

    #[view]
    public fun owner(): address acquires OffRampState {
        let state = borrow_state();
        ownable::owner(&state.ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut state.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut state.ownable_state)
    }
}
