module ccip::offramp {
    use std::account;
    use std::aptos_hash;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::option::{Self, Option};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::timestamp;
    use std::vector;

    use ccip::bcs_stream;
    use ccip::eth_abi;
    use ccip::merkle_multi_proof;
    use ccip::ownable;
    use ccip::ocr3_base;

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

        // source chain selector -> config
        source_chain_configs: SmartTable<u64, SourceChainConfig>,

        // source chain selector -> seq num -> execution state
        execution_states: SmartTable<u64, SmartTable<u64, u8>>,

        // source chain selector -> merkle root -> timestamp,
        roots: SmartTable<u64, SmartTable<vector<u8>, u64>>,
        latest_price_sequence_number: u64,
        static_config_set_events: EventHandle<StaticConfigSet>,
        dynamic_config_set_events: EventHandle<DynamicConfigSet>,
        source_chain_config_set_events: EventHandle<SourceChainConfigSet>,
        skipped_already_executed_events: EventHandle<SkippedAlreadyExecuted>,
        already_attempted_events: EventHandle<AlreadyAttempted>,
        execution_state_changed_events: EventHandle<ExecutionStateChanged>,
        commit_report_accepted_events: EventHandle<CommitReportAccepted>
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
        // this is u256 on EVM, but for both 0x1::coin and 0x1::fungible_asset, amount
        // is a u64.
        amount: u64
    }

    struct ExecutionReport has drop {
        source_chain_selector: u64,
        message: Any2AptosRampMessage,
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>>,
        proof_flag_bits: u256
    }

    struct CommitReport has store, drop, copy {
        token_price_updates: vector<TokenPriceUpdate>,
        gas_price_updates: vector<GasPriceUpdate>,
        merkle_roots: vector<MerkleRoot>,

        // TODO: this was added so that the hashed/verified report contains the target address,
        // since we don't have onramp address fields. check if we need this.
        offramp_address: address
    }

    struct TokenPriceUpdate has store, drop, copy {
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

    #[event]
    struct StaticConfigSet has store, drop {
        chain_selector: u64
    }

    #[event]
    struct DynamicConfigSet has store, drop {
        permissionless_execution_threshold_secs: u32
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

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_SOURCE_CHAIN_SELECTORS_MISMATCH: u64 = 3;
    const E_ZERO_CHAIN_SELECTOR: u64 = 4;
    const E_UNKNOWN_SOURCE_CHAIN_SELECTOR: u64 = 5;
    const E_TOKEN_TRANSFER_DATA_MISMATCH: u64 = 6;
    const E_SOURCE_CHAIN_SELECTOR_MISMATCH: u64 = 7;
    const E_DEST_CHAIN_SELECTOR_MISMATCH: u64 = 8;
    const E_TOKEN_DATA_MISMATCH: u64 = 9;
    const E_ROOT_NOT_COMMITTED: u64 = 10;
    const E_MANUAL_EXECUTION_NOT_YET_ENABLED: u64 = 11;
    const E_SOURCE_CHAIN_NOT_ENABLED: u64 = 12;
    const E_INVALID_OFFRAMP_ADDRESS: u64 = 13;
    const E_INVALID_INTERVAL: u64 = 14;
    const E_INVALID_ROOT: u64 = 15;
    const E_ROOT_ALREADY_COMMITTED: u64 = 16;
    const E_STALE_COMMIT_REPORT: u64 = 17;

    public fun initialize(
        caller: &signer,
        chain_selector: u64,
        permissionless_execution_threshold_secs: u32,

        // pairs of (source chain selector, is enabled)
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) acquires OffRampState {
        assert!(
            signer::address_of(caller) == @ccip,
            error::invalid_argument(E_NOT_PUBLISHER)
        );
        assert!(
            !exists<OffRampState>(@ccip),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );
        assert!(
            vector::length(&source_chain_selectors)
                == vector::length(&source_chain_is_enabled),
            error::invalid_argument(E_SOURCE_CHAIN_SELECTORS_MISMATCH)
        );

        let state = OffRampState {
            ownable_state: ownable::new(caller, @0x0),
            ocr3_base_state: ocr3_base::new(caller),
            chain_selector,
            permissionless_execution_threshold_secs: 0,
            source_chain_configs: smart_table::new(),
            execution_states: smart_table::new(),
            roots: smart_table::new(),
            latest_price_sequence_number: 0,
            static_config_set_events: account::new_event_handle(caller),
            dynamic_config_set_events: account::new_event_handle(caller),
            source_chain_config_set_events: account::new_event_handle(caller),
            skipped_already_executed_events: account::new_event_handle(caller),
            already_attempted_events: account::new_event_handle(caller),
            execution_state_changed_events: account::new_event_handle(caller),
            commit_report_accepted_events: account::new_event_handle(caller)
        };

        move_to(caller, state);
        let state = borrow_state_mut();

        event::emit(StaticConfigSet { chain_selector });
        event::emit_event(
            &mut state.static_config_set_events, StaticConfigSet { chain_selector }
        );

        set_dynamic_config_unchecked(permissionless_execution_threshold_secs);
        apply_source_chain_config_updates_unchecked(
            source_chain_selectors, source_chain_is_enabled
        );
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

    // TODO: consider encoding this using bcs stream
    public entry fun manually_execute(
        // message header
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64,

        // ramp message
        sender: vector<u8>,
        data: vector<u8>,
        receiver: address,
        gas_limit: u256,

        // vector of token transfer data
        source_pool_addresses: vector<vector<u8>>,
        dest_token_addresses: vector<address>,
        dest_gas_amounts: vector<u32>,
        extra_datas: vector<vector<u8>>,
        token_amounts: vector<u64>,

        // execution report footer
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>>,
        proof_flag_bits: u256
    ) acquires OffRampState {
        // TODO: chain not forked check
        let header = RampMessageHeader {
            message_id,
            source_chain_selector,
            dest_chain_selector,
            sequence_number,
            nonce
        };

        let token_transfer_len = vector::length(&source_pool_addresses);
        assert!(
            token_transfer_len == vector::length(&dest_token_addresses),
            error::invalid_argument(E_TOKEN_TRANSFER_DATA_MISMATCH)
        );
        assert!(
            token_transfer_len == vector::length(&dest_gas_amounts),
            error::invalid_argument(E_TOKEN_TRANSFER_DATA_MISMATCH)
        );
        assert!(
            token_transfer_len == vector::length(&extra_datas),
            error::invalid_argument(E_TOKEN_TRANSFER_DATA_MISMATCH)
        );
        assert!(
            token_transfer_len == vector::length(&token_amounts),
            error::invalid_argument(E_TOKEN_TRANSFER_DATA_MISMATCH)
        );

        let token_transfers = vector[];
        let i = 0;
        while (i < token_transfer_len) {
            let source_pool_address = *vector::borrow(&source_pool_addresses, i);
            let dest_token_address = *vector::borrow(&dest_token_addresses, i);
            let dest_gas_amount = *vector::borrow(&dest_gas_amounts, i);
            let extra_data = *vector::borrow(&extra_datas, i);
            let amount = *vector::borrow(&token_amounts, i);

            vector::push_back(
                &mut token_transfers,
                Any2AptosTokenTransfer {
                    source_pool_address,
                    dest_token_address,
                    dest_gas_amount,
                    extra_data,
                    amount
                }
            );
            i = i + 1;
        };

        let message = Any2AptosRampMessage {
            header,
            sender,
            data,
            receiver,
            gas_limit,
            token_amounts: token_transfers
        };

        let execution_report = ExecutionReport {
            source_chain_selector,
            message,
            offchain_token_data,
            proofs,
            proof_flag_bits
        };

        execute_single_report(execution_report, true)
    }

    fun execute_single_report(
        execution_report: ExecutionReport, manual_execution: bool
    ) acquires OffRampState {
        let state = borrow_state_mut();

        let source_chain_selector = execution_report.source_chain_selector;

        assert!(
            execution_report.message.header.source_chain_selector
                == source_chain_selector,
            error::invalid_argument(E_SOURCE_CHAIN_SELECTOR_MISMATCH)
        );
        assert!(
            execution_report.message.header.dest_chain_selector == state.chain_selector,
            error::invalid_argument(E_DEST_CHAIN_SELECTOR_MISMATCH)
        );

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

        let metadata_hash =
            calculate_metadata_hash(source_chain_selector, state.chain_selector);
        let message_hash =
            calculate_message_hash(&execution_report.message, metadata_hash);

        let hashed_leaves = vector[message_hash];
        let root =
            merkle_multi_proof::merkle_root(
                &hashed_leaves,
                &execution_report.proofs,
                execution_report.proof_flag_bits
            );

        assert!(
            smart_table::contains(&state.roots, source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
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
        let sequence_number = execution_report.message.header.sequence_number;
        let original_state =
            *smart_table::borrow(source_chain_execution_states, sequence_number);

        if (original_state != EXECUTION_STATE_UNTOUCHED) {
            event::emit(SkippedAlreadyExecuted { source_chain_selector, sequence_number });
            event::emit_event(
                &mut state.skipped_already_executed_events,
                SkippedAlreadyExecuted { source_chain_selector, sequence_number }
            );
            return
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
            return
        };

        // TODO(nonce): message.header.nonce handling

        assert!(
            vector::length(&execution_report.message.token_amounts)
                == vector::length(&execution_report.offchain_token_data),
            error::invalid_argument(E_TOKEN_DATA_MISMATCH)
        );

        let return_data =
            execute_single_message(
                &execution_report.message, &execution_report.offchain_token_data
            );

        let execution_state_ref =
            smart_table::borrow_mut(source_chain_execution_states, sequence_number);
        *execution_state_ref = EXECUTION_STATE_SUCCESS;

        event::emit(
            ExecutionStateChanged {
                source_chain_selector,
                sequence_number,
                message_id: execution_report.message.header.message_id,
                message_hash,
                return_data
            }
        );
        event::emit_event(
            &mut state.execution_state_changed_events,
            ExecutionStateChanged {
                source_chain_selector,
                sequence_number,
                message_id: execution_report.message.header.message_id,
                message_hash,
                return_data
            }
        );
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

        if (vector::length(&commit_report.token_price_updates) > 0
            || vector::length(&commit_report.gas_price_updates) > 0) {
            let ocr_sequence_number =
                ocr3_base::deserialize_sequence_bytes(
                    *vector::borrow(&report_context, 1)
                );
            if (state.latest_price_sequence_number < ocr_sequence_number) {
                state.latest_price_sequence_number = ocr_sequence_number;
                // TODO(fee-quoter): handle price updates
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
    public fun get_chain_selector(): u64 acquires OffRampState {
        borrow_state().chain_selector
    }

    #[view]
    public fun get_permissionless_execution_threshold_secs(): u32 acquires OffRampState {
        borrow_state().permissionless_execution_threshold_secs
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

    public entry fun apply_source_chain_config_updates(
        caller: &signer,
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) acquires OffRampState {
        ownable::assert_only_owner(
            signer::address_of(caller), &borrow_state().ownable_state
        );

        apply_source_chain_config_updates_unchecked(
            source_chain_selectors, source_chain_is_enabled
        )
    }

    public entry fun set_dynamic_config(
        caller: &signer, permissionless_execution_threshold_secs: u32
    ) acquires OffRampState {
        ownable::assert_only_owner(
            signer::address_of(caller), &borrow_state().ownable_state
        );

        set_dynamic_config_unchecked(permissionless_execution_threshold_secs)
    }

    inline fun borrow_state(): &OffRampState {
        borrow_global<OffRampState>(@ccip)
    }

    inline fun borrow_state_mut(): &mut OffRampState {
        borrow_global_mut<OffRampState>(@ccip)
    }

    inline fun execute_single_message(
        message: &Any2AptosRampMessage, offchain_token_data: &vector<vector<u8>>
    ): Option<u128> {
        // TODO
        option::none()
    }

    inline fun set_dynamic_config_unchecked(
        permissionless_execution_threshold_secs: u32
    ) {
        let state = borrow_state_mut();
        state.permissionless_execution_threshold_secs = permissionless_execution_threshold_secs;
        event::emit(DynamicConfigSet { permissionless_execution_threshold_secs });
        event::emit_event(
            &mut state.dynamic_config_set_events,
            DynamicConfigSet { permissionless_execution_threshold_secs }
        );
    }

    inline fun apply_source_chain_config_updates_unchecked(
        // pairs of (source chain selector, is enabled)
        source_chain_selectors: vector<u64>,
        source_chain_is_enabled: vector<bool>
    ) {
        let state = borrow_state_mut();

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
                eth_abi::encode_u64(&mut token_hash, token_transfer.amount);
            }
        );
        eth_abi::encode_bytes32(&mut outer_hash, aptos_hash::keccak256(token_hash));

        aptos_hash::keccak256(outer_hash)
    }

    inline fun deserialize_commit_report(report_bytes: vector<u8>): CommitReport {
        let stream = bcs_stream::new(report_bytes);
        let token_price_updates =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    let source_token = bcs_stream::deserialize_address(stream);
                    let usd_per_token = bcs_stream::deserialize_u256(stream);
                    TokenPriceUpdate { source_token, usd_per_token }
                }
            );

        let gas_price_updates =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    let dest_chain_selector = bcs_stream::deserialize_u64(stream);
                    let usd_per_unit_gas = bcs_stream::deserialize_u256(stream);
                    GasPriceUpdate { dest_chain_selector, usd_per_unit_gas }
                }
            );

        let merkle_roots =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    let source_chain_selector = bcs_stream::deserialize_u64(stream);
                    let min_sequence_number = bcs_stream::deserialize_u64(stream);
                    let max_sequence_number = bcs_stream::deserialize_u64(stream);
                    let merkle_root = bcs_stream::deserialize_vector_u8(stream);

                    MerkleRoot {
                        source_chain_selector,
                        min_sequence_number,
                        max_sequence_number,
                        merkle_root
                    }
                }
            );

        let offramp_address = bcs_stream::deserialize_address(&mut stream);

        CommitReport {
            token_price_updates,
            gas_price_updates,
            merkle_roots,
            offramp_address
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
