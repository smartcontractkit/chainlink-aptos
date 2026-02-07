/// The OffRamp package handles merkle root commitments and message execution.
/// Future versions of this contract will be deployed as a separate package to avoid any unwanted side effects
/// during upgrades.
module ccip_offramp::offramp {
    use std::account::{Self, SignerCapability};
    use std::aptos_hash;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::{Self, Metadata};
    use std::object;
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};
    use std::timestamp;
    use std::vector;

    use ccip_offramp::ocr3_base;

    use ccip::address;
    use ccip::auth;
    use ccip::client;
    use ccip::eth_abi;
    use ccip::fee_quoter;
    use ccip::merkle_proof;
    use ccip::ownable;
    use ccip::receiver_dispatcher;
    use ccip::receiver_registry;
    use ccip::rmn_remote;
    use ccip::token_admin_dispatcher;
    use ccip::token_admin_registry;

    use mcms::bcs_stream::{Self, BCSStream};
    use mcms::mcms_registry;

    const STATE_SEED: vector<u8> = b"CHAINLINK_CCIP_OFFRAMP";

    // These have to match the EVM states
    const EXECUTION_STATE_UNTOUCHED: u8 = 0;
    const EXECUTION_STATE_SUCCESS: u8 = 2;

    const ZERO_MERKLE_ROOT: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    struct OffRampDeployment has key, store {
        state_signer_cap: SignerCapability
    }

    struct OffRampState has key, store {
        state_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        ocr3_base_state: ocr3_base::OCR3BaseState,

        // static config
        chain_selector: u64,

        // dynamic config
        permissionless_execution_threshold_seconds: u32,

        // State
        // source chain selector -> config
        source_chain_configs: SmartTable<u64, SourceChainConfig>,
        // source chain selector -> seq num -> execution state
        execution_states: SmartTable<u64, SmartTable<u64, u8>>,

        // merkle root -> timestamp,
        roots: SmartTable<vector<u8>, u64>,
        // This is the OCR sequence number, not to be confused with the CCIP message sequence number.
        latest_price_sequence_number: u64,

        // Events
        static_config_set_events: EventHandle<StaticConfigSet>,
        dynamic_config_set_events: EventHandle<DynamicConfigSet>,
        source_chain_config_set_events: EventHandle<SourceChainConfigSet>,
        skipped_already_executed_events: EventHandle<SkippedAlreadyExecuted>,
        execution_state_changed_events: EventHandle<ExecutionStateChanged>,
        commit_report_accepted_events: EventHandle<CommitReportAccepted>,
        skipped_report_execution_events: EventHandle<SkippedReportExecution>
    }

    struct SourceChainConfig has store, drop, copy {
        router: address,
        is_enabled: bool,
        min_seq_nr: u64,
        is_rmn_verification_disabled: bool,
        on_ramp: vector<u8>
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
        amount: u256 // This is the amount to transfer, as set on the source chain.
    }

    struct ExecutionReport has drop {
        source_chain_selector: u64,
        message: Any2AptosRampMessage,
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>> // Proofs used to construct the merkle root
    }

    // Matches the EVM struct
    struct CommitReport has store, drop, copy {
        price_updates: PriceUpdates, // Price updates for the fee_quoter
        blessed_merkle_roots: vector<MerkleRoot>, // Merkle roots that have been blessed by RMN
        unblessed_merkle_roots: vector<MerkleRoot>, // Merkle roots that don't require RMN blessing
        rmn_signatures: vector<vector<u8>> // The signatures for the blessed merkle roots
    }

    struct PriceUpdates has store, drop, copy {
        token_price_updates: vector<TokenPriceUpdate>,
        gas_price_updates: vector<GasPriceUpdate>
    }

    struct TokenPriceUpdate has store, drop, copy {
        source_token: address, // This is the local token
        usd_per_token: u256
    }

    struct GasPriceUpdate has store, drop, copy {
        dest_chain_selector: u64,
        usd_per_unit_gas: u256
    }

    struct MerkleRoot has store, drop, copy {
        source_chain_selector: u64,
        on_ramp_address: vector<u8>,
        min_seq_nr: u64,
        max_seq_nr: u64,
        merkle_root: vector<u8>
    }

    struct StaticConfig has store, drop, copy {
        chain_selector: u64,
        rmn_remote: address,
        token_admin_registry: address,
        nonce_manager: address
    }

    struct DynamicConfig has store, drop, copy {
        // On EVM, the feeQuoter is a dynamic address but due to the Aptos implementation using a static
        // upgradable FeeQuoter, this value is actually static. For compatibility reasons, we keep it as a dynamic config.
        fee_quoter: address,
        permissionless_execution_threshold_seconds: u32 // The delay before manual exec is enabled
    }

    #[event]
    struct StaticConfigSet has store, drop {
        static_config: StaticConfig
    }

    #[event]
    struct DynamicConfigSet has store, drop {
        dynamic_config: DynamicConfig
    }

    #[event]
    struct SourceChainConfigSet has store, drop {
        source_chain_selector: u64,
        source_chain_config: SourceChainConfig
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
        state: u8
    }

    #[event]
    struct CommitReportAccepted has store, drop {
        blessed_merkle_roots: vector<MerkleRoot>,
        unblessed_merkle_roots: vector<MerkleRoot>,
        price_updates: PriceUpdates
    }

    #[event]
    struct SkippedReportExecution has store, drop {
        source_chain_selector: u64
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_SOURCE_CHAIN_SELECTORS_MISMATCH: u64 = 2;
    const E_ZERO_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_SOURCE_CHAIN_SELECTOR: u64 = 4;
    const E_MUST_BE_OUT_OF_ORDER_EXEC: u64 = 5;
    const E_SOURCE_CHAIN_SELECTOR_MISMATCH: u64 = 6;
    const E_DEST_CHAIN_SELECTOR_MISMATCH: u64 = 7;
    const E_TOKEN_DATA_MISMATCH: u64 = 8;
    const E_ROOT_NOT_COMMITTED: u64 = 9;
    const E_MANUAL_EXECUTION_NOT_YET_ENABLED: u64 = 10;
    const E_SOURCE_CHAIN_NOT_ENABLED: u64 = 11;
    const E_COMMIT_ON_RAMP_MISMATCH: u64 = 12;
    const E_INVALID_INTERVAL: u64 = 13;
    const E_INVALID_ROOT: u64 = 14;
    const E_ROOT_ALREADY_COMMITTED: u64 = 15;
    const E_STALE_COMMIT_REPORT: u64 = 16;
    const E_UNSUPPORTED_TOKEN: u64 = 17;
    const E_UNKNOWN_FUNCTION: u64 = 18;
    const E_CURSED_BY_RMN: u64 = 19;
    const E_FUNGIBLE_ASSET_TYPE_MISMATCH: u64 = 20;
    const E_FUNGIBLE_ASSET_AMOUNT_MISMATCH: u64 = 21;
    const E_SIGNATURE_VERIFICATION_REQUIRED_IN_COMMIT_PLUGIN: u64 = 22;
    const E_SIGNATURE_VERIFICATION_NOT_ALLOWED_IN_EXECUTION_PLUGIN: u64 = 23;
    const E_RMN_BLESSING_MISMATCH: u64 = 24;
    const E_INVALID_ON_RAMP_UPDATE: u64 = 25;
    const E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS: u64 = 26;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"OffRamp 1.6.0")
    }

    fun init_module(publisher: &signer) {
        let (state_signer, state_signer_cap) =
            account::create_resource_account(publisher, STATE_SEED);

        move_to(publisher, OffRampDeployment { state_signer_cap });

        if (@ccip_offramp == @ccip) {
            // if we're deployed on the same code object, self-register as an allowed offramp.
            auth::apply_allowed_offramp_updates(
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
        permissionless_execution_threshold_seconds: u32,
        source_chains_selector: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>
    ) acquires OffRampDeployment {
        assert!(
            exists<OffRampDeployment>(@ccip_offramp),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let OffRampDeployment { state_signer_cap } =
            move_from<OffRampDeployment>(@ccip_offramp);

        let state_signer = &account::create_signer_with_capability(&state_signer_cap);

        let ownable_state = ownable::new(state_signer, @ccip_offramp);

        ownable::assert_only_owner(signer::address_of(caller), &ownable_state);

        let state = OffRampState {
            state_signer_cap,
            ownable_state,
            ocr3_base_state: ocr3_base::new(state_signer),
            chain_selector,
            permissionless_execution_threshold_seconds: 0,
            source_chain_configs: smart_table::new(),
            execution_states: smart_table::new(),
            roots: smart_table::new(),
            latest_price_sequence_number: 0,
            static_config_set_events: account::new_event_handle(state_signer),
            dynamic_config_set_events: account::new_event_handle(state_signer),
            source_chain_config_set_events: account::new_event_handle(state_signer),
            skipped_already_executed_events: account::new_event_handle(state_signer),
            execution_state_changed_events: account::new_event_handle(state_signer),
            commit_report_accepted_events: account::new_event_handle(state_signer),
            skipped_report_execution_events: account::new_event_handle(state_signer)
        };

        let static_config = create_static_config(chain_selector);

        event::emit_event(
            &mut state.static_config_set_events,
            StaticConfigSet { static_config }
        );

        set_dynamic_config_internal(
            &mut state, permissionless_execution_threshold_seconds
        );
        apply_source_chain_config_updates_internal(
            &mut state,
            source_chains_selector,
            source_chains_is_enabled,
            source_chains_is_rmn_verification_disabled,
            source_chains_on_ramp
        );

        move_to(state_signer, state);
    }

    public fun assert_source_chain_enabled(
        state: &mut OffRampState, source_chain_selector: u64
    ) {
        // assert that the source chain is enabled.
        assert!(
            state.source_chain_configs.contains(source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_config =
            state.source_chain_configs.borrow(source_chain_selector);
        assert!(
            source_chain_config.is_enabled,
            error::permission_denied(E_SOURCE_CHAIN_NOT_ENABLED)
        );
    }

    // ================================================================
    // |                          Execution                           |
    // ================================================================
    public entry fun execute(
        caller: &signer, report_context: vector<vector<u8>>, report: vector<u8>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        let reports = deserialize_execution_report(report);
        execute_single_report(state, reports, false);
        ocr3_base::transmit(
            &mut state.ocr3_base_state,
            signer::address_of(caller),
            ocr3_base::ocr_plugin_type_execution(),
            report_context,
            report,
            vector::empty()
        )
    }

    public entry fun manually_execute(report_bytes: vector<u8>) acquires OffRampState {
        let state = borrow_state_mut();
        ocr3_base::assert_chain_not_forked(&state.ocr3_base_state);

        let report = deserialize_execution_report(report_bytes);
        execute_single_report(state, report, true);
    }

    #[view]
    public fun get_execution_state(
        source_chain_selector: u64, sequence_number: u64
    ): u8 acquires OffRampState {
        let state = borrow_state();

        assert!(
            state.execution_states.contains(source_chain_selector),
            error::invalid_argument(E_UNKNOWN_SOURCE_CHAIN_SELECTOR)
        );
        let source_chain_execution_states =
            state.execution_states.borrow(source_chain_selector);
        *source_chain_execution_states.borrow_with_default(
            sequence_number, &EXECUTION_STATE_UNTOUCHED
        )
    }

    fun execute_single_report(
        state: &mut OffRampState, execution_report: ExecutionReport, manual_execution: bool
    ) {
        let source_chain_selector = execution_report.source_chain_selector;

        if (rmn_remote::is_cursed_u128(source_chain_selector as u128)) {
            assert!(!manual_execution, error::permission_denied(E_CURSED_BY_RMN));

            event::emit_event(
                &mut state.skipped_report_execution_events,
                SkippedReportExecution { source_chain_selector }
            );
            return
        };

        assert_source_chain_enabled(state, source_chain_selector);
        assert!(
            execution_report.message.header.dest_chain_selector == state.chain_selector,
            error::invalid_argument(E_DEST_CHAIN_SELECTOR_MISMATCH)
        );

        let source_chain_config =
            state.source_chain_configs.borrow(source_chain_selector);
        let metadata_hash =
            calculate_metadata_hash_inlined(
                source_chain_selector,
                state.chain_selector,
                source_chain_config.on_ramp
            );

        let hashed_leaf =
            calculate_message_hash_inlined(&execution_report.message, metadata_hash);

        let root = merkle_proof::merkle_root(hashed_leaf, execution_report.proofs);

        // Reverts when the root is not committed
        // Essential security check
        let is_old_commit_report = is_committed_root(state, root);

        if (manual_execution) {
            assert!(
                is_old_commit_report,
                error::permission_denied(E_MANUAL_EXECUTION_NOT_YET_ENABLED)
            );
        };

        let source_chain_execution_states =
            state.execution_states.borrow_mut(source_chain_selector);

        let message = &execution_report.message;
        let sequence_number = message.header.sequence_number;
        let execution_state_ref =
            source_chain_execution_states.borrow_mut_with_default(
                sequence_number, EXECUTION_STATE_UNTOUCHED
            );

        if (*execution_state_ref != EXECUTION_STATE_UNTOUCHED) {
            event::emit_event(
                &mut state.skipped_already_executed_events,
                SkippedAlreadyExecuted { source_chain_selector, sequence_number }
            );
            return
        };

        // A zero nonce indicates out of order execution which is the only allowed case.
        assert!(
            message.header.nonce == 0,
            error::invalid_argument(E_MUST_BE_OUT_OF_ORDER_EXEC)
        );

        let number_of_tokens_in_msg = message.token_amounts.length();
        assert!(
            number_of_tokens_in_msg == execution_report.offchain_token_data.length(),
            error::invalid_argument(E_TOKEN_DATA_MISMATCH)
        );

        // Execute the message
        execute_single_message(state, message, &execution_report.offchain_token_data);

        // Since Aptos only supports success of reverts, when it reaches this it has succeeded.
        *execution_state_ref = EXECUTION_STATE_SUCCESS;

        event::emit_event(
            &mut state.execution_state_changed_events,
            ExecutionStateChanged {
                source_chain_selector,
                sequence_number,
                message_id: message.header.message_id,
                message_hash: hashed_leaf,
                state: EXECUTION_STATE_SUCCESS
            }
        );
    }

    /// Throws an error if the root is not committed.
    /// Returns true if the root is eligable for manual execution.
    inline fun is_committed_root(
        state: &mut OffRampState, root: vector<u8>
    ): bool {
        assert!(
            state.roots.contains(root),
            error::invalid_argument(E_ROOT_NOT_COMMITTED)
        );
        let timestamp_committed_secs = *state.roots.borrow(root);

        (timestamp::now_seconds() - timestamp_committed_secs)
            > (state.permissionless_execution_threshold_seconds as u64)
    }

    // ================================================================
    // |                            Commit                            |
    // ================================================================
    public entry fun commit(
        caller: &signer,
        report_context: vector<vector<u8>>,
        report: vector<u8>,
        signatures: vector<vector<u8>>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        let commit_report = deserialize_commit_report(report);

        if (commit_report.blessed_merkle_roots.length() > 0) {
            verify_blessed_roots(
                &commit_report.blessed_merkle_roots,
                commit_report.rmn_signatures
            );
        };

        if (commit_report.price_updates.token_price_updates.length() > 0
            || commit_report.price_updates.gas_price_updates.length() > 0) {
            let ocr_sequence_number =
                ocr3_base::deserialize_sequence_bytes(report_context[1]);
            if (state.latest_price_sequence_number < ocr_sequence_number) {
                state.latest_price_sequence_number = ocr_sequence_number;

                let source_tokens = vector[];
                let source_usd_per_token = vector[];
                commit_report.price_updates.token_price_updates.for_each_ref(
                    |token_price_update| {
                        let token_price_update: &TokenPriceUpdate = token_price_update;
                        source_tokens.push_back(token_price_update.source_token);
                        source_usd_per_token.push_back(token_price_update.usd_per_token);
                    }
                );

                let gas_dest_chain_selectors = vector[];
                let gas_usd_per_unit_gas = vector[];
                commit_report.price_updates.gas_price_updates.for_each_ref(
                    |gas_price_update| {
                        let gas_price_update: &GasPriceUpdate = gas_price_update;
                        gas_dest_chain_selectors.push_back(
                            gas_price_update.dest_chain_selector
                        );
                        gas_usd_per_unit_gas.push_back(gas_price_update.usd_per_unit_gas);
                    }
                );

                let state_signer =
                    account::create_signer_with_capability(&state.state_signer_cap);

                fee_quoter::update_prices(
                    &state_signer,
                    source_tokens,
                    source_usd_per_token,
                    gas_dest_chain_selectors,
                    gas_usd_per_unit_gas
                );
            } else {
                // If no non-stale valid price updates are present and the report contains no merkle roots, either
                // blessed or unblesssed, the entire report is stale and should be rejected.
                assert!(
                    commit_report.blessed_merkle_roots.length() > 0
                        || commit_report.unblessed_merkle_roots.length() > 0,
                    error::invalid_argument(E_STALE_COMMIT_REPORT)
                );
            }
        };

        // Commit the roots that do require RMN blessing validation. The blessings are checked at the start of this
        // function.
        commit_merkle_roots(state, commit_report.blessed_merkle_roots, true);
        // Commit the roots that do not require RMN blessing validation.
        commit_merkle_roots(state, commit_report.unblessed_merkle_roots, false);

        event::emit_event(
            &mut state.commit_report_accepted_events,
            CommitReportAccepted {
                blessed_merkle_roots: commit_report.blessed_merkle_roots,
                unblessed_merkle_roots: commit_report.unblessed_merkle_roots,
                price_updates: commit_report.price_updates
            }
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

    inline fun verify_blessed_roots(
        blessed_merkle_roots: &vector<MerkleRoot>, rmn_signatures: vector<vector<u8>>
    ) {
        let merkle_root_source_chains_selector = vector[];
        let merkle_root_on_ramp_addresses = vector[];
        let merkle_root_min_seq_nrs = vector[];
        let merkle_root_max_seq_nrs = vector[];
        let merkle_root_values = vector[];
        blessed_merkle_roots.for_each_ref(
            |merkle_root| {
                let merkle_root: &MerkleRoot = merkle_root;
                merkle_root_source_chains_selector.push_back(
                    merkle_root.source_chain_selector
                );
                merkle_root_on_ramp_addresses.push_back(merkle_root.on_ramp_address);
                merkle_root_min_seq_nrs.push_back(merkle_root.min_seq_nr);
                merkle_root_max_seq_nrs.push_back(merkle_root.max_seq_nr);
                merkle_root_values.push_back(merkle_root.merkle_root);
            }
        );

        rmn_remote::verify(
            @ccip_offramp,
            merkle_root_source_chains_selector,
            merkle_root_on_ramp_addresses,
            merkle_root_min_seq_nrs,
            merkle_root_max_seq_nrs,
            merkle_root_values,
            rmn_signatures
        );
    }

    inline fun commit_merkle_roots(
        state: &mut OffRampState, merkle_roots: vector<MerkleRoot>, is_blessed: bool
    ) {
        merkle_roots.for_each_ref(
            |root| {
                let root: &MerkleRoot = root;
                let source_chain_selector = root.source_chain_selector;

                assert!(
                    !rmn_remote::is_cursed_u128(source_chain_selector as u128),
                    error::permission_denied(E_CURSED_BY_RMN)
                );

                assert_source_chain_enabled(state, source_chain_selector);

                let source_chain_config =
                    state.source_chain_configs.borrow_mut(source_chain_selector);

                // If the root is blessed but RMN blessing is disabled for the source chain, or if the root is not
                // blessed but RMN blessing is enabled, we revert.
                assert!(
                    is_blessed != source_chain_config.is_rmn_verification_disabled,
                    error::invalid_state(E_RMN_BLESSING_MISMATCH)
                );

                assert!(
                    source_chain_config.on_ramp == root.on_ramp_address,
                    error::invalid_argument(E_COMMIT_ON_RAMP_MISMATCH)
                );
                assert!(
                    source_chain_config.min_seq_nr == root.min_seq_nr
                        && root.min_seq_nr <= root.max_seq_nr,
                    error::invalid_argument(E_INVALID_INTERVAL)
                );

                let merkle_root = root.merkle_root;
                assert!(
                    merkle_root.length() == 32 && merkle_root != ZERO_MERKLE_ROOT,
                    error::invalid_argument(E_INVALID_ROOT)
                );

                assert!(
                    !state.roots.contains(merkle_root),
                    error::invalid_argument(E_ROOT_ALREADY_COMMITTED)
                );

                source_chain_config.min_seq_nr = root.max_seq_nr + 1;
                state.roots.add(merkle_root, timestamp::now_seconds());
            }
        );
    }

    #[view]
    public fun get_latest_price_sequence_number(): u64 acquires OffRampState {
        borrow_state().latest_price_sequence_number
    }

    #[view]
    public fun get_merkle_root(root: vector<u8>): u64 acquires OffRampState {
        let state = borrow_state();
        assert!(state.roots.contains(root), error::invalid_argument(E_INVALID_ROOT));

        *state.roots.borrow(root)
    }

    #[view]
    public fun get_source_chain_config(
        source_chain_selector: u64
    ): SourceChainConfig acquires OffRampState {
        let state = borrow_state();
        if (state.source_chain_configs.contains(source_chain_selector)) {
            let source_chain_config =
                state.source_chain_configs.borrow(source_chain_selector);
            *source_chain_config
        } else {
            SourceChainConfig {
                router: @0x0,
                is_enabled: false,
                min_seq_nr: 0,
                is_rmn_verification_disabled: false,
                on_ramp: vector[]
            }
        }
    }

    #[view]
    public fun get_all_source_chain_configs(): (vector<u64>, vector<SourceChainConfig>) acquires OffRampState {
        let state = borrow_state();
        state.source_chain_configs.to_simple_map().to_vec_pair()
    }

    // ================================================================
    // |                           Config                             |
    // ================================================================
    #[view]
    public fun get_static_config(): StaticConfig acquires OffRampState {
        let state = borrow_state();
        create_static_config(state.chain_selector)
    }

    #[view]
    public fun get_dynamic_config(): DynamicConfig acquires OffRampState {
        let state = borrow_state();
        create_dynamic_config(state.permissionless_execution_threshold_seconds)
    }

    public entry fun set_dynamic_config(
        caller: &signer, permissionless_execution_threshold_seconds: u32
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        set_dynamic_config_internal(state, permissionless_execution_threshold_seconds)
    }

    public entry fun apply_source_chain_config_updates(
        caller: &signer,
        source_chains_selector: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        apply_source_chain_config_updates_internal(
            state,
            source_chains_selector,
            source_chains_is_enabled,
            source_chains_is_rmn_verification_disabled,
            source_chains_on_ramp
        )
    }

    inline fun get_state_address_internal(): address {
        account::create_resource_address(&@ccip_offramp, STATE_SEED)
    }

    inline fun borrow_state(): &OffRampState {
        borrow_global<OffRampState>(get_state_address_internal())
    }

    inline fun borrow_state_mut(): &mut OffRampState {
        borrow_global_mut<OffRampState>(get_state_address_internal())
    }

    inline fun execute_single_message(
        state: &mut OffRampState,
        message: &Any2AptosRampMessage,
        message_offchain_token_data: &vector<vector<u8>>
    ) {
        let (local_token_addresses, local_token_amounts) =
            release_or_mint_tokens(
                state,
                &message.token_amounts,
                message_offchain_token_data,
                message.sender,
                message.receiver,
                message.header.source_chain_selector
            );

        // Similar to EVM, we skip calling the receiver if the message data is empty and
        // the gas limit is 0, or if the receiver does not contain a registered receiver
        // module.
        // ref: https://github.com/smartcontractkit/chainlink-ccip/blob/875e982e6437dc126710d8224dd7c792a197bea6/chains/evm/contracts/offRamp/OffRamp.sol#L633

        if ((!message.data.is_empty() || message.gas_limit != 0)
            && receiver_registry::is_registered_receiver(message.receiver)) {
            let state_signer =
                account::create_signer_with_capability(&state.state_signer_cap);

            let dest_token_amounts =
                client::new_dest_token_amounts(
                    local_token_addresses, local_token_amounts
                );

            let any2aptos_message =
                client::new_any2aptos_message(
                    message.header.message_id,
                    message.header.source_chain_selector,
                    message.sender,
                    message.data,
                    dest_token_amounts
                );

            receiver_dispatcher::dispatch_receive(
                &state_signer, message.receiver, any2aptos_message
            )
        };

    }

    // ================================================================
    // |                       Token Handling                         |
    // ================================================================
    inline fun release_or_mint_tokens(
        state: &mut OffRampState,
        token_amounts: &vector<Any2AptosTokenTransfer>,
        message_offchain_token_data: &vector<vector<u8>>,
        sender: vector<u8>,
        receiver: address,
        source_chain_selector: u64
    ): (vector<address>, vector<u64>) {
        // execute_single_report already checks that the vector lengths match.
        let local_token_addresses = vector[];
        let local_token_amounts = vector[];

        token_amounts.zip_ref(
            message_offchain_token_data,
            |token_transfer, current_offchain_token_data| {
                let (token_address, token_amount) =
                    release_or_mint_single_token(
                        state,
                        token_transfer,
                        current_offchain_token_data,
                        sender,
                        receiver,
                        source_chain_selector
                    );
                local_token_addresses.push_back(token_address);
                local_token_amounts.push_back(token_amount);
            }
        );

        (local_token_addresses, local_token_amounts)
    }

    inline fun release_or_mint_single_token(
        state: &mut OffRampState,
        token_transfer: &Any2AptosTokenTransfer,
        current_offchain_token_data: &vector<u8>,
        sender: vector<u8>,
        receiver: address,
        source_chain_selector: u64
    ): (address, u64) {
        let local_token = token_transfer.dest_token_address;
        let token_pool_address = token_admin_registry::get_pool(local_token);
        assert!(token_pool_address != @0x0, error::invalid_state(E_UNSUPPORTED_TOKEN));

        let source_amount = token_transfer.amount;
        let source_pool_data = token_transfer.extra_data;

        let local_token_metadata = object::address_to_object<Metadata>(local_token);
        let before_balance =
            primary_fungible_store::balance(receiver, local_token_metadata);

        let state_signer =
            account::create_signer_with_capability(&state.state_signer_cap);

        let (fa, local_amount) =
            token_admin_dispatcher::dispatch_release_or_mint(
                &state_signer,
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

        let fa_metadata = fungible_asset::asset_metadata(&fa);
        assert!(
            local_token_metadata == fa_metadata,
            error::invalid_state(E_FUNGIBLE_ASSET_TYPE_MISMATCH)
        );

        primary_fungible_store::deposit(receiver, fa);

        let after_balance =
            primary_fungible_store::balance(receiver, local_token_metadata);

        // check that the amount deposited to the user's primary fungible store is exactly `local_amount`
        assert!(
            after_balance >= before_balance
                && (after_balance - before_balance) == local_amount,
            error::invalid_state(E_FUNGIBLE_ASSET_AMOUNT_MISMATCH)
        );

        (local_token, local_amount)
    }

    inline fun set_dynamic_config_internal(
        state: &mut OffRampState, permissionless_execution_threshold_seconds: u32
    ) {
        state.permissionless_execution_threshold_seconds =
            permissionless_execution_threshold_seconds;
        let dynamic_config =
            create_dynamic_config(permissionless_execution_threshold_seconds);
        event::emit_event(
            &mut state.dynamic_config_set_events,
            DynamicConfigSet { dynamic_config }
        );
    }

    inline fun apply_source_chain_config_updates_internal(
        state: &mut OffRampState,
        // pairs of (source chain selector, is enabled)
        source_chains_selector: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>
    ) {
        let source_chains_len = source_chains_selector.length();
        assert!(
            source_chains_len == source_chains_is_enabled.length(),
            error::invalid_argument(E_SOURCE_CHAIN_SELECTORS_MISMATCH)
        );
        assert!(
            source_chains_len == source_chains_is_rmn_verification_disabled.length(),
            error::invalid_argument(E_SOURCE_CHAIN_SELECTORS_MISMATCH)
        );
        assert!(
            source_chains_len == source_chains_on_ramp.length(),
            error::invalid_argument(E_SOURCE_CHAIN_SELECTORS_MISMATCH)
        );
        for (i in 0..source_chains_len) {
            let source_chain_selector = source_chains_selector[i];
            let is_enabled = source_chains_is_enabled[i];
            let is_rmn_verification_disabled =
                source_chains_is_rmn_verification_disabled[i];
            let on_ramp = source_chains_on_ramp[i];

            assert!(
                source_chain_selector != 0,
                error::invalid_argument(E_ZERO_CHAIN_SELECTOR)
            );

            address::assert_non_zero_address_vector(&on_ramp);

            if (!state.source_chain_configs.contains(source_chain_selector)) {
                state.source_chain_configs.add(
                    source_chain_selector,
                    SourceChainConfig {
                        router: @ccip,
                        is_enabled: false,
                        min_seq_nr: 1,
                        is_rmn_verification_disabled: false,
                        on_ramp: vector[]
                    }
                );
                state.execution_states.add(source_chain_selector, smart_table::new());
            } else {
                // OnRamp updates should only happen due to a misconfiguration.
                // If an OnRamp is misconfigured, no reports should have been
                // committed and no messages should have been executed.
                let existing_config =
                    state.source_chain_configs.borrow(source_chain_selector);
                if (existing_config.min_seq_nr != 1
                    && existing_config.on_ramp != on_ramp) {
                    abort error::invalid_argument(E_INVALID_ON_RAMP_UPDATE)
                };
            };

            let config = state.source_chain_configs.borrow_mut(source_chain_selector);
            config.is_enabled = is_enabled;
            config.on_ramp = on_ramp;
            config.is_rmn_verification_disabled = is_rmn_verification_disabled;

            event::emit_event(
                &mut state.source_chain_config_set_events,
                SourceChainConfigSet {
                    source_chain_selector,
                    source_chain_config: *config
                }
            );
        }
    }

    // ================================================================
    // |                        Metadata hash                         |
    // ================================================================
    inline fun calculate_metadata_hash_inlined(
        source_chain_selector: u64, dest_chain_selector: u64, on_ramp: vector<u8>
    ): vector<u8> {
        let packed = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut packed, aptos_hash::keccak256(b"Any2AptosMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_right_padded_bytes32(&mut packed, aptos_hash::keccak256(on_ramp));
        aptos_hash::keccak256(packed)
    }

    #[view]
    public fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64, on_ramp: vector<u8>
    ): vector<u8> {
        calculate_metadata_hash_inlined(
            source_chain_selector, dest_chain_selector, on_ramp
        )
    }

    #[view]
    public fun calculate_message_hash(
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64,
        sender: vector<u8>,
        receiver: address,
        on_ramp: vector<u8>,
        data: vector<u8>,
        gas_limit: u256,
        source_pool_addresses: vector<vector<u8>>,
        dest_token_addresses: vector<address>,
        dest_gas_amounts: vector<u32>,
        extra_datas: vector<vector<u8>>,
        amounts: vector<u256>
    ): vector<u8> {
        let source_pool_addresses_len = source_pool_addresses.length();
        assert!(
            source_pool_addresses_len == dest_token_addresses.length()
                && source_pool_addresses_len == dest_gas_amounts.length()
                && source_pool_addresses_len == extra_datas.length()
                && source_pool_addresses_len == amounts.length(),
            error::invalid_argument(E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS)
        );

        let metadata_hash =
            calculate_metadata_hash_inlined(
                source_chain_selector, dest_chain_selector, on_ramp
            );

        let token_amounts = vector[];
        for (i in 0..source_pool_addresses_len) {
            token_amounts.push_back(
                Any2AptosTokenTransfer {
                    source_pool_address: source_pool_addresses[i],
                    dest_token_address: dest_token_addresses[i],
                    dest_gas_amount: dest_gas_amounts[i],
                    extra_data: extra_datas[i],
                    amount: amounts[i]
                }
            );
        };

        let message = Any2AptosRampMessage {
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
            gas_limit,
            token_amounts
        };

        calculate_message_hash_inlined(&message, metadata_hash)
    }

    inline fun calculate_message_hash_inlined(
        message: &Any2AptosRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let outer_hash = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, merkle_proof::leaf_domain_separator()
        );
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, metadata_hash);

        let inner_hash = vector[];
        eth_abi::encode_right_padded_bytes32(&mut inner_hash, message.header.message_id);
        eth_abi::encode_address(&mut inner_hash, message.receiver);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u256(&mut inner_hash, message.gas_limit);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(inner_hash)
        );

        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.sender)
        );
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(message.data)
        );

        let token_hash = vector[];
        eth_abi::encode_u256(&mut token_hash, message.token_amounts.length() as u256);
        message.token_amounts.for_each_ref(
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
        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, aptos_hash::keccak256(token_hash)
        );

        aptos_hash::keccak256(outer_hash)
    }

    // ================================================================
    // |                       Deserialization                        |
    // ================================================================
    inline fun deserialize_commit_report(report_bytes: vector<u8>): CommitReport {
        let stream = bcs_stream::new(report_bytes);
        let token_price_updates =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    TokenPriceUpdate {
                        source_token: bcs_stream::deserialize_address(stream),
                        usd_per_token: bcs_stream::deserialize_u256(stream)
                    }
                }
            );
        let gas_price_updates =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    GasPriceUpdate {
                        dest_chain_selector: bcs_stream::deserialize_u64(stream),
                        usd_per_unit_gas: bcs_stream::deserialize_u256(stream)
                    }
                }
            );

        let blessed_merkle_roots = parse_merkle_root(&mut stream);
        let unblessed_merkle_roots = parse_merkle_root(&mut stream);

        let rmn_signatures =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    bcs_stream::deserialize_fixed_vector_u8(stream, 64)
                }
            );

        bcs_stream::assert_is_consumed(&stream);

        CommitReport {
            price_updates: PriceUpdates { token_price_updates, gas_price_updates },
            blessed_merkle_roots,
            unblessed_merkle_roots,
            rmn_signatures
        }
    }

    inline fun parse_merkle_root(stream: &mut BCSStream): vector<MerkleRoot> {
        bcs_stream::deserialize_vector(
            stream,
            |stream| {
                MerkleRoot {
                    source_chain_selector: bcs_stream::deserialize_u64(stream),
                    on_ramp_address: bcs_stream::deserialize_vector_u8(stream),
                    min_seq_nr: bcs_stream::deserialize_u64(stream),
                    max_seq_nr: bcs_stream::deserialize_u64(stream),
                    merkle_root: bcs_stream::deserialize_fixed_vector_u8(stream, 32)
                }
            }
        )
    }

    inline fun deserialize_execution_report(report_bytes: vector<u8>): ExecutionReport {
        let stream = bcs_stream::new(report_bytes);

        let source_chain_selector = bcs_stream::deserialize_u64(&mut stream);

        let message_id = bcs_stream::deserialize_fixed_vector_u8(&mut stream, 32);
        let header_source_chain_selector = bcs_stream::deserialize_u64(&mut stream);
        let dest_chain_selector = bcs_stream::deserialize_u64(&mut stream);
        let sequence_number = bcs_stream::deserialize_u64(&mut stream);
        let nonce = bcs_stream::deserialize_u64(&mut stream);

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

        let sender = bcs_stream::deserialize_vector_u8(&mut stream);
        let data = bcs_stream::deserialize_vector_u8(&mut stream);
        let receiver = bcs_stream::deserialize_address(&mut stream);
        let gas_limit = bcs_stream::deserialize_u256(&mut stream);

        let token_amounts =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| {
                    let source_pool_address = bcs_stream::deserialize_vector_u8(stream);
                    let dest_token_address = bcs_stream::deserialize_address(stream);
                    let dest_gas_amount = bcs_stream::deserialize_u32(stream);
                    let extra_data = bcs_stream::deserialize_vector_u8(stream);
                    let amount = bcs_stream::deserialize_u256(stream);

                    Any2AptosTokenTransfer {
                        source_pool_address,
                        dest_token_address,
                        dest_gas_amount,
                        extra_data,
                        amount
                    }
                }
            );

        let message = Any2AptosRampMessage {
            header,
            sender,
            data,
            receiver,
            gas_limit,
            token_amounts
        };

        let offchain_token_data =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );

        let proofs =
            bcs_stream::deserialize_vector(
                &mut stream,
                |stream| bcs_stream::deserialize_fixed_vector_u8(stream, 32)
            );

        bcs_stream::assert_is_consumed(&stream);

        ExecutionReport {
            source_chain_selector,
            message,
            offchain_token_data,
            proofs
        }
    }

    inline fun create_static_config(chain_selector: u64): StaticConfig {
        StaticConfig {
            chain_selector,
            rmn_remote: @ccip,
            token_admin_registry: @ccip,
            nonce_manager: @ccip
        }
    }

    inline fun create_dynamic_config(
        permissionless_execution_threshold_seconds: u32
    ): DynamicConfig {
        DynamicConfig {
            fee_quoter: @ccip,
            permissionless_execution_threshold_seconds
        }
    }

    // ================================================================
    // |                          Ownable                             |
    // ================================================================
    #[view]
    public fun owner(): address acquires OffRampState {
        ownable::owner(&borrow_state().ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires OffRampState {
        ownable::has_pending_transfer(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires OffRampState {
        ownable::pending_transfer_from(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires OffRampState {
        ownable::pending_transfer_to(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires OffRampState {
        ownable::pending_transfer_accepted(&borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires OffRampState {
        let state = borrow_state_mut();
        ownable::execute_ownership_transfer(caller, &mut state.ownable_state, to)
    }

    // ================================================================
    // |                             OCR                              |
    // ================================================================
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
            caller,
            &mut state.ocr3_base_state,
            config_digest,
            ocr_plugin_type,
            big_f,
            is_signature_verification_enabled,
            signers,
            transmitters
        );
        after_ocr3_config_set(state, ocr_plugin_type, is_signature_verification_enabled);
    }

    inline fun after_ocr3_config_set(
        state: &mut OffRampState, ocr_plugin_type: u8, is_signature_verification_enabled: bool
    ) {
        if (ocr_plugin_type == ocr3_base::ocr_plugin_type_commit()) {
            assert!(
                is_signature_verification_enabled,
                error::invalid_argument(
                    E_SIGNATURE_VERIFICATION_REQUIRED_IN_COMMIT_PLUGIN
                )
            );
            state.latest_price_sequence_number = 0;
        } else if (ocr_plugin_type == ocr3_base::ocr_plugin_type_execution()) {
            assert!(
                !is_signature_verification_enabled,
                error::invalid_argument(
                    E_SIGNATURE_VERIFICATION_NOT_ALLOWED_IN_EXECUTION_PLUGIN
                )
            );
        };
    }

    #[view]
    public fun latest_config_details(
        ocr_plugin_type: u8
    ): ocr3_base::OCRConfig acquires OffRampState {
        let state = borrow_state();
        ocr3_base::latest_config_details(&state.ocr3_base_state, ocr_plugin_type)
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): Option<u128> acquires OffRampDeployment, OffRampState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let permissionless_execution_threshold_seconds =
                bcs_stream::deserialize_u32(&mut stream);
            let source_chains_selector =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let source_chains_is_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let source_chains_is_rmn_verification_disabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let source_chains_on_ramp =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            initialize(
                &caller,
                chain_selector,
                permissionless_execution_threshold_seconds,
                source_chains_selector,
                source_chains_is_enabled,
                source_chains_is_rmn_verification_disabled,
                source_chains_on_ramp
            )
        } else if (function_bytes == b"apply_source_chain_config_updates") {
            let source_chains_selector =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let source_chains_is_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let source_chains_is_rmn_verification_disabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let source_chains_on_ramp =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_source_chain_config_updates(
                &caller,
                source_chains_selector,
                source_chains_is_enabled,
                source_chains_is_rmn_verification_disabled,
                source_chains_on_ramp
            )
        } else if (function_bytes == b"set_dynamic_config") {
            let permissionless_execution_threshold_seconds =
                bcs_stream::deserialize_u32(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_dynamic_config(&caller, permissionless_execution_threshold_seconds)
        } else if (function_bytes == b"set_ocr3_config") {
            let config_digest = bcs_stream::deserialize_vector_u8(&mut stream);
            let ocr_plugin_type = bcs_stream::deserialize_u8(&mut stream);
            let big_f = bcs_stream::deserialize_u8(&mut stream);
            let is_signature_verification_enabled =
                bcs_stream::deserialize_bool(&mut stream);
            let signers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            let transmitters =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            set_ocr3_config(
                &caller,
                config_digest,
                ocr_plugin_type,
                big_f,
                is_signature_verification_enabled,
                signers,
                transmitters
            )
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
            publisher, string::utf8(b"offramp"), McmsCallback {}
        );
    }

    // ======================= Getters ==========================
    public fun chain_selector(config: &StaticConfig): u64 {
        config.chain_selector
    }

    public fun permissionless_execution_threshold_seconds(
        config: &DynamicConfig
    ): u32 {
        config.permissionless_execution_threshold_seconds
    }

    public fun is_enabled(config: &SourceChainConfig): bool {
        config.is_enabled
    }

    public fun is_rmn_verification_disabled(config: &SourceChainConfig): bool {
        config.is_rmn_verification_disabled
    }

    // ========================== Test Functions ========================== //
    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun test_register_mcms_entrypoint(publisher: &signer) {
        register_mcms_entrypoint(publisher);
    }

    #[test_only]
    public fun test_execute_single_report(report: ExecutionReport) acquires OffRampState {
        execute_single_report(
            borrow_global_mut<OffRampState>(get_state_address_internal()),
            report,
            false
        );
    }

    #[test_only]
    public fun test_create_execution_report(
        source_chain_selector: u64,
        message: Any2AptosRampMessage,
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>>
    ): ExecutionReport {
        ExecutionReport {
            source_chain_selector,
            message,
            offchain_token_data,
            proofs
        }
    }

    #[test_only]
    public fun test_add_root(root: vector<u8>, timestamp: u64) acquires OffRampState {
        let state = borrow_global_mut<OffRampState>(get_state_address_internal());
        state.roots.add(root, timestamp);
    }

    #[test_only]
    public fun test_deserialize_commit_report(report_bytes: vector<u8>): CommitReport {
        deserialize_commit_report(report_bytes)
    }

    #[test_only]
    public fun test_deserialize_execution_report(
        report_bytes: vector<u8>
    ): ExecutionReport {
        deserialize_execution_report(report_bytes)
    }

    #[test_only]
    public fun test_calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64, onramp: vector<u8>
    ): vector<u8> {
        calculate_metadata_hash_inlined(
            source_chain_selector, dest_chain_selector, onramp
        )
    }

    #[test_only]
    public fun test_calculate_message_hash(
        message: &Any2AptosRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        calculate_message_hash_inlined(message, metadata_hash)
    }

    #[test_only]
    public fun test_create_any2aptos_ramp_message(
        header: RampMessageHeader,
        sender: vector<u8>,
        data: vector<u8>,
        receiver: address,
        gas_limit: u256,
        token_amounts: vector<Any2AptosTokenTransfer>
    ): Any2AptosRampMessage {
        Any2AptosRampMessage {
            header,
            sender,
            data,
            receiver,
            gas_limit,
            token_amounts
        }
    }

    #[test_only]
    public fun test_create_any2aptos_token_transfer(
        source_pool_address: vector<u8>,
        dest_token_address: address,
        dest_gas_amount: u32,
        extra_data: vector<u8>,
        amount: u256
    ): Any2AptosTokenTransfer {
        Any2AptosTokenTransfer {
            source_pool_address,
            dest_token_address,
            dest_gas_amount,
            extra_data,
            amount
        }
    }

    #[test_only]
    public fun test_create_ramp_message_header(
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64
    ): RampMessageHeader {
        RampMessageHeader {
            message_id,
            source_chain_selector,
            dest_chain_selector,
            sequence_number,
            nonce
        }
    }

    #[test_only]
    public fun test_create_merkle_root(
        source_chain_selector: u64,
        on_ramp_address: vector<u8>,
        min_seq_nr: u64,
        max_seq_nr: u64,
        merkle_root: vector<u8>
    ): MerkleRoot {
        MerkleRoot {
            source_chain_selector,
            on_ramp_address,
            min_seq_nr,
            max_seq_nr,
            merkle_root
        }
    }

    #[test_only]
    public fun message(report: &ExecutionReport): &Any2AptosRampMessage {
        &report.message
    }

    #[test_only]
    public fun sender(message: &Any2AptosRampMessage): vector<u8> {
        message.sender
    }

    #[test_only]
    public fun data(message: &Any2AptosRampMessage): vector<u8> {
        message.data
    }

    #[test_only]
    public fun receiver(message: &Any2AptosRampMessage): address {
        message.receiver
    }

    #[test_only]
    public fun gas_limit(message: &Any2AptosRampMessage): u256 {
        message.gas_limit
    }

    #[test_only]
    public fun header(message: &Any2AptosRampMessage): &RampMessageHeader {
        &message.header
    }

    #[test_only]
    public fun header_source_chain_selector(header: &RampMessageHeader): u64 {
        header.source_chain_selector
    }

    #[test_only]
    public fun header_dest_chain_selector(header: &RampMessageHeader): u64 {
        header.dest_chain_selector
    }

    #[test_only]
    public fun header_message_id(header: &RampMessageHeader): vector<u8> {
        header.message_id
    }

    #[test_only]
    public fun sequence_number(header: &RampMessageHeader): u64 {
        header.sequence_number
    }

    #[test_only]
    public fun nonce(header: &RampMessageHeader): u64 {
        header.nonce
    }

    #[test_only]
    public fun token_amounts(message: &Any2AptosRampMessage)
        : &vector<Any2AptosTokenTransfer> {
        &message.token_amounts
    }

    #[test_only]
    public fun commit_report_price_updates(report: &CommitReport): &PriceUpdates {
        &report.price_updates
    }

    #[test_only]
    public fun commit_report_blessed_merkle_roots(report: &CommitReport)
        : &vector<MerkleRoot> {
        &report.blessed_merkle_roots
    }

    #[test_only]
    public fun commit_report_unblessed_merkle_roots(
        report: &CommitReport
    ): &vector<MerkleRoot> {
        &report.unblessed_merkle_roots
    }

    #[test_only]
    public fun commit_report_rmn_signatures(report: &CommitReport): &vector<vector<u8>> {
        &report.rmn_signatures
    }

    #[test_only]
    public fun price_updates_token_price_updates(
        updates: &PriceUpdates
    ): &vector<TokenPriceUpdate> {
        &updates.token_price_updates
    }

    #[test_only]
    public fun price_updates_gas_price_updates(updates: &PriceUpdates)
        : &vector<GasPriceUpdate> {
        &updates.gas_price_updates
    }

    #[test_only]
    public fun token_price_update_source_token(
        update: &TokenPriceUpdate
    ): address {
        update.source_token
    }

    #[test_only]
    public fun token_price_update_usd_per_token(
        update: &TokenPriceUpdate
    ): u256 {
        update.usd_per_token
    }

    #[test_only]
    public fun merkle_root_source_chain_selector(root: &MerkleRoot): u64 {
        root.source_chain_selector
    }

    #[test_only]
    public fun merkle_root_on_ramp_address(root: &MerkleRoot): vector<u8> {
        root.on_ramp_address
    }

    #[test_only]
    public fun merkle_root_min_seq_nr(root: &MerkleRoot): u64 {
        root.min_seq_nr
    }

    #[test_only]
    public fun merkle_root_max_seq_nr(root: &MerkleRoot): u64 {
        root.max_seq_nr
    }

    #[test_only]
    public fun merkle_root_merkle_root(root: &MerkleRoot): vector<u8> {
        root.merkle_root
    }

    #[test_only]
    public fun source_chain_config_on_ramp(config: &SourceChainConfig): vector<u8> {
        config.on_ramp
    }
}
