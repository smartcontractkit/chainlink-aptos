/// The OffRamp package handles merkle root commitments and message execution.
/// Future versions of this contract will be deployed as a separate package to avoid any unwanted side effects
/// during upgrades.
module ccip_offramp::offramp {
    use std::ascii;
    use std::type_name;

    use sui::address;
    use sui::clock;
    use sui::event;
    use sui::hash;
    use std::string::{Self, String};
    use std::u256;
    use sui::table::{Self, Table};
    use sui::vec_map::{Self, VecMap};

    use ccip::client;
    use ccip::offramp_state_helper as osh;
    use ccip::eth_abi;
    use ccip::fee_quoter::{Self, FeeQuoterCap};
    use ccip::merkle_proof;
    use ccip::receiver_registry;
    use ccip::token_admin_registry;
    use ccip::rmn_remote;
    use ccip::state_object::CCIPObjectRef;

    use ccip_offramp::ocr3_base::{Self, OCR3BaseState, OCRConfig};

    use mcms::bcs_stream::{Self, BCSStream};

    public struct OwnerCap has key, store {
        id: UID
    }

    public struct OffRampState has key, store {
        id: UID,
        ocr3_base_state: OCR3BaseState,

        // static config
        chain_selector: u64,

        // dynamic config
        permissionless_execution_threshold_seconds: u32,

        // source chain selector -> config
        source_chain_configs: VecMap<u64, SourceChainConfig>,
        // source chain selector -> seq num -> execution state
        execution_states: Table<u64, Table<u64, u8>>,

        // merkle root -> timestamp in secs
        roots: Table<vector<u8>, u64>,
        // This is the OCR sequence number, not to be confused with the CCIP message sequence number.
        latest_price_sequence_number: u64,
        fee_quoter_cap: Option<FeeQuoterCap>,
        dest_transfer_cap: Option<osh::DestTransferCap>,
    }

    public struct OffRampStatePointer has key, store {
        id: UID,
        off_ramp_state_id: address,
        owner_cap_id: address,
    }

    public struct SourceChainConfig has store, drop, copy {
        router: address,
        is_enabled: bool,
        min_seq_nr: u64,
        is_rmn_verification_disabled: bool,
        on_ramp: vector<u8>
    }

    // report public structs
    public struct RampMessageHeader has drop {
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64
    }

    public struct Any2SuiRampMessage has drop {
        header: RampMessageHeader,
        sender: vector<u8>,
        data: vector<u8>,
        receiver: address,
        gas_limit: u256,
        token_amounts: vector<Any2SuiTokenTransfer>
    }

    public struct Any2SuiTokenTransfer has drop {
        source_pool_address: vector<u8>,
        dest_token_address: address, // this is the coin metadata address
        dest_gas_amount: u32,
        extra_data: vector<u8>,

        amount: u256 // This is the amount to transfer, as set on the source chain.
    }

    public struct ExecutionReport has drop {
        source_chain_selector: u64,
        message: Any2SuiRampMessage,
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>>, // Proofs used to construct the merkle root
    }

    // Matches the EVM public struct
    public struct CommitReport has store, drop, copy {
        price_updates: PriceUpdates, // Price updates for the fee_quoter
        blessed_merkle_roots: vector<MerkleRoot>, // Merkle roots that have been blessed by RMN
        unblessed_merkle_roots: vector<MerkleRoot>, // Merkle roots that don't require RMN blessing
        rmn_signatures: vector<vector<u8>> // The signatures for the blessed merkle roots
    }

    public struct PriceUpdates has store, drop, copy {
        token_price_updates: vector<TokenPriceUpdate>,
        gas_price_updates: vector<GasPriceUpdate>
    }

    public struct TokenPriceUpdate has store, drop, copy {
        source_token: address,
        usd_per_token: u256
    }

    public struct GasPriceUpdate has store, drop, copy {
        dest_chain_selector: u64,
        usd_per_unit_gas: u256
    }

    public struct MerkleRoot has store, drop, copy {
        source_chain_selector: u64,
        on_ramp_address: vector<u8>,
        min_seq_nr: u64,
        max_seq_nr: u64,
        merkle_root: vector<u8>
    }

    public struct StaticConfig has store, drop, copy {
        chain_selector: u64,
        rmn_remote: address,
        token_admin_registry: address,
        nonce_manager: address
    }

    // On EVM, the feeQuoter is a dynamic address but due to the Sui implementation using a static
    // upgradable FeeQuoter stored within the state ref, this value is actually static and cannot be
    // accessed by its object id/address directly by users.
    // For compatibility reasons, we keep it as a dynamic config.
    public struct DynamicConfig has store, drop, copy {
        fee_quoter: address,
        permissionless_execution_threshold_seconds: u32 // The delay before manual exec is enabled
    }

    public struct StaticConfigSet has copy, drop {
        chain_selector: u64
    }

    public struct DynamicConfigSet has copy, drop {
        dynamic_config: DynamicConfig
    }

    public struct SourceChainConfigSet has copy, drop {
        source_chain_selector: u64,
        source_chain_config: SourceChainConfig
    }

    public struct SkippedAlreadyExecuted has copy, drop {
        source_chain_selector: u64,
        sequence_number: u64
    }

    public struct ExecutionStateChanged has copy, drop {
        source_chain_selector: u64,
        sequence_number: u64,
        message_id: vector<u8>,
        message_hash: vector<u8>,
        state: u8
    }

    public struct CommitReportAccepted has copy, drop {
        blessed_merkle_roots: vector<MerkleRoot>,
        unblessed_merkle_roots: vector<MerkleRoot>,
        price_updates: PriceUpdates
    }

    public struct SkippedReportExecution has copy, drop {
        source_chain_selector: u64
    }

    // These have to match the EVM states
    const EXECUTION_STATE_UNTOUCHED: u8 = 0;
    // const EXECUTION_STATE_IN_PROGRESS: u8 = 1;
    const EXECUTION_STATE_SUCCESS: u8 = 2;
    // const EXECUTION_STATE_FAILURE: u8 = 3;

    const ZERO_MERKLE_ROOT: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ];
    const E_SOURCE_CHAIN_SELECTORS_MISMATCH: u64 = 1;
    const E_ZERO_CHAIN_SELECTOR: u64 = 2;
    const E_UNKNOWN_SOURCE_CHAIN_SELECTOR: u64 = 3;
    const E_MUST_BE_OUT_OF_ORDER_EXEC: u64 = 4;
    const E_SOURCE_CHAIN_SELECTOR_MISMATCH: u64 = 5;
    const E_DEST_CHAIN_SELECTOR_MISMATCH: u64 = 6;
    const E_TOKEN_DATA_MISMATCH: u64 = 7;
    const E_ROOT_NOT_COMMITTED: u64 = 8;
    const E_MANUAL_EXECUTION_NOT_YET_ENABLED: u64 = 9;
    const E_SOURCE_CHAIN_NOT_ENABLED: u64 = 10;
    const E_COMMIT_ON_RAMP_MISMATCH: u64 = 11;
    const E_INVALID_INTERVAL: u64 = 12;
    const E_INVALID_ROOT: u64 = 13;
    const E_ROOT_ALREADY_COMMITTED: u64 = 14;
    const E_STALE_COMMIT_REPORT: u64 = 15;
    const E_CURSED_BY_RMN: u64 = 16;
    const E_SIGNATURE_VERIFICATION_REQUIRED_IN_COMMIT_PLUGIN: u64 = 17;
    const E_SIGNATURE_VERIFICATION_NOT_ALLOWED_IN_EXECUTION_PLUGIN: u64 = 18;
    const E_FEE_QUOTER_CAP_EXISTS: u64 = 19;
    const E_TOKEN_AMOUNT_OVERFLOW: u64 = 20;
    const E_DEST_TRANSFER_CAP_EXISTS: u64 = 21;
    const E_RMN_BLESSING_MISMATCH: u64 = 22;
    const E_UNSUPPORTED_TOKEN: u64 = 23;
    const E_INVALID_ON_RAMP_UPDATE: u64 = 24;
    const E_DEST_TRANSFER_CAP_NOT_SET: u64 = 25;

    public fun type_and_version(): String {
        string::utf8(b"OffRamp 1.6.0")
    }

    public struct OFFRAMP has drop {}

    fun init(_witness: OFFRAMP, ctx: &mut TxContext) {
        let owner_cap = OwnerCap {
            id: object::new(ctx)
        };

        let state = OffRampState {
            id: object::new(ctx),
            ocr3_base_state: ocr3_base::new(ctx),
            chain_selector: 0,
            permissionless_execution_threshold_seconds: 0,
            source_chain_configs: vec_map::empty<u64, SourceChainConfig>(),
            execution_states: table::new(ctx),
            roots: table::new(ctx),
            latest_price_sequence_number: 0,
            fee_quoter_cap: option::none(),
            dest_transfer_cap: option::none(),
        };

        let pointer = OffRampStatePointer {
            id: object::new(ctx),
            off_ramp_state_id: object::id_to_address(object::borrow_id(&state)),
            owner_cap_id: object::id_to_address(object::borrow_id(&owner_cap)),
        };

        let tn = type_name::get_with_original_ids<OFFRAMP>();
        let package_bytes = ascii::into_bytes(tn.get_address());
        let package_id = address::from_ascii_bytes(&package_bytes);

        transfer::share_object(state);
        transfer::transfer(owner_cap, ctx.sender());
        transfer::transfer(pointer, package_id);
    }

    public fun initialize(
        state: &mut OffRampState,
        _: &OwnerCap,
        fee_quoter_cap: FeeQuoterCap,
        dest_transfer_cap: osh::DestTransferCap,
        chain_selector: u64,
        permissionless_execution_threshold_seconds: u32,
        source_chains_selectors: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        state.chain_selector = chain_selector;

        assert!(
            state.fee_quoter_cap.is_none(),
            E_FEE_QUOTER_CAP_EXISTS
        );
        state.fee_quoter_cap.fill(fee_quoter_cap);
        assert!(
            state.dest_transfer_cap.is_none(),
            E_DEST_TRANSFER_CAP_EXISTS
        );
        state.dest_transfer_cap.fill(dest_transfer_cap);

        event::emit(StaticConfigSet { chain_selector });

        set_dynamic_config_internal(
            state,
            permissionless_execution_threshold_seconds
        );
        apply_source_chain_config_updates_internal(
            state,
            source_chains_selectors,
            source_chains_is_enabled,
            source_chains_is_rmn_verification_disabled,
            source_chains_on_ramp,
            ctx
        );
    }

    public fun get_ocr3_base(state: &OffRampState): &OCR3BaseState {
        &state.ocr3_base_state
    }

    fun set_dynamic_config_internal(
        state: &mut OffRampState, permissionless_execution_threshold_seconds: u32
    ) {
        state.permissionless_execution_threshold_seconds =
            permissionless_execution_threshold_seconds;
        let dynamic_config =
            create_dynamic_config(permissionless_execution_threshold_seconds);
        event::emit(DynamicConfigSet { dynamic_config });
    }

    fun create_dynamic_config(
        permissionless_execution_threshold_seconds: u32
    ): DynamicConfig {
        DynamicConfig { fee_quoter: @ccip, permissionless_execution_threshold_seconds }
    }

    fun apply_source_chain_config_updates_internal(
        state: &mut OffRampState,
        source_chains_selector: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        let source_chains_len = source_chains_selector.length();
        assert!(
            source_chains_len == source_chains_is_enabled.length(),
            E_SOURCE_CHAIN_SELECTORS_MISMATCH
        );
        assert!(
            source_chains_len == source_chains_is_rmn_verification_disabled.length(),
            E_SOURCE_CHAIN_SELECTORS_MISMATCH
        );
        assert!(
            source_chains_len == source_chains_on_ramp.length(),
            E_SOURCE_CHAIN_SELECTORS_MISMATCH
        );

        let mut i = 0;
        while (i < source_chains_len) {
            let source_chain_selector = source_chains_selector[i];
            let is_enabled = source_chains_is_enabled[i];
            let is_rmn_verification_disabled = source_chains_is_rmn_verification_disabled[i];
            let on_ramp = source_chains_on_ramp[i];

            assert!(source_chain_selector != 0, E_ZERO_CHAIN_SELECTOR);
            ccip::address::assert_non_zero_address_vector(&on_ramp);

            if (state.source_chain_configs.contains(&source_chain_selector)) {
                // OnRamp updates should only happen due to a misconfiguration.
                // If an OnRamp is misconfigured, no reports should have been
                // committed and no messages should have been executed.
                let existing_config =
                    state.source_chain_configs.get(&source_chain_selector);
                assert!(
                    existing_config.min_seq_nr == 1 || existing_config.on_ramp == on_ramp,
                    E_INVALID_ON_RAMP_UPDATE
                );
            } else {
                state.source_chain_configs.insert(
                    source_chain_selector,
                    SourceChainConfig {
                        router: @ccip,
                        is_enabled: false,
                        min_seq_nr: 1,
                        is_rmn_verification_disabled: false,
                        on_ramp: vector[]
                    }
                );
                state.execution_states.add(source_chain_selector, table::new(ctx));
            };

            let config = state.source_chain_configs.get_mut(&source_chain_selector);
            config.is_enabled = is_enabled;
            config.on_ramp = on_ramp;
            config.is_rmn_verification_disabled = is_rmn_verification_disabled;

            event::emit(
                SourceChainConfigSet { source_chain_selector, source_chain_config: *config }
            );
            i = i + 1;
        }
    }

    fun assert_source_chain_enabled(
        state: &OffRampState, source_chain_selector: u64
    ) {
        // assert that the source chain is enabled.
        assert!(
            state.source_chain_configs.contains(&source_chain_selector),
            E_UNKNOWN_SOURCE_CHAIN_SELECTOR
        );
        let source_chain_config = state.source_chain_configs.get(&source_chain_selector);
        assert!(
            source_chain_config.is_enabled,
            E_SOURCE_CHAIN_NOT_ENABLED
        );
    }

    // ================================================================
    // |                          Execution                           |
    // ================================================================

    public fun init_execute(
        ref: &CCIPObjectRef,
        state: &mut OffRampState,
        clock: &clock::Clock,
        report_context: vector<vector<u8>>,
        report: vector<u8>,
        ctx: &mut TxContext
    ): osh::ReceiverParams {
        let reports = deserialize_execution_report(report);

        ocr3_base::transmit(
            &state.ocr3_base_state,
            ctx.sender(),
            ocr3_base::ocr_plugin_type_execution(),
            report_context,
            report,
            vector[],
            ctx
        );

        pre_execute_single_report(ref, state, clock, reports, false)
    }

    public fun finish_execute(
        state: &mut OffRampState,
        receiver_params: osh::ReceiverParams,
    ) {
        assert!(state.dest_transfer_cap.is_some(), E_DEST_TRANSFER_CAP_NOT_SET);
        osh::deconstruct_receiver_params(state.dest_transfer_cap.borrow(), receiver_params);
    }

    // this function does not involve ocr3 transmit & it sets manual_execution to true
    public fun manually_init_execute(
        ref: &CCIPObjectRef,
        state: &mut OffRampState,
        clock: &clock::Clock,
        report_bytes: vector<u8>
    ): osh::ReceiverParams {
        let reports = deserialize_execution_report(report_bytes);

        pre_execute_single_report(ref, state, clock, reports, true)
    }

    public fun get_execution_state(
        state: &OffRampState, source_chain_selector: u64, sequence_number: u64
    ): u8 {
        assert!(
            state.execution_states.contains(source_chain_selector),
            E_UNKNOWN_SOURCE_CHAIN_SELECTOR
        );
        let source_chain_execution_states =
            state.execution_states.borrow(source_chain_selector);
        let execution_state = source_chain_execution_states.borrow(sequence_number);
        *execution_state
    }

    fun deserialize_execution_report(report_bytes: vector<u8>): ExecutionReport {
        let mut stream = bcs_stream::new(report_bytes);
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
            E_SOURCE_CHAIN_SELECTOR_MISMATCH
        );

        let sender = bcs_stream::deserialize_vector_u8(&mut stream);
        let data = bcs_stream::deserialize_vector_u8(&mut stream);
        let receiver = bcs_stream::deserialize_address(&mut stream);
        let gas_limit = bcs_stream::deserialize_u256(&mut stream);

        let token_amounts =
            bcs_stream::deserialize_vector!(
                &mut stream,
                |stream| {
                    let source_pool_address = bcs_stream::deserialize_vector_u8(stream);
                    let dest_token_address = bcs_stream::deserialize_address(stream);
                    let dest_gas_amount = bcs_stream::deserialize_u32(stream);
                    let extra_data = bcs_stream::deserialize_vector_u8(stream);
                    let amount = bcs_stream::deserialize_u256(stream);

                    Any2SuiTokenTransfer {
                        source_pool_address,
                        dest_token_address,
                        dest_gas_amount,
                        extra_data,
                        amount
                    }
                }
            );

        let message = Any2SuiRampMessage {
            header,
            sender,
            data,
            receiver,
            gas_limit,
            token_amounts
        };

        let offchain_token_data =
            bcs_stream::deserialize_vector!(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );

        let proofs =
            bcs_stream::deserialize_vector!(
                &mut stream,
                |stream| bcs_stream::deserialize_fixed_vector_u8(stream, 32)
            );

        ExecutionReport { source_chain_selector, message, offchain_token_data, proofs }
    }

    #[allow(implicit_const_copy)]
    fun pre_execute_single_report(
        ref: &CCIPObjectRef,
        state: &mut OffRampState,
        clock: &clock::Clock,
        execution_report: ExecutionReport,
        manual_execution: bool
    ): osh::ReceiverParams {
        let source_chain_selector = execution_report.source_chain_selector;

        if (rmn_remote::is_cursed_u128(ref, source_chain_selector as u128)) {
            assert!(!manual_execution, E_CURSED_BY_RMN);

            event::emit(SkippedReportExecution { source_chain_selector });

            return osh::create_receiver_params(state.dest_transfer_cap.borrow(), source_chain_selector)
        };

        assert_source_chain_enabled(state, source_chain_selector);

        assert!(
            execution_report.message.header.dest_chain_selector == state.chain_selector,
            E_DEST_CHAIN_SELECTOR_MISMATCH
        );

        let source_chain_config = state.source_chain_configs[&source_chain_selector];
        let metadata_hash =
            calculate_metadata_hash(
                source_chain_selector,
                state.chain_selector,
                source_chain_config.on_ramp
            );

        let hashed_leaf = calculate_message_hash(
            &execution_report.message, metadata_hash
        );

        let root = merkle_proof::merkle_root_simple(hashed_leaf, execution_report.proofs);

        // Reverts when the root is not committed
        // Essential security check
        let is_old_commit_report = is_committed_root(state, clock, root);

        if (manual_execution) {
            assert!(is_old_commit_report, E_MANUAL_EXECUTION_NOT_YET_ENABLED);
        };

        let source_chain_execution_states =
            table::borrow_mut(&mut state.execution_states, source_chain_selector);

        let message = &execution_report.message;
        let sequence_number = message.header.sequence_number;
        let execution_state_ref =
            if (source_chain_execution_states.contains(sequence_number)) {
                table::borrow_mut(source_chain_execution_states, sequence_number)
            } else {
                &mut EXECUTION_STATE_UNTOUCHED
            };

        if (*execution_state_ref != EXECUTION_STATE_UNTOUCHED) {
            event::emit(SkippedAlreadyExecuted { source_chain_selector, sequence_number });

            return osh::create_receiver_params(state.dest_transfer_cap.borrow(), source_chain_selector)
        };

        // A zero nonce indicates out of order execution which is the only allowed case.
        assert!(message.header.nonce == 0, E_MUST_BE_OUT_OF_ORDER_EXEC);

        let number_of_tokens_in_msg = message.token_amounts.length();
        assert!(
            number_of_tokens_in_msg == execution_report.offchain_token_data.length(),
            E_TOKEN_DATA_MISMATCH
        );
        assert!(state.dest_transfer_cap.is_some(), E_DEST_TRANSFER_CAP_NOT_SET);

        let mut i = 0;
        let mut receiver_params = osh::create_receiver_params(state.dest_transfer_cap.borrow(), source_chain_selector);

        let mut token_addresses = vector[];
        let mut token_amounts = vector[];

        while (i < number_of_tokens_in_msg) {
            let token_pool_address: address = token_admin_registry::get_pool(ref, message.token_amounts[i].dest_token_address);
            assert!(token_pool_address != @0x0, E_UNSUPPORTED_TOKEN);
            let mut amount_op = u256::try_as_u64(message.token_amounts[i].amount);
            assert!(
                amount_op.is_some(),
                E_TOKEN_AMOUNT_OVERFLOW
            );
            let amount = amount_op.extract();

            osh::add_dest_token_transfer(
                state.dest_transfer_cap.borrow(),
                &mut receiver_params,
                message.receiver,
                amount,
                message.token_amounts[i].dest_token_address,
                token_pool_address,
                message.token_amounts[i].source_pool_address,
                message.token_amounts[i].extra_data,
                execution_report.offchain_token_data[i],
            );
            token_addresses.push_back(message.token_amounts[i].dest_token_address);
            token_amounts.push_back(amount);
            i = i + 1;
        };

        // if the message has data or gas limit, and the receiver is registered,
        // fill the any2sui message for the receiver to execute
        if ((!message.data.is_empty() || message.gas_limit != 0) &&
            receiver_registry::is_registered_receiver(ref, message.receiver)) {
            let dest_token_amounts =
                client::new_dest_token_amounts(token_addresses, token_amounts);
            let any2sui_message =
                client::new_any2sui_message(
                    message.header.message_id,
                    message.header.source_chain_selector,
                    message.sender,
                    message.data,
                    dest_token_amounts,
                );

            osh::populate_message(state.dest_transfer_cap.borrow(), &mut receiver_params, any2sui_message);
        };

        // the entire PTB either succeeds or fails so we can set the state to success
        *execution_state_ref = EXECUTION_STATE_SUCCESS;

        event::emit(
            ExecutionStateChanged {
                source_chain_selector,
                sequence_number,
                message_id: message.header.message_id,
                message_hash: hashed_leaf,
                state: EXECUTION_STATE_SUCCESS
            }
        );

        // return the hot potato to user/execution DON
        receiver_params
    }

    /// Throws an error if the root is not committed.
    /// Returns true if the root is eligable for manual execution.
    fun is_committed_root(
        state: &OffRampState, clock: &clock::Clock, root: vector<u8>
    ): bool {
        assert!(state.roots.contains(root), E_ROOT_NOT_COMMITTED);
        let timestamp_committed_secs = state.roots[root];

        (clock.timestamp_ms() / 1000 - timestamp_committed_secs)
            > (state.permissionless_execution_threshold_seconds as u64)
    }

    // ================================================================
    // |                        Metadata hash                         |
    // ================================================================

    fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64, on_ramp: vector<u8>
    ): vector<u8> {
        let mut packed = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut packed, hash::keccak256(&b"Any2SuiMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_right_padded_bytes32(&mut packed, hash::keccak256(&on_ramp));
        hash::keccak256(&packed)
    }

    fun calculate_message_hash(
        message: &Any2SuiRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let mut outer_hash = vector[];
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, merkle_proof::leaf_domain_separator());
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, metadata_hash);

        let mut inner_hash = vector[];
        eth_abi::encode_right_padded_bytes32(&mut inner_hash, message.header.message_id);
        eth_abi::encode_address(&mut inner_hash, message.receiver);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u256(&mut inner_hash, message.gas_limit);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&inner_hash));

        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&message.sender));
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&message.data));

        let mut token_hash = vector[];
        eth_abi::encode_u256(
            &mut token_hash, message.token_amounts.length() as u256
        );
        message.token_amounts.do_ref!(
            |token_transfer| {
                let token_transfer: &Any2SuiTokenTransfer = token_transfer;
                eth_abi::encode_bytes(&mut token_hash, token_transfer.source_pool_address);
                eth_abi::encode_address(&mut token_hash, token_transfer.dest_token_address);
                eth_abi::encode_u32(&mut token_hash, token_transfer.dest_gas_amount);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.extra_data);
                eth_abi::encode_u256(&mut token_hash, token_transfer.amount);
            }
        );
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&token_hash));

        hash::keccak256(&outer_hash)
    }

    // ================================================================
    // |                       Deserialization                        |
    // ================================================================

    fun deserialize_commit_report(report_bytes: vector<u8>): CommitReport {
        let mut stream = bcs_stream::new(report_bytes);
        let token_price_updates =
            bcs_stream::deserialize_vector!(
                &mut stream,
                |stream| {
                    TokenPriceUpdate {
                        source_token: bcs_stream::deserialize_address(stream),
                        usd_per_token: bcs_stream::deserialize_u256(stream)
                    }
                }
            );

        let gas_price_updates =
            bcs_stream::deserialize_vector!(
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
            bcs_stream::deserialize_vector!(
                &mut stream,
                |stream| { bcs_stream::deserialize_fixed_vector_u8(stream, 64) }
            );

        bcs_stream::assert_is_consumed(&stream);

        CommitReport {
            price_updates: PriceUpdates { token_price_updates, gas_price_updates },
            blessed_merkle_roots,
            unblessed_merkle_roots,
            rmn_signatures
        }
    }

    fun parse_merkle_root(stream: &mut BCSStream): vector<MerkleRoot> {
        bcs_stream::deserialize_vector!(
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

    // ================================================================
    // |                             OCR                              |
    // ================================================================

    public fun set_ocr3_config(
        state: &mut OffRampState,
        _: &OwnerCap,
        config_digest: vector<u8>,
        ocr_plugin_type: u8,
        big_f: u8,
        is_signature_verification_enabled: bool,
        signers: vector<vector<u8>>,
        transmitters: vector<address>
    ) {
        ocr3_base::set_ocr3_config(
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

    fun after_ocr3_config_set(
        state: &mut OffRampState,
        ocr_plugin_type: u8,
        is_signature_verification_enabled: bool
    ) {
        if (ocr_plugin_type == ocr3_base::ocr_plugin_type_commit()) {
            assert!(
                is_signature_verification_enabled,
                E_SIGNATURE_VERIFICATION_REQUIRED_IN_COMMIT_PLUGIN
            );
            state.latest_price_sequence_number = 0;
        } else if (ocr_plugin_type == ocr3_base::ocr_plugin_type_execution()) {
            assert!(
                !is_signature_verification_enabled,
                E_SIGNATURE_VERIFICATION_NOT_ALLOWED_IN_EXECUTION_PLUGIN
            );
        };
    }

    public fun latest_config_details(
        state: &OffRampState, ocr_plugin_type: u8
    ): OCRConfig {
        ocr3_base::latest_config_details(&state.ocr3_base_state, ocr_plugin_type)
    }

    public fun latest_config_digest_fields(
        cfg: OCRConfig,
    ): (vector<u8>, u8, u8, bool, vector<vector<u8>>, vector<address>) {
        ocr3_base::latest_config_details_fields(cfg)
    }

    // ================================================================
    // |                            Commit                            |
    // ================================================================

    public fun commit(
        ref: &mut CCIPObjectRef,
        state: &mut OffRampState,
        clock: &clock::Clock,
        report_context: vector<vector<u8>>,
        report: vector<u8>,
        signatures: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        let commit_report = deserialize_commit_report(report);

        if (commit_report.blessed_merkle_roots.length() > 0) {
            verify_blessed_roots(
                ref,
                object::id_to_address(&object::id(state)),
                &commit_report.blessed_merkle_roots,
                commit_report.rmn_signatures,
            );
        };

        if (commit_report.price_updates.token_price_updates.length() > 0
            || commit_report.price_updates.gas_price_updates.length() > 0) {
            let ocr_sequence_number =
                ocr3_base::deserialize_sequence_bytes(report_context[1]);
            if (state.latest_price_sequence_number < ocr_sequence_number) {
                state.latest_price_sequence_number = ocr_sequence_number;

                let mut source_tokens = vector[];
                let mut source_usd_per_token = vector[];

                commit_report.price_updates.token_price_updates.do_ref!(
                    |token_price_update| {
                        source_tokens.push_back(
                            token_price_update.source_token
                        );
                        source_usd_per_token.push_back(
                            token_price_update.usd_per_token
                        );
                    }
                );

                let mut gas_dest_chain_selectors = vector[];
                let mut gas_usd_per_unit_gas = vector[];
                commit_report.price_updates.gas_price_updates.do_ref!(
                    |gas_price_update| {
                        gas_dest_chain_selectors.push_back(
                            gas_price_update.dest_chain_selector
                        );
                        gas_usd_per_unit_gas.push_back(
                            gas_price_update.usd_per_unit_gas
                        );
                    }
                );

                fee_quoter::update_prices(
                    ref,
                    state.fee_quoter_cap.borrow(),
                    clock,
                    source_tokens,
                    source_usd_per_token,
                    gas_dest_chain_selectors,
                    gas_usd_per_unit_gas,
                );
            } else {
                // If no non-stale valid price updates are present and the report contains no merkle roots,
                // either blessed or unblesssed, the entire report is stale and should be rejected.
                assert!(
                    commit_report.blessed_merkle_roots.length() > 0
                        || commit_report.unblessed_merkle_roots.length() > 0,
                    E_STALE_COMMIT_REPORT
                );
            };
        };

        // Commit the roots that do require RMN blessing validation.
        // The blessings are checked at the start of this function.
        commit_merkle_roots(ref, state, clock, commit_report.blessed_merkle_roots, true);
        // Commit the roots that do not require RMN blessing validation.
        commit_merkle_roots(ref, state, clock, commit_report.unblessed_merkle_roots, false);

        event::emit(
            CommitReportAccepted {
                blessed_merkle_roots: commit_report.blessed_merkle_roots,
                unblessed_merkle_roots: commit_report.unblessed_merkle_roots,
                price_updates: commit_report.price_updates
            }
        );

        ocr3_base::transmit(
            &state.ocr3_base_state,
            ctx.sender(),
            ocr3_base::ocr_plugin_type_commit(),
            report_context,
            report,
            signatures,
            ctx
        )
    }

    fun verify_blessed_roots(
        ref: &CCIPObjectRef,
        off_ramp_state_address: address,
        blessed_merkle_roots: &vector<MerkleRoot>,
        rmn_signatures: vector<vector<u8>>,
    ) {
        let mut merkle_root_source_chains_selector = vector[];
        let mut merkle_root_on_ramp_addresses = vector[];
        let mut merkle_root_min_seq_nrs = vector[];
        let mut merkle_root_max_seq_nrs = vector[];
        let mut merkle_root_values = vector[];
        vector::do_ref!(
            blessed_merkle_roots,
            |merkle_root| {
                let merkle_root: &MerkleRoot = merkle_root;
                merkle_root_source_chains_selector.push_back(
                    merkle_root.source_chain_selector
                );
                merkle_root_on_ramp_addresses.push_back(merkle_root.on_ramp_address);
                merkle_root_max_seq_nrs.push_back(
                    merkle_root.max_seq_nr
                );
                merkle_root_min_seq_nrs.push_back(
                    merkle_root.min_seq_nr
                );
                merkle_root_values.push_back(
                    merkle_root.merkle_root
                );
            }
        );
        rmn_remote::verify(
            ref,
            off_ramp_state_address,
            merkle_root_source_chains_selector,
            merkle_root_on_ramp_addresses,
            merkle_root_min_seq_nrs,
            merkle_root_max_seq_nrs,
            merkle_root_values,
            rmn_signatures
        );
    }

    fun commit_merkle_roots(
        ref: &CCIPObjectRef,
        state: &mut OffRampState,
        clock: &clock::Clock,
        merkle_roots: vector<MerkleRoot>,
        is_blessed: bool
    ) {
        merkle_roots.do_ref!(
            |root| {
                let root: &MerkleRoot = root;
                let source_chain_selector = root.source_chain_selector;

                assert!(
                    !rmn_remote::is_cursed_u128(ref, source_chain_selector as u128),
                    E_CURSED_BY_RMN
                );

                assert_source_chain_enabled(state, source_chain_selector);

                let source_chain_config = state.source_chain_configs.get_mut(&source_chain_selector);

                // If the root is blessed but RMN blessing is disabled for the source chain, or if the root is not
                // blessed but RMN blessing is enabled, we revert.
                assert!(
                    is_blessed != source_chain_config.is_rmn_verification_disabled,
                    E_RMN_BLESSING_MISMATCH
                );

                assert!(
                    source_chain_config.on_ramp == root.on_ramp_address,
                    E_COMMIT_ON_RAMP_MISMATCH
                );
                assert!(
                    source_chain_config.min_seq_nr == root.min_seq_nr
                    && root.min_seq_nr <= root.max_seq_nr,
                    E_INVALID_INTERVAL
                );

                let merkle_root = root.merkle_root;
                assert!(
                    merkle_root.length() == 32 && merkle_root != ZERO_MERKLE_ROOT,
                    E_INVALID_ROOT
                );

                assert!(
                    !state.roots.contains(merkle_root),
                    E_ROOT_ALREADY_COMMITTED
                );

                source_chain_config.min_seq_nr = root.max_seq_nr + 1;
                state.roots.add(merkle_root, clock.timestamp_ms() / 1000);
            }
        )
    }

    public fun get_latest_price_sequence_number(state: &OffRampState): u64 {
        state.latest_price_sequence_number
    }

    public fun get_merkle_root(state: &OffRampState, root: vector<u8>): u64 {
        assert!(
            state.roots.contains(root),
            E_INVALID_ROOT
        );

        *table::borrow(&state.roots, root)
    }

    public fun get_source_chain_config(
        state: &OffRampState,
        source_chain_selector: u64
    ): SourceChainConfig {
        if (state.source_chain_configs.contains(&source_chain_selector)) {
            let source_chain_config = state.source_chain_configs.get(&source_chain_selector);
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

    public fun get_source_chain_config_fields(
        source_chain_config: SourceChainConfig,
    ): (address, bool, u64, bool, vector<u8>) {
        (
            source_chain_config.router,
            source_chain_config.is_enabled,
            source_chain_config.min_seq_nr,
            source_chain_config.is_rmn_verification_disabled,
            source_chain_config.on_ramp,
        )
    }

    public fun get_all_source_chain_configs(state: &OffRampState): (vector<u64>, vector<SourceChainConfig>) {
        let mut chain_selectors = vector[];
        let mut chain_configs = vector[];
        let keys = state.source_chain_configs.keys();
        keys.do_ref!(
            |key| {
                chain_selectors.push_back(*key);
                chain_configs.push_back(*state.source_chain_configs.get(key));
            }
        );
        (chain_selectors, chain_configs)
    }

    // ================================================================
    // |                           Config                             |
    // ================================================================

    public fun get_static_config(state: &OffRampState): StaticConfig {
        create_static_config(state.chain_selector)
    }

    // why do we need these addresses? for offchain?
    // rmn_remote: @ccip,
    // token_admin_registry: @ccip,
    // nonce_manager: @ccip
    public fun get_static_config_fields(cfg: StaticConfig): (u64, address, address, address) {
        (
            cfg.chain_selector,
            cfg.rmn_remote,
            cfg.token_admin_registry,
            cfg.nonce_manager
        )
    }

    public fun get_dynamic_config(state: &OffRampState): DynamicConfig {
        create_dynamic_config(state.permissionless_execution_threshold_seconds)
    }

    public fun get_dynamic_config_fields(cfg: DynamicConfig): (address, u32) {
        (
            cfg.fee_quoter,
            cfg.permissionless_execution_threshold_seconds
        )
    }

    public fun set_dynamic_config(
        state: &mut OffRampState,
        _: &OwnerCap,
        permissionless_execution_threshold_seconds: u32
    ) {
        set_dynamic_config_internal(
            state,
            permissionless_execution_threshold_seconds
        )
    }

    fun create_static_config(chain_selector: u64): StaticConfig {
        StaticConfig {
            chain_selector,
            rmn_remote: @ccip,
            token_admin_registry: @ccip,
            nonce_manager: @ccip
        }
    }

    public fun apply_source_chain_config_updates(
        state: &mut OffRampState,
        _: &OwnerCap,
        source_chains_selector: vector<u64>,
        source_chains_is_enabled: vector<bool>,
        source_chains_is_rmn_verification_disabled: vector<bool>,
        source_chains_on_ramp: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        apply_source_chain_config_updates_internal(
            state,
            source_chains_selector,
            source_chains_is_enabled,
            source_chains_is_rmn_verification_disabled,
            source_chains_on_ramp,
            ctx
        )
    }

    #[test_only]
    public(package) fun show_source_chain_config(cfg: SourceChainConfig): (address, bool, u64, bool, vector<u8>) {
        (cfg.router, cfg.is_enabled, cfg.min_seq_nr, cfg.is_rmn_verification_disabled, cfg.on_ramp)
    }

    #[test]
    fun test_calculate_message_hash() {
        let expected_hash =
            x"c8d6cf666864a60dd6ecd89e5c294734c53b3218d3f83d2d19a3c3f9e200e00d";

        let message_id =
            x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let message = Any2SuiRampMessage {
            header: RampMessageHeader {
                message_id,
                source_chain_selector: 1,
                dest_chain_selector: 2,
                sequence_number: 42,
                nonce: 123
            },
            sender: x"8765432109fedcba8765432109fedcba87654321",
            data: b"sample message data",
            receiver: @0x1234,
            gas_limit: 500000,
            token_amounts: vector[
                Any2SuiTokenTransfer {
                    source_pool_address: x"abcdef1234567890abcdef1234567890abcdef12",
                    dest_token_address: @0x5678,
                    dest_gas_amount: 10000,
                    extra_data: x"00112233",
                    amount: 1000000
                },
                Any2SuiTokenTransfer {
                    source_pool_address: x"123456789abcdef123456789abcdef123456789a",
                    dest_token_address: @0x9abc,
                    dest_gas_amount: 20000,
                    extra_data: x"ffeeddcc",
                    amount: 5000000
                }
            ]
        };
        let metadata_hash =
            x"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        let message_hash = calculate_message_hash(&message, metadata_hash);
        assert!(message_hash == expected_hash);
    }

    #[test]
    fun test_calculate_metadata_hash() {
        let expected_hash =
            x"b62ec658417caa5bcc6ff1d8c45f8b1cb52e1b0ed71603a04b250b107ed836d9";
        let expected_hash_alternate =
            x"89da72ab93f7bd546d60b58a1e1b5f628fd456fe163614ff1e31a2413ca1b55a";

        let source_chain_selector = 123456789;
        let dest_chain_selector = 987654321;
        let on_ramp = b"source-onramp-address";

        let metadata_hash =
            calculate_metadata_hash(source_chain_selector, dest_chain_selector, on_ramp);
        let metadata_hash_alternate =
            calculate_metadata_hash(
                source_chain_selector + 1, dest_chain_selector, on_ramp
            );

        assert!(metadata_hash == expected_hash, 1);
        assert!(metadata_hash_alternate == expected_hash_alternate, 2);
    }

    #[test]
    fun test_deserialize_execution_report() {
        let expected_sender = x"d87929a32cf0cbdc9e2d07ffc7c33344079de727";
        let expected_data = x"68656c6c6f20434349505265636569766572";
        let expected_receiver =
            @0xbd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490;
        let expected_gas_limit = 100000;
        let expected_message_id =
            x"20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc";
        let expected_source_chain_selector = 909606746561742123;
        let expected_dest_chain_selector = 743186221051783445;
        let expected_sequence_number = 1;
        let expected_nonce = 0;
        let expected_leaf_bytes =
            x"c50d2bc9b6bba65c578d8ba98560be9fd1e812e5798b752aa4b83f6739b60960";

        let report_bytes =
            x"2b851c4684929f0c20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc2b851c4684929f0c15a9c133ee53500a0100000000000000000000000000000014d87929a32cf0cbdc9e2d07ffc7c33344079de7271268656c6c6f20434349505265636569766572bd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490a086010000000000000000000000000000000000000000000000000000000000000000";
        let onramp = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";
        let execution_report = deserialize_execution_report(report_bytes);

        assert!(
            execution_report.message.header.source_chain_selector == expected_source_chain_selector,
            1
        );
        assert!(
            execution_report.message.header.dest_chain_selector == expected_dest_chain_selector,
            2
        );
        assert!(
            execution_report.message.header.sequence_number == expected_sequence_number,
            3
        );
        assert!(execution_report.message.header.nonce == expected_nonce, 4);
        assert!(execution_report.message.sender == expected_sender, 5);
        assert!(execution_report.message.data == expected_data, 6);
        assert!(execution_report.message.receiver == expected_receiver, 7);
        assert!(execution_report.message.gas_limit == expected_gas_limit, 8);
        assert!(execution_report.message.header.message_id == expected_message_id, 9);

        let metadata_hash =
            calculate_metadata_hash(
                execution_report.source_chain_selector,
                execution_report.message.header.dest_chain_selector,
                onramp
            );
        let hashed_leaf = calculate_message_hash(&execution_report.message, metadata_hash);

        assert!(expected_leaf_bytes == hashed_leaf, 1);
    }
}


#[test_only]
module ccip::offramp_test {
    use ccip::offramp::{Self, OffRampState};
    use ccip::state_object::{Self, CCIPObjectRef};
    use sui::test_scenario::{Self, Scenario};

    const OFF_RAMP_STATE_NAME: vector<u8> = b"OffRampState";
    const CHAIN_SELECTOR: u64 = 123456789;
    const SOURCE_CHAIN_SELECTOR_1: u64 = 11223344;
    const SOURCE_CHAIN_SELECTOR_2: u64 = 33445566;
    const SOURCE_CHAIN_ONRAMP_1: vector<u8> = x"e5b948b5b6800dbeedf993ebbd3824b80f548c7c19ebfbd7982080b8ff68c24d";
    const SOURCE_CHAIN_ONRAMP_2: vector<u8> = x"1b215d2fb37eeb21386c59a0c23ccaffe26c735100ca843d4226d9156cf84484";

    fun set_up_test(): (Scenario, CCIPObjectRef) {
        let mut scenario = test_scenario::begin(@0x1);
        let ctx = scenario.ctx();

        let ref = state_object::create(ctx);
        (scenario, ref)
    }

    fun tear_down_test(scenario: Scenario, ref: CCIPObjectRef) {
        state_object::destroy_state_object(ref);
        test_scenario::end(scenario);
    }

    fun initialize(ref: &mut CCIPObjectRef, ctx: &mut TxContext) {
        offramp::initialize(
            ref,
            CHAIN_SELECTOR,
            10000, // permissionless_execution_threshold_seconds
            vector[
                SOURCE_CHAIN_SELECTOR_1, SOURCE_CHAIN_SELECTOR_2
            ], // source_chains_selectors
            vector[
                true, false
            ], // source_chains_is_enabled
            vector[
                false, true
            ], // source_chains_is_rmn_verification_disabled
            vector[
                SOURCE_CHAIN_ONRAMP_1, SOURCE_CHAIN_ONRAMP_2
            ], // source_chains_on_ramp
            ctx
        );
    }

    #[test]
    public fun test_initialize() {
        let (mut scenario, mut ref) = set_up_test();
        let ctx = scenario.ctx();
        initialize(&mut ref, ctx);

        let _state = state_object::borrow<OffRampState>(&ref, OFF_RAMP_STATE_NAME);

        let cfg = offramp::get_source_chain_config(&ref, SOURCE_CHAIN_SELECTOR_1);
        let (router, is_enabled, min_seq_nr, is_rmn_enabled, on_ramp) = offramp::show_source_chain_config(cfg);
        assert!(router == @ccip);
        assert!(is_enabled == true);
        assert!(min_seq_nr == 1);
        assert!(is_rmn_enabled == false);
        assert!(on_ramp == SOURCE_CHAIN_ONRAMP_1);

        let cfg = offramp::get_source_chain_config(&ref, SOURCE_CHAIN_SELECTOR_2);
        let (router, is_enabled, min_seq_nr, is_rmn_enabled, on_ramp) = offramp::show_source_chain_config(cfg);
        assert!(router == @ccip);
        assert!(is_enabled == false);
        assert!(min_seq_nr == 1);
        assert!(is_rmn_enabled == true);
        assert!(on_ramp == SOURCE_CHAIN_ONRAMP_2);

        tear_down_test(scenario, ref);
    }
}