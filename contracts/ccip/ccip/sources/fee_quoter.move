/// This module is responsible for storage and retrieval of fee token and token transfer
/// information and pricing.
module ccip::fee_quoter {
    use std::account;
    use std::bcs;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::Metadata;
    use std::object;
    use std::option;
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};
    use std::timestamp;

    use ccip::auth;
    use ccip::client;
    use ccip::eth_abi;
    use ccip::state_object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const CHAIN_FAMILY_SELECTOR_EVM: vector<u8> = x"2812d52c";
    const CHAIN_FAMILY_SELECTOR_SVM: vector<u8> = x"1e10bdc4";
    const CHAIN_FAMILY_SELECTOR_APTOS: vector<u8> = x"ac77ffec";
    const CHAIN_FAMILY_SELECTOR_SUI: vector<u8> = x"c4e05953";

    /// @dev We disallow the first 1024 addresses to avoid calling into a range known for hosting precompiles. Calling
    /// into precompiles probably won't cause any issues, but to be safe we can disallow this range. It is extremely
    /// unlikely that anyone would ever be able to generate an address in this range. There is no official range of
    /// precompiles, but EIP-7587 proposes to reserve the range 0x100 to 0x1ff. Our range is more conservative, even
    /// though it might not be exhaustive for all chains, which is OK. We also disallow the zero address, which is a
    /// common practice.
    const EVM_PRECOMPILE_SPACE: u256 = 1024;

    /// @dev According to the Aptos docs, the first 0xa addresses are reserved for precompiles.
    /// https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/doc/account.md#function-create_framework_reserved_account-1
    /// We use the same range for SUI, even though there is one documented reserved address outside of this range.
    /// Since sending a message to this address would not cause any negative side effects, as it would never register
    /// a callback with CCIP, there is no negative impact.
    /// https://move-book.com/appendix/reserved-addresses.html
    const MOVE_PRECOMPILE_SPACE: u256 = 0x0b;

    const ALLOW_OUT_OF_ORDER_EXECUTION: bool = true;

    const GAS_PRICE_BITS: u8 = 112;
    const GAS_PRICE_MASK_112_BITS: u256 = 0xffffffffffffffffffffffffffff; // 28 f's

    const MESSAGE_FIXED_BYTES: u64 = 32 * 15;
    const MESSAGE_FIXED_BYTES_PER_TOKEN: u64 = 32 * (4 + (3 + 2));

    const CCIP_LOCK_OR_BURN_V1_RET_BYTES: u32 = 32;

    /// The maximum number of accounts that can be passed in SVMExtraArgs.
    const SVM_EXTRA_ARGS_MAX_ACCOUNTS: u64 = 64;

    /// Number of overhead accounts needed for message execution on SVM.
    /// These are message.receiver, and the OffRamp Signer PDA specific to the receiver.
    const SVM_MESSAGING_ACCOUNTS_OVERHEAD: u64 = 2;

    /// The size of each SVM account (in bytes).
    const SVM_ACCOUNT_BYTE_SIZE: u64 = 32;

    /// The expected static payload size of a token transfer when Borsh encoded and submitted to SVM.
    /// TokenPool extra data and offchain data sizes are dynamic, and should be accounted for separately.
    const SVM_TOKEN_TRANSFER_DATA_OVERHEAD: u64 = (4 + 32) // source_pool
    + 32 // token_address
    + 4 // gas_amount
    + 4 // extra_data overhead
    + 32 // amount
    + 32 // size of the token lookup table account
    + 32 // token-related accounts in the lookup table, over-estimated to 32, typically between 11 - 13
    + 32 // token account belonging to the token receiver, e.g ATA, not included in the token lookup table
    + 32 // per-chain token pool config, not included in the token lookup table
    + 32 // per-chain token billing config, not always included in the token lookup table
    + 32; // OffRamp pool signer PDA, not included in the token lookup table;

    const MAX_U64: u256 = 18446744073709551615;
    const MAX_U160: u256 = 1461501637330902918203684832716283019655932542975;
    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const VAL_1E5: u256 = 100_000;
    const VAL_1E14: u256 = 100_000_000_000_000;
    const VAL_1E16: u256 = 10_000_000_000_000_000;
    const VAL_1E18: u256 = 1_000_000_000_000_000_000;

    // Link has 8 decimals on Aptos and 18 decimals on it's native chain, Ethereum. We want to emit
    // the fee in juels (1e18) denomination for consistency across chains. This means we multiply
    // the fee by 1e10 on Aptos before we emit it in the event.
    const LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER: u256 = 10_000_000_000;

    struct FeeQuoterState has key, store {
        // max_fee_juels_per_msg is in juels (1e18) denomination for consistency across chains.
        max_fee_juels_per_msg: u256,
        link_token: address,
        token_price_staleness_threshold: u64,
        fee_tokens: vector<address>,
        usd_per_unit_gas_by_dest_chain: SmartTable<u64, TimestampedPrice>,
        usd_per_token: SmartTable<address, TimestampedPrice>,
        dest_chain_configs: SmartTable<u64, DestChainConfig>,
        // dest chain selector -> local token -> TokenTransferFeeConfig
        token_transfer_fee_configs: SmartTable<u64, SmartTable<address, TokenTransferFeeConfig>>,
        premium_multiplier_wei_per_eth: SmartTable<address, u64>,
        fee_token_added_events: EventHandle<FeeTokenAdded>,
        fee_token_removed_events: EventHandle<FeeTokenRemoved>,
        token_transfer_fee_config_added_events: EventHandle<TokenTransferFeeConfigAdded>,
        token_transfer_fee_config_removed_events: EventHandle<TokenTransferFeeConfigRemoved>,
        usd_per_token_updated_events: EventHandle<UsdPerTokenUpdated>,
        usd_per_unit_gas_updated_events: EventHandle<UsdPerUnitGasUpdated>,
        dest_chain_added_events: EventHandle<DestChainAdded>,
        dest_chain_config_updated_events: EventHandle<DestChainConfigUpdated>,
        premium_multiplier_wei_per_eth_updated_events: EventHandle<
            PremiumMultiplierWeiPerEthUpdated>
    }

    struct StaticConfig has drop {
        max_fee_juels_per_msg: u256,
        link_token: address,
        token_price_staleness_threshold: u64
    }

    struct DestChainConfig has store, drop, copy {
        is_enabled: bool,
        max_number_of_tokens_per_msg: u16,
        max_data_bytes: u32,
        max_per_msg_gas_limit: u32,
        dest_gas_overhead: u32,
        dest_gas_per_payload_byte_base: u8,
        dest_gas_per_payload_byte_high: u8,
        dest_gas_per_payload_byte_threshold: u16,
        dest_data_availability_overhead_gas: u32,
        dest_gas_per_data_availability_byte: u16,
        dest_data_availability_multiplier_bps: u16,
        chain_family_selector: vector<u8>,
        enforce_out_of_order: bool,
        default_token_fee_usd_cents: u16,
        default_token_dest_gas_overhead: u32,
        default_tx_gas_limit: u32,
        // Multiplier for gas costs, 1e18 based so 11e17 = 10% extra cost.
        gas_multiplier_wei_per_eth: u64,
        gas_price_staleness_threshold: u32,
        network_fee_usd_cents: u32
    }

    struct TokenTransferFeeConfig has store, drop, copy {
        min_fee_usd_cents: u32,
        max_fee_usd_cents: u32,
        deci_bps: u16,
        dest_gas_overhead: u32,
        dest_bytes_overhead: u32,
        is_enabled: bool
    }

    struct TimestampedPrice has store, drop, copy {
        value: u256,
        timestamp: u64
    }

    #[event]
    struct FeeTokenAdded has store, drop {
        fee_token: address
    }

    #[event]
    struct FeeTokenRemoved has store, drop {
        fee_token: address
    }

    #[event]
    struct TokenTransferFeeConfigAdded has store, drop {
        dest_chain_selector: u64,
        token: address,
        token_transfer_fee_config: TokenTransferFeeConfig
    }

    #[event]
    struct TokenTransferFeeConfigRemoved has store, drop {
        dest_chain_selector: u64,
        token: address
    }

    #[event]
    struct UsdPerTokenUpdated has store, drop {
        token: address,
        usd_per_token: u256,
        timestamp: u64
    }

    #[event]
    struct UsdPerUnitGasUpdated has store, drop {
        dest_chain_selector: u64,
        usd_per_unit_gas: u256,
        timestamp: u64
    }

    #[event]
    struct DestChainAdded has store, drop {
        dest_chain_selector: u64,
        dest_chain_config: DestChainConfig
    }

    #[event]
    struct DestChainConfigUpdated has store, drop {
        dest_chain_selector: u64,
        dest_chain_config: DestChainConfig
    }

    #[event]
    struct PremiumMultiplierWeiPerEthUpdated has store, drop {
        token: address,
        premium_multiplier_wei_per_eth: u64
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_INVALID_LINK_TOKEN: u64 = 2;
    const E_UNKNOWN_DEST_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_TOKEN: u64 = 4;
    const E_DEST_CHAIN_NOT_ENABLED: u64 = 5;
    const E_TOKEN_UPDATE_MISMATCH: u64 = 6;
    const E_GAS_UPDATE_MISMATCH: u64 = 7;
    const E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH: u64 = 8;
    const E_FEE_TOKEN_NOT_SUPPORTED: u64 = 9;
    const E_TOKEN_NOT_SUPPORTED: u64 = 10;
    const E_UNKNOWN_CHAIN_FAMILY_SELECTOR: u64 = 11;
    const E_STALE_GAS_PRICE: u64 = 12;
    const E_MESSAGE_TOO_LARGE: u64 = 13;
    const E_UNSUPPORTED_NUMBER_OF_TOKENS: u64 = 14;
    const E_INVALID_EVM_ADDRESS: u64 = 15;
    const E_INVALID_32BYTES_ADDRESS: u64 = 16;
    const E_FEE_TOKEN_COST_TOO_HIGH: u64 = 17;
    const E_MESSAGE_GAS_LIMIT_TOO_HIGH: u64 = 18;
    const E_EXTRA_ARG_OUT_OF_ORDER_EXECUTION_MUST_BE_TRUE: u64 = 19;
    const E_INVALID_EXTRA_ARGS_TAG: u64 = 20;
    const E_INVALID_EXTRA_ARGS_DATA: u64 = 21;
    const E_INVALID_TOKEN_RECEIVER: u64 = 22;
    const E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH: u64 = 23;
    const E_MESSAGE_FEE_TOO_HIGH: u64 = 24;
    const E_SOURCE_TOKEN_DATA_TOO_LARGE: u64 = 25;
    const E_INVALID_DEST_CHAIN_SELECTOR: u64 = 26;
    const E_INVALID_GAS_LIMIT: u64 = 27;
    const E_INVALID_CHAIN_FAMILY_SELECTOR: u64 = 28;
    const E_TO_TOKEN_AMOUNT_TOO_LARGE: u64 = 29;
    const E_UNKNOWN_FUNCTION: u64 = 30;
    const E_ZERO_TOKEN_PRICE: u64 = 31;
    const E_TOO_MANY_SVM_EXTRA_ARGS_ACCOUNTS: u64 = 32;
    const E_INVALID_SVM_EXTRA_ARGS_WRITABLE_BITMAP: u64 = 33;
    const E_INVALID_FEE_RANGE: u64 = 34;
    const E_INVALID_DEST_BYTES_OVERHEAD: u64 = 35;
    const E_INVALID_SVM_RECEIVER_LENGTH: u64 = 36;
    const E_TOKEN_AMOUNT_MISMATCH: u64 = 37;
    const E_INVALID_SVM_ACCOUNT_LENGTH: u64 = 38;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"FeeQuoter 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };
    }

    public entry fun initialize(
        caller: &signer,
        max_fee_juels_per_msg: u256,
        link_token: address,
        token_price_staleness_threshold: u64,
        fee_tokens: vector<address>
    ) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            !exists<FeeQuoterState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        assert!(
            object::object_exists<Metadata>(link_token),
            error::invalid_argument(E_INVALID_LINK_TOKEN)
        );

        let state_object_signer = state_object::object_signer();

        let state = FeeQuoterState {
            max_fee_juels_per_msg,
            link_token,
            token_price_staleness_threshold,
            fee_tokens,
            usd_per_unit_gas_by_dest_chain: smart_table::new(),
            usd_per_token: smart_table::new(),
            dest_chain_configs: smart_table::new(),
            token_transfer_fee_configs: smart_table::new(),
            premium_multiplier_wei_per_eth: smart_table::new(),
            fee_token_added_events: account::new_event_handle(&state_object_signer),
            fee_token_removed_events: account::new_event_handle(&state_object_signer),
            token_transfer_fee_config_added_events: account::new_event_handle(
                &state_object_signer
            ),
            token_transfer_fee_config_removed_events: account::new_event_handle(
                &state_object_signer
            ),
            usd_per_token_updated_events: account::new_event_handle(&state_object_signer),
            usd_per_unit_gas_updated_events: account::new_event_handle(
                &state_object_signer
            ),
            dest_chain_added_events: account::new_event_handle(&state_object_signer),
            dest_chain_config_updated_events: account::new_event_handle(
                &state_object_signer
            ),
            premium_multiplier_wei_per_eth_updated_events: account::new_event_handle(
                &state_object_signer
            )
        };
        move_to(&state_object_signer, state);
    }

    #[view]
    public fun get_token_price(token: address): TimestampedPrice acquires FeeQuoterState {
        get_token_price_internal(borrow_state(), token)
    }

    public fun timestamped_price_value(
        timestamped_price: &TimestampedPrice
    ): u256 {
        timestamped_price.value
    }

    public fun timestamped_price_timestamp(
        timestamped_price: &TimestampedPrice
    ): u64 {
        timestamped_price.timestamp
    }

    #[view]
    public fun get_token_prices(
        tokens: vector<address>
    ): (vector<TimestampedPrice>) acquires FeeQuoterState {
        let state = borrow_state();
        tokens.map_ref(|token| get_token_price_internal(state, *token))
    }

    #[view]
    public fun get_dest_chain_gas_price(
        dest_chain_selector: u64
    ): TimestampedPrice acquires FeeQuoterState {
        get_dest_chain_gas_price_internal(borrow_state(), dest_chain_selector)
    }

    #[view]
    public fun get_token_and_gas_prices(
        token: address, dest_chain_selector: u64
    ): (u256, u256) acquires FeeQuoterState {
        let state = borrow_state();
        let dest_chain_config = get_dest_chain_config_internal(
            state, dest_chain_selector
        );
        assert!(
            dest_chain_config.is_enabled,
            error::invalid_argument(E_DEST_CHAIN_NOT_ENABLED)
        );
        let token_price = get_token_price_internal(state, token);
        let gas_price_value =
            get_validated_gas_price_internal(
                state, dest_chain_config, dest_chain_selector
            );
        (token_price.value, gas_price_value)
    }

    #[view]
    public fun convert_token_amount(
        from_token: address, from_token_amount: u64, to_token: address
    ): u64 acquires FeeQuoterState {
        let state = borrow_state();
        convert_token_amount_internal(state, from_token, from_token_amount, to_token)
    }

    #[view]
    public fun get_fee_tokens(): vector<address> acquires FeeQuoterState {
        borrow_state().fee_tokens
    }

    public entry fun apply_fee_token_updates(
        caller: &signer,
        fee_tokens_to_remove: vector<address>,
        fee_tokens_to_add: vector<address>
    ) acquires FeeQuoterState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        // Remove tokens
        fee_tokens_to_remove.for_each_ref(
            |fee_token| {
                let fee_token = *fee_token;
                let (found, index) = state.fee_tokens.index_of(&fee_token);
                if (found) {
                    state.fee_tokens.remove(index);
                    event::emit_event(
                        &mut state.fee_token_removed_events, FeeTokenRemoved { fee_token }
                    );
                };
            }
        );

        // Add new tokens
        fee_tokens_to_add.for_each_ref(
            |fee_token| {
                let fee_token = *fee_token;
                let (found, _) = state.fee_tokens.index_of(&fee_token);
                if (!found) {
                    state.fee_tokens.push_back(fee_token);
                    event::emit_event(
                        &mut state.fee_token_added_events, FeeTokenAdded { fee_token }
                    );
                };
            }
        );
    }

    #[view]
    public fun get_token_transfer_fee_config(
        dest_chain_selector: u64, token: address
    ): TokenTransferFeeConfig acquires FeeQuoterState {
        *get_token_transfer_fee_config_internal(
            borrow_state(), dest_chain_selector, token
        )
    }

    inline fun get_token_transfer_fee_config_internal(
        state: &FeeQuoterState, dest_chain_selector: u64, token: address
    ): &TokenTransferFeeConfig {
        let empty_fee_config = TokenTransferFeeConfig {
            min_fee_usd_cents: 0,
            max_fee_usd_cents: 0,
            deci_bps: 0,
            dest_gas_overhead: 0,
            dest_bytes_overhead: 0,
            is_enabled: false
        };

        if (!state.token_transfer_fee_configs.contains(dest_chain_selector)) {
            &empty_fee_config
        } else {
            let dest_chain_fee_configs =
                state.token_transfer_fee_configs.borrow(dest_chain_selector);

            dest_chain_fee_configs.borrow_with_default(token, &empty_fee_config)
        }
    }

    // Note that unlike EVM, this only allows changes for a single dest chain selector
    // at a time.
    public entry fun apply_token_transfer_fee_config_updates(
        caller: &signer,
        dest_chain_selector: u64,
        add_tokens: vector<address>,
        add_min_fee_usd_cents: vector<u32>,
        add_max_fee_usd_cents: vector<u32>,
        add_deci_bps: vector<u16>,
        add_dest_gas_overhead: vector<u32>,
        add_dest_bytes_overhead: vector<u32>,
        add_is_enabled: vector<bool>,
        remove_tokens: vector<address>
    ) acquires FeeQuoterState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        if (!state.token_transfer_fee_configs.contains(dest_chain_selector)) {
            state.token_transfer_fee_configs.add(
                dest_chain_selector, smart_table::new()
            );
        };
        let token_transfer_fee_configs =
            state.token_transfer_fee_configs.borrow_mut(dest_chain_selector);

        let add_tokens_len = add_tokens.length();
        assert!(
            add_tokens_len == add_min_fee_usd_cents.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == add_max_fee_usd_cents.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == add_deci_bps.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == add_dest_gas_overhead.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == add_dest_bytes_overhead.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == add_is_enabled.length(),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );

        for (i in 0..add_tokens_len) {
            let token = add_tokens[i];
            let min_fee_usd_cents = add_min_fee_usd_cents[i];
            let max_fee_usd_cents = add_max_fee_usd_cents[i];
            let deci_bps = add_deci_bps[i];
            let dest_gas_overhead = add_dest_gas_overhead[i];
            let dest_bytes_overhead = add_dest_bytes_overhead[i];
            let is_enabled = add_is_enabled[i];

            let token_transfer_fee_config = TokenTransferFeeConfig {
                min_fee_usd_cents,
                max_fee_usd_cents,
                deci_bps,
                dest_gas_overhead,
                dest_bytes_overhead,
                is_enabled
            };

            if (token_transfer_fee_config.min_fee_usd_cents
                >= token_transfer_fee_config.max_fee_usd_cents) {
                abort error::invalid_argument(E_INVALID_FEE_RANGE);
            };
            if (token_transfer_fee_config.dest_bytes_overhead
                < CCIP_LOCK_OR_BURN_V1_RET_BYTES) {
                abort error::invalid_argument(E_INVALID_DEST_BYTES_OVERHEAD);
            };

            token_transfer_fee_configs.upsert(token, token_transfer_fee_config);

            event::emit_event(
                &mut state.token_transfer_fee_config_added_events,
                TokenTransferFeeConfigAdded {
                    dest_chain_selector,
                    token,
                    token_transfer_fee_config
                }
            );
        };

        remove_tokens.for_each_ref(
            |token| {
                let token: address = *token;
                if (token_transfer_fee_configs.contains(token)) {
                    token_transfer_fee_configs.remove(token);

                    event::emit_event(
                        &mut state.token_transfer_fee_config_removed_events,
                        TokenTransferFeeConfigRemoved { dest_chain_selector, token }
                    );
                }
            }
        );
    }

    public fun update_prices(
        caller: &signer,
        source_tokens: vector<address>,
        source_usd_per_token: vector<u256>,
        gas_dest_chain_selectors: vector<u64>,
        gas_usd_per_unit_gas: vector<u256>
    ) acquires FeeQuoterState {
        auth::assert_is_allowed_offramp(signer::address_of(caller));

        assert!(
            source_tokens.length() == source_usd_per_token.length(),
            error::invalid_argument(E_TOKEN_UPDATE_MISMATCH)
        );
        assert!(
            gas_dest_chain_selectors.length() == gas_usd_per_unit_gas.length(),
            error::invalid_argument(E_GAS_UPDATE_MISMATCH)
        );

        let state = borrow_state_mut();
        let timestamp = timestamp::now_seconds();

        source_tokens.zip_ref(
            &source_usd_per_token,
            |token, usd_per_token| {
                let timestamped_price = TimestampedPrice { value: *usd_per_token, timestamp };
                state.usd_per_token.upsert(*token, timestamped_price);
                event::emit_event(
                    &mut state.usd_per_token_updated_events,
                    UsdPerTokenUpdated {
                        token: *token,
                        usd_per_token: *usd_per_token,
                        timestamp
                    }
                );
            }
        );

        gas_dest_chain_selectors.zip_ref(
            &gas_usd_per_unit_gas,
            |dest_chain_selector, usd_per_unit_gas| {
                let timestamped_price =
                    TimestampedPrice { value: *usd_per_unit_gas, timestamp };
                state.usd_per_unit_gas_by_dest_chain.upsert(
                    *dest_chain_selector, timestamped_price
                );

                event::emit_event(
                    &mut state.usd_per_unit_gas_updated_events,
                    UsdPerUnitGasUpdated {
                        dest_chain_selector: *dest_chain_selector,
                        usd_per_unit_gas: *usd_per_unit_gas,
                        timestamp
                    }
                );
            }
        );
    }

    #[view]
    public fun get_validated_fee(
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        local_token_addresses: vector<address>,
        local_token_amounts: vector<u64>,
        _token_store_addresses: vector<address>,
        fee_token: address,
        _fee_token_store: address,
        extra_args: vector<u8>
    ): u64 acquires FeeQuoterState {
        let state = borrow_state();

        let dest_chain_config = get_dest_chain_config_internal(
            state, dest_chain_selector
        );
        assert!(
            dest_chain_config.is_enabled,
            error::invalid_argument(E_DEST_CHAIN_NOT_ENABLED)
        );

        assert!(
            state.fee_tokens.contains(&fee_token),
            error::invalid_argument(E_FEE_TOKEN_NOT_SUPPORTED)
        );

        let chain_family_selector = dest_chain_config.chain_family_selector;

        let data_len = data.length();
        let tokens_len = local_token_addresses.length();
        validate_message(dest_chain_config, data_len, tokens_len);

        let gas_limit =
            if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM
                || chain_family_selector == CHAIN_FAMILY_SELECTOR_APTOS
                || chain_family_selector == CHAIN_FAMILY_SELECTOR_SUI) {
                resolve_generic_gas_limit(dest_chain_config, extra_args)
            } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM) {
                resolve_svm_gas_limit(
                    dest_chain_config,
                    state,
                    dest_chain_selector,
                    extra_args,
                    receiver,
                    data_len,
                    tokens_len,
                    local_token_addresses
                )
            } else {
                abort error::invalid_argument(E_UNKNOWN_CHAIN_FAMILY_SELECTOR)
            };

        validate_dest_family_address(chain_family_selector, receiver, gas_limit);

        let fee_token_price = get_token_price_internal(state, fee_token);
        assert!(fee_token_price.value > 0, error::invalid_state(E_ZERO_TOKEN_PRICE));

        let packed_gas_price =
            get_validated_gas_price_internal(
                state, dest_chain_config, dest_chain_selector
            );

        let (premium_fee_usd_wei, token_transfer_gas, token_transfer_bytes_overhead) =
            if (tokens_len > 0) {
                get_token_transfer_cost(
                    state,
                    dest_chain_config,
                    dest_chain_selector,
                    fee_token,
                    fee_token_price,
                    local_token_addresses,
                    local_token_amounts
                )
            } else {
                ((dest_chain_config.network_fee_usd_cents as u256) * VAL_1E16, 0, 0)
            };
        let premium_multiplier =
            get_premium_multiplier_wei_per_eth_internal(state, fee_token);
        premium_fee_usd_wei *=(premium_multiplier as u256); // Apply premium multiplier in wei/eth units

        let data_availability_cost_usd_36_decimals =
            if (dest_chain_config.dest_data_availability_multiplier_bps > 0) {
                // Extract data availability gas price (upper 112 bits) - matches EVM uint112 behavior
                let data_availability_gas_price =
                    (packed_gas_price >> GAS_PRICE_BITS) & GAS_PRICE_MASK_112_BITS;
                get_data_availability_cost(
                    dest_chain_config,
                    data_availability_gas_price,
                    data_len,
                    tokens_len,
                    token_transfer_bytes_overhead
                )
            } else { 0 };

        let call_data_length: u256 =
            (data_len as u256) + (token_transfer_bytes_overhead as u256);
        let dest_call_data_cost =
            call_data_length
                * (dest_chain_config.dest_gas_per_payload_byte_base as u256);
        if (call_data_length
            > (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)) {
            dest_call_data_cost =
                (dest_chain_config.dest_gas_per_payload_byte_base as u256)
                    * (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)
                    + (
                        call_data_length
                            - (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)
                    ) * (dest_chain_config.dest_gas_per_payload_byte_high as u256);
        };

        let total_dest_chain_gas =
            (dest_chain_config.dest_gas_overhead as u256) + (token_transfer_gas as u256)
                + dest_call_data_cost + gas_limit;

        let gas_cost = packed_gas_price & GAS_PRICE_MASK_112_BITS;

        let total_cost_usd =
            (
                total_dest_chain_gas * gas_cost
                    * (dest_chain_config.gas_multiplier_wei_per_eth as u256)
            ) + premium_fee_usd_wei + data_availability_cost_usd_36_decimals;

        let fee_token_cost = total_cost_usd / fee_token_price.value;

        // we need to convert back to a u64 which is what the fungible asset module uses for amounts.
        assert!(
            fee_token_cost <= MAX_U64,
            error::invalid_state(E_FEE_TOKEN_COST_TOO_HIGH)
        );
        fee_token_cost as u64
    }

    public entry fun apply_premium_multiplier_wei_per_eth_updates(
        caller: &signer, tokens: vector<address>, premium_multiplier_wei_per_eth: vector<u64>
    ) acquires FeeQuoterState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        tokens.zip_ref(
            &premium_multiplier_wei_per_eth,
            |token, premium_multiplier_wei_per_eth| {
                let token: address = *token;
                let premium_multiplier_wei_per_eth: u64 = *premium_multiplier_wei_per_eth;
                state.premium_multiplier_wei_per_eth.upsert(
                    token, premium_multiplier_wei_per_eth
                );
                event::emit_event(
                    &mut state.premium_multiplier_wei_per_eth_updated_events,
                    PremiumMultiplierWeiPerEthUpdated {
                        token,
                        premium_multiplier_wei_per_eth
                    }
                );
            }
        );
    }

    #[view]
    public fun get_premium_multiplier_wei_per_eth(token: address): u64 acquires FeeQuoterState {
        let state = borrow_state();
        get_premium_multiplier_wei_per_eth_internal(state, token)
    }

    inline fun get_premium_multiplier_wei_per_eth_internal(
        state: &FeeQuoterState, token: address
    ): u64 {
        assert!(
            state.premium_multiplier_wei_per_eth.contains(token),
            error::invalid_argument(E_UNKNOWN_TOKEN)
        );
        *state.premium_multiplier_wei_per_eth.borrow(token)
    }

    inline fun resolve_generic_gas_limit(
        dest_chain_config: &DestChainConfig, extra_args: vector<u8>
    ): u256 {
        let (gas_limit, _allow_out_of_order_execution) =
            decode_generic_extra_args(dest_chain_config, extra_args);
        assert!(
            gas_limit <= (dest_chain_config.max_per_msg_gas_limit as u256),
            error::invalid_argument(E_MESSAGE_GAS_LIMIT_TOO_HIGH)
        );
        gas_limit
    }

    inline fun resolve_svm_gas_limit(
        dest_chain_config: &DestChainConfig,
        state: &FeeQuoterState,
        dest_chain_selector: u64,
        extra_args: vector<u8>,
        receiver: vector<u8>,
        data_len: u64,
        tokens_len: u64,
        local_token_addresses: vector<address>
    ): u256 {
        let extra_args_len = extra_args.length();
        assert!(extra_args_len > 0, error::invalid_argument(E_INVALID_EXTRA_ARGS_DATA));

        let (
            compute_units,
            account_is_writable_bitmap,
            _allow_out_of_order_execution,
            token_receiver,
            accounts
        ) = decode_svm_extra_args(extra_args);

        let gas_limit = compute_units;

        assert!(
            gas_limit <= dest_chain_config.max_per_msg_gas_limit,
            error::invalid_argument(E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH)
        );

        let accounts_length = accounts.length();
        // The max payload size for SVM is heavily dependent on the accounts passed into extra args and the number of
        // tokens. Below, token and account overhead will count towards maxDataBytes.
        let svm_expanded_data_length = data_len;

        // The receiver length has not yet been validated before this point.
        assert!(
            receiver.length() == 32,
            error::invalid_argument(E_INVALID_SVM_RECEIVER_LENGTH)
        );
        let receiver_uint = eth_abi::decode_u256_value(receiver);
        if (receiver_uint == 0) {
            // When message receiver is zero, CCIP receiver is not invoked on SVM.
            // There should not be additional accounts specified for the receiver.
            assert!(
                accounts_length == 0,
                error::invalid_argument(E_TOO_MANY_SVM_EXTRA_ARGS_ACCOUNTS)
            );
        } else {
            // The messaging accounts needed for CCIP receiver on SVM are:
            // message receiver, offramp PDA signer,
            // plus remaining accounts specified in SVM extraArgs. Each account is 32 bytes.
            svm_expanded_data_length +=((accounts_length
                + SVM_MESSAGING_ACCOUNTS_OVERHEAD) * SVM_ACCOUNT_BYTE_SIZE);
        };

        for (i in 0..accounts_length) {
            assert!(
                accounts[i].length() == 32,
                error::invalid_argument(E_INVALID_SVM_ACCOUNT_LENGTH)
            );
        };

        if (tokens_len > 0) {
            assert!(
                token_receiver.length() == 32
                    && eth_abi::decode_u256_value(token_receiver) != 0,
                error::invalid_argument(E_INVALID_TOKEN_RECEIVER)
            );
        };
        assert!(
            accounts_length <= SVM_EXTRA_ARGS_MAX_ACCOUNTS,
            error::invalid_argument(E_TOO_MANY_SVM_EXTRA_ARGS_ACCOUNTS)
        );
        assert!(
            (account_is_writable_bitmap >> (accounts_length as u8)) == 0,
            error::invalid_argument(E_INVALID_SVM_EXTRA_ARGS_WRITABLE_BITMAP)
        );

        svm_expanded_data_length += tokens_len * SVM_TOKEN_TRANSFER_DATA_OVERHEAD;

        // The token destBytesOverhead can be very different per token so we have to take it into account as well.
        for (i in 0..tokens_len) {
            let local_token_address = local_token_addresses[i];
            let destBytesOverhead =
                get_token_transfer_fee_config_internal(
                    state, dest_chain_selector, local_token_address
                ).dest_bytes_overhead;

            // Pools get CCIP_LOCK_OR_BURN_V1_RET_BYTES by default, but if an override is set we use that instead.
            if (destBytesOverhead > 0) {
                svm_expanded_data_length +=(destBytesOverhead as u64);
            } else {
                svm_expanded_data_length +=(CCIP_LOCK_OR_BURN_V1_RET_BYTES as u64);
            }
        };

        assert!(
            svm_expanded_data_length <= (dest_chain_config.max_data_bytes as u64),
            error::invalid_argument(E_MESSAGE_TOO_LARGE)
        );

        gas_limit as u256
    }

    inline fun decode_generic_extra_args(
        dest_chain_config: &DestChainConfig, extra_args: vector<u8>
    ): (u256, bool) {
        let extra_args_len = extra_args.length();
        if (extra_args_len == 0) {
            // If extra args are empty, generate default values. Out-of-order is always true.
            (
                dest_chain_config.default_tx_gas_limit as u256,
                ALLOW_OUT_OF_ORDER_EXECUTION
            )
        } else {
            assert!(
                extra_args_len >= 4,
                error::invalid_argument(E_INVALID_EXTRA_ARGS_DATA)
            );

            let args_tag = extra_args.slice(0, 4);
            assert!(
                args_tag == client::generic_extra_args_v2_tag(),
                error::invalid_argument(E_INVALID_EXTRA_ARGS_TAG)
            );

            let args_data = extra_args.slice(4, extra_args_len);
            decode_generic_extra_args_v2(args_data)
        }
    }

    inline fun decode_generic_extra_args_v2(extra_args: vector<u8>): (u256, bool) {
        let stream = bcs_stream::new(extra_args);
        let gas_limit = bcs_stream::deserialize_u256(&mut stream);
        let allow_out_of_order_execution = bcs_stream::deserialize_bool(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (gas_limit, allow_out_of_order_execution)
    }

    inline fun decode_svm_extra_args(
        extra_args: vector<u8>
    ): (
        u32, u64, bool, vector<u8>, vector<vector<u8>>
    ) {
        let extra_args_len = extra_args.length();
        assert!(extra_args_len >= 4, error::invalid_argument(E_INVALID_EXTRA_ARGS_DATA));

        let args_tag = extra_args.slice(0, 4);
        assert!(
            args_tag == client::svm_extra_args_v1_tag(),
            error::invalid_argument(E_INVALID_EXTRA_ARGS_TAG)
        );
        let args_data = extra_args.slice(4, extra_args_len);
        decode_svm_extra_args_v1(args_data)
    }

    inline fun decode_svm_extra_args_v1(
        extra_args: vector<u8>
    ): (
        u32, u64, bool, vector<u8>, vector<vector<u8>>
    ) {
        let stream = bcs_stream::new(extra_args);
        let compute_units = bcs_stream::deserialize_u32(&mut stream);
        let account_is_writable_bitmap = bcs_stream::deserialize_u64(&mut stream);
        let allow_out_of_order_execution = bcs_stream::deserialize_bool(&mut stream);
        let token_receiver = bcs_stream::deserialize_vector_u8(&mut stream);
        let accounts =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        bcs_stream::assert_is_consumed(&stream);
        (
            compute_units,
            account_is_writable_bitmap,
            allow_out_of_order_execution,
            token_receiver,
            accounts
        )
    }

    inline fun get_data_availability_cost(
        dest_chain_config: &DestChainConfig,
        data_availability_gas_price: u256,
        data_len: u64,
        tokens_len: u64,
        total_transfer_bytes_overhead: u32
    ): u256 {
        let data_availability_length_bytes =
            MESSAGE_FIXED_BYTES + data_len + (tokens_len
                * MESSAGE_FIXED_BYTES_PER_TOKEN)
                + (total_transfer_bytes_overhead as u64);

        let data_availability_gas =
            ((data_availability_length_bytes as u256)
                * (dest_chain_config.dest_gas_per_data_availability_byte as u256)) + (
                dest_chain_config.dest_data_availability_overhead_gas as u256
            );

        data_availability_gas * data_availability_gas_price
            * (dest_chain_config.dest_data_availability_multiplier_bps as u256)
            * VAL_1E14
    }

    inline fun get_token_transfer_cost(
        state: &FeeQuoterState,
        dest_chain_config: &DestChainConfig,
        dest_chain_selector: u64,
        fee_token: address,
        fee_token_price: TimestampedPrice,
        local_token_addresses: vector<address>,
        local_token_amounts: vector<u64>
    ): (u256, u32, u32) {
        let token_transfer_fee_wei: u256 = 0;
        let token_transfer_gas: u32 = 0;
        let token_transfer_bytes_overhead: u32 = 0;

        local_token_addresses.zip_ref(
            &local_token_amounts,
            |local_token_address, local_token_amount| {
                let local_token_address: address = *local_token_address;
                let local_token_amount: u64 = *local_token_amount;

                let transfer_fee_config =
                    get_token_transfer_fee_config_internal(
                        state, dest_chain_selector, local_token_address
                    );

                if (!transfer_fee_config.is_enabled) {
                    token_transfer_fee_wei +=(
                        (dest_chain_config.default_token_fee_usd_cents as u256)
                            * VAL_1E16
                    );
                    token_transfer_gas += dest_chain_config.default_token_dest_gas_overhead;
                    token_transfer_bytes_overhead += CCIP_LOCK_OR_BURN_V1_RET_BYTES;
                } else {
                    let bps_fee_usd_wei = 0;
                    if (transfer_fee_config.deci_bps > 0) {
                        let token_price =
                            if (local_token_address == fee_token) {
                                fee_token_price
                            } else {
                                get_token_price_internal(state, local_token_address)
                            };
                        let token_usd_value =
                            calc_usd_value_from_token_amount(
                                local_token_amount, token_price.value
                            );
                        bps_fee_usd_wei =
                            (token_usd_value * (transfer_fee_config.deci_bps as u256))
                                / VAL_1E5;
                    };

                    token_transfer_gas += transfer_fee_config.dest_gas_overhead;
                    token_transfer_bytes_overhead += transfer_fee_config.dest_bytes_overhead;

                    let min_fee_usd_wei =
                        (transfer_fee_config.min_fee_usd_cents as u256) * VAL_1E16;
                    let max_fee_usd_wei =
                        (transfer_fee_config.max_fee_usd_cents as u256) * VAL_1E16;
                    let selected_fee_usd_wei =
                        if (bps_fee_usd_wei < min_fee_usd_wei) {
                            min_fee_usd_wei
                        } else if (bps_fee_usd_wei > max_fee_usd_wei) {
                            max_fee_usd_wei
                        } else {
                            bps_fee_usd_wei
                        };
                    token_transfer_fee_wei += selected_fee_usd_wei;
                }
            }
        );

        (token_transfer_fee_wei, token_transfer_gas, token_transfer_bytes_overhead)
    }

    inline fun calc_usd_value_from_token_amount(
        token_amount: u64, token_price: u256
    ): u256 {
        (token_amount as u256) * token_price / VAL_1E18
    }

    #[view]
    public fun get_token_receiver(
        dest_chain_selector: u64, extra_args: vector<u8>, message_receiver: vector<u8>
    ): vector<u8> acquires FeeQuoterState {
        let chain_family_selector =
            get_dest_chain_config_internal(borrow_state(), dest_chain_selector).chain_family_selector;
        if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM
            || chain_family_selector == CHAIN_FAMILY_SELECTOR_APTOS
            || chain_family_selector == CHAIN_FAMILY_SELECTOR_SUI) {
            message_receiver
        } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM) {
            let (
                _compute_units,
                _account_is_writable_bitmap,
                _allow_out_of_order_execution,
                token_receiver,
                _accounts
            ) = decode_svm_extra_args(extra_args);
            token_receiver
        } else {
            abort error::invalid_argument(E_UNKNOWN_CHAIN_FAMILY_SELECTOR)
        }
    }

    #[view]
    /// @returns (msg_fee_juels, is_out_of_order_execution, converted_extra_args, dest_exec_data_per_token)
    public fun process_message_args(
        dest_chain_selector: u64,
        fee_token: address,
        fee_token_amount: u64,
        extra_args: vector<u8>,
        local_token_addresses: vector<address>,
        dest_token_addresses: vector<vector<u8>>,
        dest_pool_datas: vector<vector<u8>>
    ): (
        u256, bool, vector<u8>, vector<vector<u8>>
    ) acquires FeeQuoterState {
        let state = borrow_state();
        // This is the fee in Aptos denomination. We convert it to juels (1e18 based) below.
        let msg_fee_link_local_denomination =
            if (fee_token == state.link_token) {
                fee_token_amount
            } else {
                convert_token_amount_internal(
                    state,
                    fee_token,
                    fee_token_amount,
                    state.link_token
                )
            };

        // We convert the local denomination to juels here. This means that the offchain monitoring will always
        // get a consistent juels amount regardless of the token denomination on the chain.
        let msg_fee_juels =
            (msg_fee_link_local_denomination as u256)
                * LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER;

        // max_fee_juels_per_msg is in juels denomination for consistency across chains.
        assert!(
            msg_fee_juels <= state.max_fee_juels_per_msg,
            error::invalid_argument(E_MESSAGE_FEE_TOO_HIGH)
        );

        let dest_chain_config = get_dest_chain_config_internal(
            state, dest_chain_selector
        );

        let (converted_extra_args, is_out_of_order_execution) =
            process_chain_family_selector(
                dest_chain_config, !dest_token_addresses.is_empty(), extra_args
            );

        let dest_exec_data_per_token =
            process_pool_return_data(
                state,
                dest_chain_config,
                dest_chain_selector,
                local_token_addresses,
                dest_token_addresses,
                dest_pool_datas
            );

        (
            msg_fee_juels,
            is_out_of_order_execution,
            converted_extra_args,
            dest_exec_data_per_token
        )
    }

    inline fun process_chain_family_selector(
        dest_chain_config: &DestChainConfig,
        is_message_with_token_transfers: bool,
        extra_args: vector<u8>
    ): (vector<u8>, bool) {
        let chain_family_selector = dest_chain_config.chain_family_selector;
        if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM
            || chain_family_selector == CHAIN_FAMILY_SELECTOR_APTOS
            || chain_family_selector == CHAIN_FAMILY_SELECTOR_SUI) {
            let (gas_limit, _allow_out_of_order_execution) =
                decode_generic_extra_args(dest_chain_config, extra_args);
            let extra_args_v2 =
                client::encode_generic_extra_args_v2(
                    gas_limit, ALLOW_OUT_OF_ORDER_EXECUTION
                );
            (extra_args_v2, ALLOW_OUT_OF_ORDER_EXECUTION)
        } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM) {
            let (
                compute_units,
                _account_is_writable_bitmap,
                _allow_out_of_order_execution,
                token_receiver,
                _accounts
            ) = decode_svm_extra_args(extra_args);
            if (is_message_with_token_transfers) {
                assert!(
                    token_receiver.length() == 32,
                    error::invalid_argument(E_INVALID_TOKEN_RECEIVER)
                );
                let token_receiver_uint = eth_abi::decode_u256_value(token_receiver);
                assert!(
                    token_receiver_uint > 0,
                    error::invalid_argument(E_INVALID_TOKEN_RECEIVER)
                );
            };

            assert!(
                compute_units <= dest_chain_config.max_per_msg_gas_limit,
                error::invalid_argument(E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH)
            );

            (extra_args, ALLOW_OUT_OF_ORDER_EXECUTION)
        } else {
            abort error::invalid_argument(E_UNKNOWN_CHAIN_FAMILY_SELECTOR)
        }
    }

    inline fun process_pool_return_data(
        state: &FeeQuoterState,
        dest_chain_config: &DestChainConfig,
        dest_chain_selector: u64,
        local_token_addresses: vector<address>,
        dest_token_addresses: vector<vector<u8>>,
        dest_pool_datas: vector<vector<u8>>
    ): vector<vector<u8>> {
        let chain_family_selector = dest_chain_config.chain_family_selector;

        let tokens_len = dest_token_addresses.length();
        assert!(
            tokens_len == dest_pool_datas.length(),
            error::invalid_argument(E_TOKEN_AMOUNT_MISMATCH)
        );

        let dest_exec_data_per_token = vector[];
        for (i in 0..tokens_len) {
            let local_token_address = local_token_addresses[i];
            let dest_token_address = dest_token_addresses[i];
            let dest_pool_data_len = dest_pool_datas[i].length();

            let token_transfer_fee_config =
                get_token_transfer_fee_config_internal(
                    state, dest_chain_selector, local_token_address
                );
            if (dest_pool_data_len > (CCIP_LOCK_OR_BURN_V1_RET_BYTES as u64)) {
                assert!(
                    dest_pool_data_len
                        <= (token_transfer_fee_config.dest_bytes_overhead as u64),
                    error::invalid_argument(E_SOURCE_TOKEN_DATA_TOO_LARGE)
                );
            };

            // We pass in 1 as gas_limit as this only matters for SVM address validation. This ensures the address
            // may not be 0x0.
            validate_dest_family_address(chain_family_selector, dest_token_address, 1);

            let dest_gas_amount =
                if (token_transfer_fee_config.is_enabled) {
                    token_transfer_fee_config.dest_gas_overhead
                } else {
                    dest_chain_config.default_token_dest_gas_overhead
                };

            let dest_exec_data = bcs::to_bytes(&dest_gas_amount);
            dest_exec_data_per_token.push_back(dest_exec_data);
        };

        dest_exec_data_per_token
    }

    #[view]
    public fun get_dest_chain_config(
        dest_chain_selector: u64
    ): DestChainConfig acquires FeeQuoterState {
        *get_dest_chain_config_internal(borrow_state(), dest_chain_selector)
    }

    inline fun get_dest_chain_config_internal(
        state: &FeeQuoterState, dest_chain_selector: u64
    ): &DestChainConfig {
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        state.dest_chain_configs.borrow(dest_chain_selector)
    }

    public entry fun apply_dest_chain_config_updates(
        caller: &signer,
        dest_chain_selector: u64,
        is_enabled: bool,
        max_number_of_tokens_per_msg: u16,
        max_data_bytes: u32,
        max_per_msg_gas_limit: u32,
        dest_gas_overhead: u32,
        dest_gas_per_payload_byte_base: u8,
        dest_gas_per_payload_byte_high: u8,
        dest_gas_per_payload_byte_threshold: u16,
        dest_data_availability_overhead_gas: u32,
        dest_gas_per_data_availability_byte: u16,
        dest_data_availability_multiplier_bps: u16,
        chain_family_selector: vector<u8>,
        enforce_out_of_order: bool,
        default_token_fee_usd_cents: u16,
        default_token_dest_gas_overhead: u32,
        default_tx_gas_limit: u32,
        gas_multiplier_wei_per_eth: u64,
        gas_price_staleness_threshold: u32,
        network_fee_usd_cents: u32
    ) acquires FeeQuoterState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        assert!(
            dest_chain_selector != 0,
            error::invalid_argument(E_INVALID_DEST_CHAIN_SELECTOR)
        );
        assert!(
            default_tx_gas_limit != 0 && default_tx_gas_limit <= max_per_msg_gas_limit,
            error::invalid_argument(E_INVALID_GAS_LIMIT)
        );

        assert!(
            chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM
                || chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM
                || chain_family_selector == CHAIN_FAMILY_SELECTOR_APTOS
                || chain_family_selector == CHAIN_FAMILY_SELECTOR_SUI,
            error::invalid_argument(E_INVALID_CHAIN_FAMILY_SELECTOR)
        );

        let dest_chain_config = DestChainConfig {
            is_enabled,
            max_number_of_tokens_per_msg,
            max_data_bytes,
            max_per_msg_gas_limit,
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            chain_family_selector,
            enforce_out_of_order,
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            default_tx_gas_limit,
            gas_multiplier_wei_per_eth,
            gas_price_staleness_threshold,
            network_fee_usd_cents
        };

        if (state.dest_chain_configs.contains(dest_chain_selector)) {
            let dest_chain_config_ref =
                state.dest_chain_configs.borrow_mut(dest_chain_selector);
            *dest_chain_config_ref = dest_chain_config;
            event::emit_event(
                &mut state.dest_chain_config_updated_events,
                DestChainConfigUpdated { dest_chain_selector, dest_chain_config }
            );
        } else {
            state.dest_chain_configs.add(dest_chain_selector, dest_chain_config);
            event::emit_event(
                &mut state.dest_chain_added_events,
                DestChainAdded { dest_chain_selector, dest_chain_config }
            );
        }
    }

    #[view]
    public fun get_static_config(): StaticConfig acquires FeeQuoterState {
        let state = borrow_state();
        StaticConfig {
            max_fee_juels_per_msg: state.max_fee_juels_per_msg,
            link_token: state.link_token,
            token_price_staleness_threshold: state.token_price_staleness_threshold
        }
    }

    inline fun borrow_state(): &FeeQuoterState {
        borrow_global<FeeQuoterState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut FeeQuoterState {
        borrow_global_mut<FeeQuoterState>(state_object::object_address())
    }

    inline fun get_validated_token_price(
        state: &FeeQuoterState, token: address
    ): TimestampedPrice {
        let token_price = get_token_price_internal(state, token);
        assert!(
            token_price.value > 0 && token_price.timestamp > 0,
            error::invalid_state(E_TOKEN_NOT_SUPPORTED)
        );
        token_price
    }

    // Token prices can be stale. On EVM we have additional fallbacks to a price feed, if configured. Since these
    // fallbacks don't exist on Aptos, we simply return the price as is.
    inline fun get_token_price_internal(
        state: &FeeQuoterState, token: address
    ): TimestampedPrice {
        assert!(
            state.usd_per_token.contains(token),
            error::invalid_argument(E_UNKNOWN_TOKEN)
        );
        *state.usd_per_token.borrow(token)
    }

    inline fun get_dest_chain_gas_price_internal(
        state: &FeeQuoterState, dest_chain_selector: u64
    ): TimestampedPrice {
        assert!(
            state.usd_per_unit_gas_by_dest_chain.contains(dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        *state.usd_per_unit_gas_by_dest_chain.borrow(dest_chain_selector)
    }

    inline fun get_validated_gas_price_internal(
        state: &FeeQuoterState, dest_chain_config: &DestChainConfig, dest_chain_selector: u64
    ): u256 {
        let gas_price = get_dest_chain_gas_price_internal(state, dest_chain_selector);
        if (dest_chain_config.gas_price_staleness_threshold > 0) {
            let time_passed_seconds = timestamp::now_seconds() - gas_price.timestamp;
            assert!(
                time_passed_seconds
                    <= (dest_chain_config.gas_price_staleness_threshold as u64),
                error::invalid_state(E_STALE_GAS_PRICE)
            );
        };
        gas_price.value
    }

    inline fun convert_token_amount_internal(
        state: &FeeQuoterState,
        from_token: address,
        from_token_amount: u64,
        to_token: address
    ): u64 {
        let from_token_price = get_validated_token_price(state, from_token);
        let to_token_price = get_validated_token_price(state, to_token);
        let to_token_amount =
            ((from_token_amount as u256) * from_token_price.value) / to_token_price.value;
        assert!(
            to_token_amount <= MAX_U64,
            error::invalid_argument(E_TO_TOKEN_AMOUNT_TOO_LARGE)
        );
        to_token_amount as u64
    }

    inline fun validate_message(
        dest_chain_config: &DestChainConfig, data_len: u64, tokens_len: u64
    ) {
        assert!(
            data_len <= (dest_chain_config.max_data_bytes as u64),
            error::invalid_argument(E_MESSAGE_TOO_LARGE)
        );
        assert!(
            tokens_len <= (dest_chain_config.max_number_of_tokens_per_msg as u64),
            error::invalid_argument(E_UNSUPPORTED_NUMBER_OF_TOKENS)
        );
    }

    inline fun validate_dest_family_address(
        chain_family_selector: vector<u8>, encoded_address: vector<u8>, gas_limit: u256
    ) {
        if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM) {
            validate_evm_address(encoded_address);
        } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM) {
            // SVM addresses don't have a precompile space at the first X addresses, instead we validate that if the gasLimit
            // is non-zero, the address must not be 0x0.
            let min_address = 0;
            if (gas_limit > 0) {
                min_address = 1;
            };
            validate_32byte_address(encoded_address, min_address);
        } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_APTOS
            || chain_family_selector == CHAIN_FAMILY_SELECTOR_SUI) {
            validate_32byte_address(encoded_address, MOVE_PRECOMPILE_SPACE);
        };
    }

    inline fun validate_evm_address(encoded_address: vector<u8>) {
        assert!(
            encoded_address.length() == 32,
            error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );

        let encoded_address_uint = eth_abi::decode_u256_value(encoded_address);

        assert!(
            encoded_address_uint >= EVM_PRECOMPILE_SPACE,
            error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );
        assert!(
            encoded_address_uint <= MAX_U160,
            error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );
    }

    inline fun validate_32byte_address(
        encoded_address: vector<u8>, min_value: u256
    ) {
        assert!(
            encoded_address.length() == 32,
            error::invalid_argument(E_INVALID_32BYTES_ADDRESS)
        );

        let encoded_address_uint = eth_abi::decode_u256_value(encoded_address);
        assert!(
            encoded_address_uint >= min_value,
            error::invalid_argument(E_INVALID_32BYTES_ADDRESS)
        );
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires FeeQuoterState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let max_fee_juels_per_msg = bcs_stream::deserialize_u256(&mut stream);
            let link_token = bcs_stream::deserialize_address(&mut stream);
            let token_price_staleness_threshold = bcs_stream::deserialize_u64(
                &mut stream
            );
            let fee_tokens =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            initialize(
                &caller,
                max_fee_juels_per_msg,
                link_token,
                token_price_staleness_threshold,
                fee_tokens
            )
        } else if (function_bytes == b"apply_fee_token_updates") {
            let fee_tokens_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let fee_tokens_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_fee_token_updates(&caller, fee_tokens_to_remove, fee_tokens_to_add)
        } else if (function_bytes == b"apply_token_transfer_fee_config_updates") {
            let dest_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let add_tokens =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let add_min_fee_usd_cents =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u32(stream)
                );
            let add_max_fee_usd_cents =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u32(stream)
                );
            let add_deci_bps =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u16(stream)
                );
            let add_dest_gas_overhead =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u32(stream)
                );
            let add_dest_bytes_overhead =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u32(stream)
                );
            let add_is_enabled =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let remove_tokens =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_token_transfer_fee_config_updates(
                &caller,
                dest_chain_selector,
                add_tokens,
                add_min_fee_usd_cents,
                add_max_fee_usd_cents,
                add_deci_bps,
                add_dest_gas_overhead,
                add_dest_bytes_overhead,
                add_is_enabled,
                remove_tokens
            )
        } else if (function_bytes == b"update_prices") {
            let source_tokens =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let source_usd_per_token =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u256(stream)
                );
            let gas_dest_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let gas_usd_per_unit_gas =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u256(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            update_prices(
                &caller,
                source_tokens,
                source_usd_per_token,
                gas_dest_chain_selectors,
                gas_usd_per_unit_gas
            )
        } else if (function_bytes == b"apply_premium_multiplier_wei_per_eth_updates") {
            let tokens =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let premium_multiplier_wei_per_eth =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_premium_multiplier_wei_per_eth_updates(
                &caller, tokens, premium_multiplier_wei_per_eth
            )
        } else if (function_bytes == b"apply_dest_chain_config_updates") {
            let dest_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let is_enabled = bcs_stream::deserialize_bool(&mut stream);
            let max_number_of_tokens_per_msg = bcs_stream::deserialize_u16(&mut stream);
            let max_data_bytes = bcs_stream::deserialize_u32(&mut stream);
            let max_per_msg_gas_limit = bcs_stream::deserialize_u32(&mut stream);
            let dest_gas_overhead = bcs_stream::deserialize_u32(&mut stream);
            let dest_gas_per_payload_byte_base = bcs_stream::deserialize_u8(&mut stream);
            let dest_gas_per_payload_byte_high = bcs_stream::deserialize_u8(&mut stream);
            let dest_gas_per_payload_byte_threshold =
                bcs_stream::deserialize_u16(&mut stream);
            let dest_data_availability_overhead_gas =
                bcs_stream::deserialize_u32(&mut stream);
            let dest_gas_per_data_availability_byte =
                bcs_stream::deserialize_u16(&mut stream);
            let dest_data_availability_multiplier_bps =
                bcs_stream::deserialize_u16(&mut stream);
            let chain_family_selector =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u8(stream)
                );
            let enforce_out_of_order = bcs_stream::deserialize_bool(&mut stream);
            let default_token_fee_usd_cents = bcs_stream::deserialize_u16(&mut stream);
            let default_token_dest_gas_overhead = bcs_stream::deserialize_u32(
                &mut stream
            );
            let default_tx_gas_limit = bcs_stream::deserialize_u32(&mut stream);
            let gas_multiplier_wei_per_eth = bcs_stream::deserialize_u64(&mut stream);
            let gas_price_staleness_threshold = bcs_stream::deserialize_u32(&mut stream);
            let network_fee_usd_cents = bcs_stream::deserialize_u32(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            apply_dest_chain_config_updates(
                &caller,
                dest_chain_selector,
                is_enabled,
                max_number_of_tokens_per_msg,
                max_data_bytes,
                max_per_msg_gas_limit,
                dest_gas_overhead,
                dest_gas_per_payload_byte_base,
                dest_gas_per_payload_byte_high,
                dest_gas_per_payload_byte_threshold,
                dest_data_availability_overhead_gas,
                dest_gas_per_data_availability_byte,
                dest_data_availability_multiplier_bps,
                chain_family_selector,
                enforce_out_of_order,
                default_token_fee_usd_cents,
                default_token_dest_gas_overhead,
                default_tx_gas_limit,
                gas_multiplier_wei_per_eth,
                gas_price_staleness_threshold,
                network_fee_usd_cents
            )
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"fee_quoter"), McmsCallback {}
        );
    }

    public fun dest_chain_config_values(
        config: DestChainConfig
    ): (
        bool,
        u16,
        u32,
        u32,
        u32,
        u8,
        u8,
        u16,
        u32,
        u16,
        u16,
        vector<u8>,
        bool,
        u16,
        u32,
        u32,
        u64,
        u32,
        u32
    ) {
        (
            config.is_enabled,
            config.max_number_of_tokens_per_msg,
            config.max_data_bytes,
            config.max_per_msg_gas_limit,
            config.dest_gas_overhead,
            config.dest_gas_per_payload_byte_base,
            config.dest_gas_per_payload_byte_high,
            config.dest_gas_per_payload_byte_threshold,
            config.dest_data_availability_overhead_gas,
            config.dest_gas_per_data_availability_byte,
            config.dest_data_availability_multiplier_bps,
            config.chain_family_selector,
            config.enforce_out_of_order,
            config.default_token_fee_usd_cents,
            config.default_token_dest_gas_overhead,
            config.default_tx_gas_limit,
            config.gas_multiplier_wei_per_eth,
            config.gas_price_staleness_threshold,
            config.network_fee_usd_cents
        )
    }

    public fun token_transfer_fee_config_values(
        config: TokenTransferFeeConfig
    ): (u32, u32, u16, u32, u32, bool) {
        (
            config.min_fee_usd_cents,
            config.max_fee_usd_cents,
            config.deci_bps,
            config.dest_gas_overhead,
            config.dest_bytes_overhead,
            config.is_enabled
        )
    }

    // ========================== TEST ONLY ==========================
    #[test_only]
    public fun test_register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"fee_quoter"), McmsCallback {}
        );
    }

    #[test_only]
    public fun test_decode_svm_extra_args(
        extra_args: vector<u8>
    ): (
        u32, u64, bool, vector<u8>, vector<vector<u8>>
    ) {
        decode_svm_extra_args(extra_args)
    }

    #[test_only]
    public fun test_decode_generic_extra_args(
        dest_chain_config: &DestChainConfig, extra_args: vector<u8>
    ): (u256, bool) {
        decode_generic_extra_args(dest_chain_config, extra_args)
    }

    #[test_only]
    public fun test_decode_generic_extra_args_v2(extra_args: vector<u8>): (u256, bool) {
        decode_generic_extra_args_v2(extra_args)
    }

    #[test_only]
    public fun test_decode_svm_extra_args_v1(
        extra_args: vector<u8>
    ): (
        u32, u64, bool, vector<u8>, vector<vector<u8>>
    ) {
        decode_svm_extra_args_v1(extra_args)
    }

    #[test_only]
    public fun test_create_dest_chain_config(
        is_enabled: bool,
        max_number_of_tokens_per_msg: u16,
        max_data_bytes: u32,
        max_per_msg_gas_limit: u32,
        dest_gas_overhead: u32,
        dest_gas_per_payload_byte_base: u8,
        dest_gas_per_payload_byte_high: u8,
        dest_gas_per_payload_byte_threshold: u16,
        dest_data_availability_overhead_gas: u32,
        dest_gas_per_data_availability_byte: u16,
        dest_data_availability_multiplier_bps: u16,
        chain_family_selector: vector<u8>,
        enforce_out_of_order: bool,
        default_token_fee_usd_cents: u16,
        default_token_dest_gas_overhead: u32,
        default_tx_gas_limit: u32,
        gas_multiplier_wei_per_eth: u64,
        gas_price_staleness_threshold: u32,
        network_fee_usd_cents: u32
    ): DestChainConfig {
        DestChainConfig {
            is_enabled,
            max_number_of_tokens_per_msg,
            max_data_bytes,
            max_per_msg_gas_limit,
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            chain_family_selector,
            enforce_out_of_order,
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            default_tx_gas_limit,
            gas_multiplier_wei_per_eth,
            gas_price_staleness_threshold,
            network_fee_usd_cents
        }
    }
}
