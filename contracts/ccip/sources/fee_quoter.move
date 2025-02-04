/// This module is responsible for storage and retrieval of fee token and token transfer
/// information and pricing.
///
/// TODO:
/// at the moment, this module updates prices from received OCR3 reports.
/// on EVM, the FeeQuoter contract takes the newer value between the prices stored locally
/// (which are from OCR3 reports or from keystone reports), and that of a configured OCR2
/// data feed price value.
/// on Aptos, we have keystone feeds only and could:
/// - allow configuration of feed_ids to query the keystone feeds router/registry module
/// - support dynamic dispatch registration with the keystone forwarder module to receive
///   keystone reports directly.
/// only one of the two should be necessary since the data source for both should be the same
/// (ie. keystone reports) and contain the same data points.
/// the first option should be preferred since it does not require additional complexity with
/// dynamic dispatch and additional report deserialization.
module ccip::fee_quoter {
    use std::account;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::Metadata;
    use std::object::{Self, Object};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::timestamp;
    use std::vector;

    use ccip::client;
    use ccip::eth_abi;
    use ccip::ownable;
    use ccip::state_object;

    friend ccip::offramp;
    friend ccip::onramp;

    const CHAIN_FAMILY_SELECTOR_EVM: vector<u8> = x"2812d52c";
    const CHAIN_FAMILY_SELECTOR_SVM: vector<u8> = x"1e10bdc4";

    const EVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"97a657c9";
    const EVM_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
    const EVM_PRECOMPILE_SPACE: u256 = 1024;

    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";

    const GAS_PRICE_BITS: u8 = 112;

    const MESSAGE_FIXED_BYTES: u64 = 32 * 15;
    const MESSAGE_FIXED_BYTES_PER_TOKEN: u64 = 32 * (4 + (3 + 2));

    const CCIP_LOCK_OR_BURN_V1_RET_BYTES: u32 = 32;

    const MAX_U64: u256 = 18446744073709551615;
    const MAX_U160: u256 = 1461501637330902918203684832716283019655932542975;
    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const VAL_1E5: u256 = 100_000;
    const VAL_1E14: u256 = 100_000_000_000_000;
    const VAL_1E16: u256 = 10_000_000_000_000_000;
    const VAL_1E18: u256 = 1_000_000_000_000_000_000;

    struct FeeQuoterState has key, store {
        ownable_state: ownable::OwnableState,
        max_fee_juels_per_msg: u128,
        link_token: address,
        token_price_staleness_threshold: u64,
        fee_tokens: vector<address>,
        usd_per_unit_gas_by_dest_chain: SmartTable<u64, TimestampedPrice>,
        usd_per_token: SmartTable<address, TimestampedPrice>,
        dest_chain_configs: SmartTable<u64, DestChainConfig>,
        // dest chain selector -> local token -> TokenTransferFeeConfig
        token_transfer_fee_configs: SmartTable<u64, SmartTable<address, TokenTransferFeeConfig>>,
        // TODO: should this be octa per apt?
        premium_multiplier_wei_per_eth: SmartTable<address, u64>,
        fee_token_added_events: EventHandle<FeeTokenAdded>,
        fee_token_removed_events: EventHandle<FeeTokenRemoved>,
        token_transfer_fee_config_added_events: EventHandle<TokenTransferFeeConfigAdded>,
        token_transfer_fee_config_removed_events: EventHandle<TokenTransferFeeConfigRemoved>,
        usd_per_token_updated_events: EventHandle<UsdPerTokenUpdated>,
        usd_per_unit_gas_updated_events: EventHandle<UsdPerUnitGasUpdated>
    }

    struct StaticConfig has drop {
        max_fee_juels_per_msg: u128,
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
        // TODO: should this be octa per apt?
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
        price: u256,
        timestamp_secs: u64
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
    const E_INVALID_SVM_ADDRESS: u64 = 16;
    const E_FEE_TOKEN_COST_TOO_HIGH: u64 = 17;
    const E_MESSAGE_GAS_LIMIT_TOO_HIGH: u64 = 18;
    const E_EXTRA_ARG_OUT_OF_ORDER_EXECUTION_MUST_BE_TRUE: u64 = 19;
    const E_INVALID_EXTRA_ARGS_TAG: u64 = 20;
    const E_INVALID_EXTRA_ARGS_DATA: u64 = 21;
    const E_INVALID_TOKEN_RECEIVER: u64 = 22;
    const E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH: u64 = 23;

    public entry fun initialize(
        caller: &signer,
        max_fee_juels_per_msg: u128,
        link_token: address,
        token_price_staleness_threshold: u64,
        fee_tokens: vector<address>
    ) {
        state_object::assert_can_initialize(caller);

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
            ownable_state: ownable::new(
                &state_object_signer, signer::address_of(caller), @0x0
            ),
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
            )
        };
        move_to(&state_object_signer, state);
    }

    #[view]
    public fun get_token_price(token: address): TimestampedPrice acquires FeeQuoterState {
        get_token_price_internal(borrow_state(), token)
    }

    #[view]
    public fun get_token_prices(
        tokens: vector<address>
    ): (vector<TimestampedPrice>) acquires FeeQuoterState {
        let state = borrow_state();
        vector::map_ref(&tokens, |token| get_token_price_internal(state, *token))
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
        (token_price.price, gas_price_value)
    }

    #[view]
    public fun convert_token_amount(
        from_token: address, from_token_amount: u256, to_token: address
    ): u256 acquires FeeQuoterState {
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
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        // Remove tokens
        vector::for_each_ref(
            &fee_tokens_to_remove,
            |fee_token| {
                let fee_token = *fee_token;
                let (found, index) = vector::index_of(&state.fee_tokens, &fee_token);
                if (found) {
                    vector::remove(&mut state.fee_tokens, index);
                    event::emit(FeeTokenRemoved { fee_token });
                    event::emit_event(
                        &mut state.fee_token_removed_events,
                        FeeTokenRemoved { fee_token }
                    );
                };
            }
        );

        // Add new tokens
        vector::for_each_ref(
            &fee_tokens_to_add,
            |fee_token| {
                let fee_token = *fee_token;
                let (found, _) = vector::index_of(&state.fee_tokens, &fee_token);
                if (!found) {
                    vector::push_back(&mut state.fee_tokens, fee_token);
                    event::emit(FeeTokenAdded { fee_token });
                    event::emit_event(
                        &mut state.fee_token_added_events,
                        FeeTokenAdded { fee_token }
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
        assert!(
            smart_table::contains(
                &state.token_transfer_fee_configs, dest_chain_selector
            ),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        let dest_chain_fee_configs =
            smart_table::borrow(&state.token_transfer_fee_configs, dest_chain_selector);
        assert!(
            smart_table::contains(dest_chain_fee_configs, token),
            error::invalid_argument(E_TOKEN_NOT_SUPPORTED)
        );
        smart_table::borrow(dest_chain_fee_configs, token)
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
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);
        if (!smart_table::contains(
            &state.token_transfer_fee_configs, dest_chain_selector
        )) {
            smart_table::add(
                &mut state.token_transfer_fee_configs,
                dest_chain_selector,
                smart_table::new()
            );
        };
        let token_transfer_fee_configs =
            smart_table::borrow_mut(
                &mut state.token_transfer_fee_configs, dest_chain_selector
            );

        let add_tokens_len = vector::length(&add_tokens);
        assert!(
            add_tokens_len == vector::length(&add_min_fee_usd_cents),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == vector::length(&add_max_fee_usd_cents),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == vector::length(&add_deci_bps),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == vector::length(&add_dest_gas_overhead),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == vector::length(&add_dest_bytes_overhead),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );
        assert!(
            add_tokens_len == vector::length(&add_is_enabled),
            error::invalid_argument(E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH)
        );

        let i = 0;
        while (i < add_tokens_len) {
            let token = *vector::borrow(&add_tokens, i);
            let min_fee_usd_cents = *vector::borrow(&add_min_fee_usd_cents, i);
            let max_fee_usd_cents = *vector::borrow(&add_max_fee_usd_cents, i);
            let deci_bps = *vector::borrow(&add_deci_bps, i);
            let dest_gas_overhead = *vector::borrow(&add_dest_gas_overhead, i);
            let dest_bytes_overhead = *vector::borrow(&add_dest_bytes_overhead, i);
            let is_enabled = *vector::borrow(&add_is_enabled, i);

            let token_transfer_fee_config = TokenTransferFeeConfig {
                min_fee_usd_cents,
                max_fee_usd_cents,
                deci_bps,
                dest_gas_overhead,
                dest_bytes_overhead,
                is_enabled
            };

            smart_table::add(
                token_transfer_fee_configs, token, token_transfer_fee_config
            );

            event::emit(
                TokenTransferFeeConfigAdded {
                    dest_chain_selector,
                    token,
                    token_transfer_fee_config
                }
            );
            event::emit_event(
                &mut state.token_transfer_fee_config_added_events,
                TokenTransferFeeConfigAdded {
                    dest_chain_selector,
                    token,
                    token_transfer_fee_config
                }
            );

            i = i + 1;
        };

        vector::for_each_ref(
            &remove_tokens,
            |token| {
                let token: address = *token;
                if (smart_table::contains(token_transfer_fee_configs, token)) {
                    smart_table::remove(token_transfer_fee_configs, token);

                    event::emit(
                        TokenTransferFeeConfigRemoved { dest_chain_selector, token }
                    );
                    event::emit_event(
                        &mut state.token_transfer_fee_config_removed_events,
                        TokenTransferFeeConfigRemoved { dest_chain_selector, token }
                    );
                }
            }
        );
    }

    public(friend) fun update_prices(
        source_tokens: vector<address>,
        source_usd_per_token: vector<u256>,
        gas_dest_chain_selectors: vector<u64>,
        gas_usd_per_unit_gas: vector<u256>
    ) acquires FeeQuoterState {
        assert!(
            vector::length(&source_tokens) == vector::length(&source_usd_per_token),
            error::invalid_argument(E_TOKEN_UPDATE_MISMATCH)
        );
        assert!(
            vector::length(&gas_dest_chain_selectors)
                == vector::length(&gas_usd_per_unit_gas),
            error::invalid_argument(E_GAS_UPDATE_MISMATCH)
        );

        let state = borrow_state_mut();
        let timestamp_secs = timestamp::now_seconds();

        vector::zip_ref(
            &source_tokens,
            &source_usd_per_token,
            |token, usd_per_token| {
                let timestamped_price = TimestampedPrice {
                    price: *usd_per_token,
                    timestamp_secs
                };
                smart_table::upsert(&mut state.usd_per_token, *token, timestamped_price);
                event::emit(
                    UsdPerTokenUpdated {
                        token: *token,
                        usd_per_token: *usd_per_token,
                        timestamp: timestamp_secs
                    }
                );
                event::emit_event(
                    &mut state.usd_per_token_updated_events,
                    UsdPerTokenUpdated {
                        token: *token,
                        usd_per_token: *usd_per_token,
                        timestamp: timestamp_secs
                    }
                );
            }
        );

        vector::zip_ref(
            &gas_dest_chain_selectors,
            &gas_usd_per_unit_gas,
            |dest_chain_selector, usd_per_unit_gas| {
                let timestamped_price = TimestampedPrice {
                    price: *usd_per_unit_gas,
                    timestamp_secs
                };
                smart_table::upsert(
                    &mut state.usd_per_unit_gas_by_dest_chain,
                    *dest_chain_selector,
                    timestamped_price
                );

                event::emit(
                    UsdPerUnitGasUpdated {
                        dest_chain_selector: *dest_chain_selector,
                        usd_per_unit_gas: *usd_per_unit_gas,
                        timestamp: timestamp_secs
                    }
                );
                event::emit_event(
                    &mut state.usd_per_unit_gas_updated_events,
                    UsdPerUnitGasUpdated {
                        dest_chain_selector: *dest_chain_selector,
                        usd_per_unit_gas: *usd_per_unit_gas,
                        timestamp: timestamp_secs
                    }
                );
            }
        );
    }

    // TODO: should this be public?
    public(friend) fun get_fee(
        dest_chain_selector: u64, message: &client::Aptos2AnyMessage
    ): u64 acquires FeeQuoterState {
        let (dest_chain_selector, receiver, data, fee_token, fee_token_store, extra_args) =

            client::get_aptos2any_fields(message);

        let (local_token_addresses, local_token_amounts) =
            client::get_aptos2any_token_transfers(message);

        let state = borrow_state_mut();

        let dest_chain_config = get_dest_chain_config_internal(
            state, dest_chain_selector
        );
        assert!(
            dest_chain_config.is_enabled,
            error::invalid_argument(E_DEST_CHAIN_NOT_ENABLED)
        );

        let fee_token_address = object::object_address(&fee_token);
        assert!(
            vector::contains(&state.fee_tokens, &fee_token_address),
            error::invalid_argument(E_FEE_TOKEN_NOT_SUPPORTED)
        );

        let chain_family_selector = dest_chain_config.chain_family_selector;

        let data_len = vector::length(&data);
        let tokens_len = vector::length(&local_token_addresses);
        validate_message(dest_chain_config, data_len, tokens_len);

        let gas_limit =
            if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM) {
                validate_evm_address(receiver);
                resolve_evm_gas_limit(dest_chain_config, extra_args)
            } else if (chain_family_selector == CHAIN_FAMILY_SELECTOR_SVM) {
                let require_valid_token_receiver = tokens_len > 0;
                let svm_gas_limit =
                    resolve_svm_gas_limit(
                        dest_chain_config, extra_args, require_valid_token_receiver
                    );
                let must_be_non_zero = svm_gas_limit > 0;
                validate_svm_address(receiver, must_be_non_zero);
                svm_gas_limit
            } else {
                abort error::invalid_argument(E_UNKNOWN_CHAIN_FAMILY_SELECTOR)
            };

        let fee_token_price = get_token_price_internal(state, fee_token_address);
        let packed_gas_price =
            get_validated_gas_price_internal(
                state, dest_chain_config, dest_chain_selector
            );

        // TODO: this should probably be premium_fee_usd_octa for aptos?
        let (premium_fee_usd_wei, token_transfer_gas, token_transfer_bytes_overhead) =
            if (tokens_len > 0) {
                get_token_transfer_cost(
                    state,
                    dest_chain_config,
                    dest_chain_selector,
                    fee_token_address,
                    fee_token_price,
                    local_token_addresses,
                    local_token_amounts
                )
            } else {
                ((dest_chain_config.network_fee_usd_cents as u256) * VAL_1E16, 0, 0)
            };
        let premium_multiplier =
            *smart_table::borrow(
                &state.premium_multiplier_wei_per_eth, fee_token_address
            );
        premium_fee_usd_wei = premium_fee_usd_wei * (premium_multiplier as u256);

        let data_availability_cost_usd_36_decimals =
            if (dest_chain_config.dest_data_availability_multiplier_bps > 0) {
                // TODO: on EVM, the gas price is uint224 and the top 112 bits are used. here we're using a u256
                // and expecting that the extra top 22 bits are zeroes. update this and `gas_cost` below
                // if needed.
                let data_availability_gas_price = packed_gas_price >> GAS_PRICE_BITS;
                get_data_availability_cost(
                    state,
                    dest_chain_config,
                    data_availability_gas_price,
                    data_len,
                    tokens_len,
                    token_transfer_bytes_overhead
                )
            } else { 0 };

        let call_data_length: u256 =
            (data_len as u256) * (token_transfer_bytes_overhead as u256);
        let dest_call_data_cost =
            call_data_length
                * (dest_chain_config.dest_gas_per_payload_byte_base as u256);
        if (call_data_length
            > (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)) {
            dest_call_data_cost = (
                dest_chain_config.dest_gas_per_payload_byte_base as u256
            ) * (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)
                + (
                    call_data_length
                        - (dest_chain_config.dest_gas_per_payload_byte_threshold as u256)
                ) * (dest_chain_config.dest_gas_per_payload_byte_high as u256);
        };

        let total_dest_chain_gas =
            (dest_chain_config.dest_gas_overhead as u256) + (token_transfer_gas as u256)
                + dest_call_data_cost + gas_limit;

        let gas_cost = packed_gas_price & (MAX_U256 >> (255 - GAS_PRICE_BITS + 1));

        let total_cost_usd =
            (
                total_dest_chain_gas * gas_cost
                    * (dest_chain_config.gas_multiplier_wei_per_eth as u256)
            ) + premium_fee_usd_wei + data_availability_cost_usd_36_decimals;

        let fee_token_cost = total_cost_usd / fee_token_price.price;

        // we need to convert back to a u64 which is what the fungible asset module uses for amounts.
        assert!(
            fee_token_cost <= MAX_U64, error::invalid_state(E_FEE_TOKEN_COST_TOO_HIGH)
        );
        fee_token_cost as u64
    }

    inline fun resolve_evm_gas_limit(
        dest_chain_config: &DestChainConfig, extra_args: vector<u8>
    ): u256 {
        let extra_args_len = vector::length(&extra_args);
        if (extra_args_len == 0) {
            dest_chain_config.default_tx_gas_limit as u256
        } else {
            // TODO: we need extra validation here. if extra_args length is less than tag length + data length,
            // vector::slice will revert.
            let args_tag = vector::slice(&extra_args, 0, 4);
            let args_data = vector::slice(&extra_args, 4, extra_args_len);
            let (gas_limit, allow_out_of_order_execution) =
                if (args_tag == EVM_EXTRA_ARGS_V2_TAG) {
                    decode_evm_extra_args_v2(args_data)
                } else if (args_tag == EVM_EXTRA_ARGS_V1_TAG) {
                    let stream = eth_abi::new_stream(args_data);
                    let gas_limit = eth_abi::decode_u256(&mut stream);
                    (gas_limit, false)
                } else {
                    abort error::invalid_argument(E_INVALID_EXTRA_ARGS_TAG)
                };
            assert!(
                gas_limit <= (dest_chain_config.max_per_msg_gas_limit as u256),
                error::invalid_argument(E_MESSAGE_GAS_LIMIT_TOO_HIGH)
            );
            assert!(
                !dest_chain_config.enforce_out_of_order || allow_out_of_order_execution,
                error::invalid_argument(E_EXTRA_ARG_OUT_OF_ORDER_EXECUTION_MUST_BE_TRUE)
            );
            gas_limit
        }
    }

    inline fun resolve_svm_gas_limit(
        dest_chain_config: &DestChainConfig,
        extra_args: vector<u8>,
        require_valid_token_receiver: bool
    ): u256 {
        let extra_args_len = vector::length(&extra_args);
        assert!(extra_args_len > 0, error::invalid_argument(E_INVALID_EXTRA_ARGS_DATA));

        // TODO: we need extra validation here. if extra_args length is less than tag length + data length,
        // vector::slice will revert.
        let args_tag = vector::slice(&extra_args, 0, 4);
        assert!(
            args_tag == SVM_EXTRA_ARGS_V1_TAG,
            error::invalid_argument(E_INVALID_EXTRA_ARGS_TAG)
        );
        let args_data = vector::slice(&extra_args, 4, extra_args_len);
        let (
            compute_units,
            account_is_writable_bitmap,
            allow_out_of_order_execution,
            token_receiver,
            accounts
        ) = decode_svm_extra_args_v1(args_data);
        assert!(
            !dest_chain_config.enforce_out_of_order || allow_out_of_order_execution,
            error::invalid_argument(E_EXTRA_ARG_OUT_OF_ORDER_EXECUTION_MUST_BE_TRUE)
        );
        assert!(
            compute_units <= dest_chain_config.max_per_msg_gas_limit,
            error::invalid_argument(E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH)
        );
        if (require_valid_token_receiver) {
            let stream = eth_abi::new_stream(token_receiver);
            let token_receiver_uint = eth_abi::decode_u256(&mut stream);
            assert!(
                token_receiver_uint > 0,
                error::invalid_argument(E_INVALID_TOKEN_RECEIVER)
            );
        };
        compute_units as u256
    }

    inline fun decode_evm_extra_args_v2(extra_args: vector<u8>): (u256, bool) {
        let stream = eth_abi::new_stream(extra_args);
        let gas_limit = eth_abi::decode_u256(&mut stream);
        let allow_out_of_order_execution = eth_abi::decode_bool(&mut stream);
        (gas_limit, allow_out_of_order_execution)
    }

    inline fun decode_svm_extra_args_v1(
        extra_args: vector<u8>
    ): (u32, u64, bool, vector<u8>, vector<vector<u8>>) {
        let stream = eth_abi::new_stream(extra_args);
        let compute_units = eth_abi::decode_u32(&mut stream);
        let account_is_writable_bitmap = eth_abi::decode_u64(&mut stream);
        let allow_out_of_order_execution = eth_abi::decode_bool(&mut stream);
        let token_receiver = eth_abi::decode_bytes32(&mut stream);
        let accounts =
            eth_abi::decode_vector(
                &mut stream,
                |stream| { eth_abi::decode_bytes32(stream) }
            );
        (
            compute_units,
            account_is_writable_bitmap,
            allow_out_of_order_execution,
            token_receiver,
            accounts
        )
    }

    inline fun get_data_availability_cost(
        state: &FeeQuoterState,
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
        fee_token_address: address,
        fee_token_price: TimestampedPrice,
        local_token_addresses: vector<address>,
        local_token_amounts: vector<u64>
    ): (u256, u32, u32) {
        let token_transfer_fee_wei: u256 = 0;
        let token_transfer_gas: u32 = 0;
        let token_transfer_bytes_overhead: u32 = 0;

        let tokens_len = vector::length(&local_token_addresses);
        vector::zip_ref(
            &local_token_addresses,
            &local_token_amounts,
            |local_token_address, local_token_amount| {
                let local_token_address: address = *local_token_address;
                let local_token_amount: u64 = *local_token_amount;

                let transfer_fee_config =
                    get_token_transfer_fee_config_internal(
                        state, dest_chain_selector, local_token_address
                    );

                if (!transfer_fee_config.is_enabled) {
                    token_transfer_fee_wei = token_transfer_fee_wei
                        + ((dest_chain_config.default_token_fee_usd_cents as u256)
                            * VAL_1E16);
                    token_transfer_gas = token_transfer_gas
                        + dest_chain_config.default_token_dest_gas_overhead;
                    token_transfer_bytes_overhead = token_transfer_bytes_overhead
                        + CCIP_LOCK_OR_BURN_V1_RET_BYTES;
                } else {
                    let bps_fee_usd_wei = 0;
                    if (transfer_fee_config.deci_bps > 0) {
                        let token_price =
                            if (local_token_address == fee_token_address) {
                                fee_token_price
                            } else {
                                get_token_price_internal(state, local_token_address)
                            };
                        let token_usd_value =
                            calc_usd_value_from_token_amount(
                                local_token_amount, token_price.price
                            );
                        bps_fee_usd_wei = (
                            token_usd_value * (transfer_fee_config.deci_bps as u256)
                        ) / VAL_1E5;
                    };

                    token_transfer_gas = token_transfer_gas
                        + transfer_fee_config.dest_gas_overhead;
                    token_transfer_bytes_overhead = token_transfer_bytes_overhead
                        + transfer_fee_config.dest_bytes_overhead;

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
                    token_transfer_fee_wei = token_transfer_fee_wei
                        + selected_fee_usd_wei;
                }
            }
        );

        (token_transfer_fee_wei, token_transfer_gas, token_transfer_bytes_overhead)
    }

    inline fun calc_usd_value_from_token_amount(
        token_amount: u64, token_price: u256
    ): u256 {
        (token_amount as u256) * (token_price as u256) / VAL_1E18
    }

    public(friend) fun process_message_args(
        _dest_chain_selector: u64,
        _fee_token: Object<Metadata>,
        _fee_token_amount: u64,
        _extra_args: vector<u8>,
        _local_token_addresses: vector<address>,
        _local_token_amounts: vector<u64>,
        _dest_token_addresses: vector<vector<u8>>,
        _dest_pool_datas: vector<vector<u8>>
    ): (u256, bool, vector<u8>, vector<vector<u8>>) {
        // TODO
        (0, false, vector[], vector[])
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
            smart_table::contains(&state.dest_chain_configs, dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        smart_table::borrow(&state.dest_chain_configs, dest_chain_selector)
    }

    public entry fun apply_dest_chain_config_updates(caller: &signer) {
        // TODO
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

    inline fun get_token_price_internal(
        state: &FeeQuoterState, token: address
    ): TimestampedPrice {
        assert!(
            smart_table::contains(&state.usd_per_token, token),
            error::invalid_argument(E_UNKNOWN_TOKEN)
        );
        *smart_table::borrow(&state.usd_per_token, token)
    }

    inline fun get_dest_chain_gas_price_internal(
        state: &FeeQuoterState, dest_chain_selector: u64
    ): TimestampedPrice {
        assert!(
            smart_table::contains(
                &state.usd_per_unit_gas_by_dest_chain, dest_chain_selector
            ),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        *smart_table::borrow(
            &state.usd_per_unit_gas_by_dest_chain, dest_chain_selector
        )
    }

    inline fun get_validated_gas_price_internal(
        state: &FeeQuoterState,
        dest_chain_config: &DestChainConfig,
        dest_chain_selector: u64
    ): u256 {
        let gas_price = get_dest_chain_gas_price_internal(state, dest_chain_selector);
        if (dest_chain_config.gas_price_staleness_threshold > 0) {
            let time_passed_seconds = timestamp::now_seconds()
                - gas_price.timestamp_secs;
            assert!(
                time_passed_seconds
                    <= (dest_chain_config.gas_price_staleness_threshold as u64),
                error::invalid_state(E_STALE_GAS_PRICE)
            );
        };
        gas_price.price
    }

    inline fun convert_token_amount_internal(
        state: &FeeQuoterState,
        from_token: address,
        from_token_amount: u256,
        to_token: address
    ): u256 {
        let from_token_price = get_token_price_internal(state, from_token);
        let to_token_price = get_token_price_internal(state, to_token);

        (from_token_amount * from_token_price.price) / to_token_price.price
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
        chain_family_selector: vector<u8>, receiver: vector<u8>
    ) {
        if (chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM) {}
    }

    inline fun validate_evm_address(encoded_address: vector<u8>) {
        let encoded_address_len = vector::length(&encoded_address);
        assert!(
            encoded_address_len == 32, error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );

        let stream = eth_abi::new_stream(encoded_address);
        let encoded_address_uint = eth_abi::decode_u256(&mut stream);

        assert!(
            encoded_address_uint >= EVM_PRECOMPILE_SPACE,
            error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );
        assert!(
            encoded_address_uint <= MAX_U160,
            error::invalid_argument(E_INVALID_EVM_ADDRESS)
        );
    }

    inline fun validate_svm_address(
        encoded_address: vector<u8>, must_be_non_zero: bool
    ) {
        let encoded_address_len = vector::length(&encoded_address);
        assert!(
            encoded_address_len == 32, error::invalid_argument(E_INVALID_SVM_ADDRESS)
        );

        if (must_be_non_zero) {
            let stream = eth_abi::new_stream(encoded_address);
            let encoded_address_uint = eth_abi::decode_u256(&mut stream);
            assert!(
                encoded_address_uint > 0,
                error::invalid_argument(E_INVALID_SVM_ADDRESS)
            );
        };
    }

    //
    // ccip::ownable functions
    //

    #[view]
    public fun owner(): address acquires FeeQuoterState {
        let state = borrow_state();
        ownable::owner(&state.ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires FeeQuoterState {
        let state = borrow_state_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut state.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires FeeQuoterState {
        let state = borrow_state_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut state.ownable_state)
    }
}
