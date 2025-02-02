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
    use ccip::ownable;
    use ccip::state_object;

    friend ccip::offramp;
    friend ccip::onramp;

    struct FeeQuoterState has key, store {
        ownable_state: ownable::OwnableState,
        max_fee_juels_per_msg: u256,
        link_token: address,
        token_price_staleness_threshold: u64,
        fee_tokens: vector<address>,
        usd_per_unit_gas_by_dest_chain: SmartTable<u64, TimestampedPrice>,
        usd_per_token: SmartTable<address, TimestampedPrice>,
        dest_chain_configs: SmartTable<u64, DestChainConfig>,
        fee_token_added_events: EventHandle<FeeTokenAdded>,
        fee_token_removed_events: EventHandle<FeeTokenRemoved>
    }

    struct DestChainConfig has store, drop {
        is_enabled: bool
    }

    struct TimestampedPrice has store, drop, copy {
        price: u256,
        timestamp_microseconds: u64
    }

    #[event]
    struct FeeTokenAdded has store, drop {
        fee_token: address
    }

    #[event]
    struct FeeTokenRemoved has store, drop {
        fee_token: address
    }

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_INVALID_LINK_TOKEN: u64 = 2;
    const E_UNKNOWN_DEST_CHAIN_SELECTOR: u64 = 3;
    const E_UNKNOWN_TOKEN: u64 = 4;
    const E_DEST_CHAIN_NOT_ENABLED: u64 = 5;
    const E_TOKEN_UPDATE_MISMATCH: u64 = 6;
    const E_GAS_UPDATE_MISMATCH: u64 = 7;

    public entry fun initialize(
        caller: &signer,
        max_fee_juels_per_msg: u256,
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
            fee_token_added_events: account::new_event_handle(&state_object_signer),
            fee_token_removed_events: account::new_event_handle(&state_object_signer)
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
        assert!(
            smart_table::contains(&state.dest_chain_configs, dest_chain_selector),
            error::invalid_argument(E_UNKNOWN_DEST_CHAIN_SELECTOR)
        );
        let dest_chain_config =
            smart_table::borrow(&state.dest_chain_configs, dest_chain_selector);
        assert!(
            dest_chain_config.is_enabled,
            error::invalid_argument(E_DEST_CHAIN_NOT_ENABLED)
        );
        let token_price = get_token_price_internal(state, token);
        let gas_price = get_dest_chain_gas_price_internal(state, dest_chain_selector);
        (token_price.price, gas_price.price)
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
        let timestamp_microseconds = timestamp::now_microseconds();

        vector::zip_ref(
            &source_tokens,
            &source_usd_per_token,
            |token, usd_per_token| {
                let timestamped_price = TimestampedPrice {
                    price: *usd_per_token,
                    timestamp_microseconds
                };
                smart_table::upsert(&mut state.usd_per_token, *token, timestamped_price);
            }
        );

        vector::zip_ref(
            &gas_dest_chain_selectors,
            &gas_usd_per_unit_gas,
            |dest_chain_selector, usd_per_unit_gas| {
                let timestamped_price = TimestampedPrice {
                    price: *usd_per_unit_gas,
                    timestamp_microseconds
                };
                smart_table::upsert(
                    &mut state.usd_per_unit_gas_by_dest_chain,
                    *dest_chain_selector,
                    timestamped_price
                );
            }
        );
    }

    public(friend) fun get_fee(
        _dest_chain_selector: u64, _message: &client::Aptos2AnyMessage
    ): u64 {
        // TODO
        0
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
