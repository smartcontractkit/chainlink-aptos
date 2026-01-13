module ccip_token_pool::token_pool {
    use std::account::{Self};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::{Self, FungibleAsset, Metadata};
    use std::object::{Self, Object};
    use std::smart_table::{Self, SmartTable};

    use ccip::address;
    use ccip::eth_abi;
    use ccip::token_admin_registry;
    use ccip::rmn_remote;
    use ccip::allowlist;

    use ccip_token_pool::rate_limiter;
    use ccip_token_pool::token_pool_rate_limiter;

    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const MAX_U64: u256 = 18446744073709551615;

    struct TokenPoolState has key, store {
        allowlist_state: allowlist::AllowlistState,
        fa_metadata: Object<Metadata>,
        remote_chain_configs: SmartTable<u64, RemoteChainConfig>,
        rate_limiter_config: token_pool_rate_limiter::RateLimitState,
        locked_events: EventHandle<LockedOrBurned>,
        released_events: EventHandle<ReleasedOrMinted>,
        remote_pool_added_events: EventHandle<RemotePoolAdded>,
        remote_pool_removed_events: EventHandle<RemotePoolRemoved>,
        chain_added_events: EventHandle<ChainAdded>,
        chain_removed_events: EventHandle<ChainRemoved>,
        liquidity_added_events: EventHandle<LiquidityAdded>,
        liquidity_removed_events: EventHandle<LiquidityRemoved>,
        rebalancer_set_events: EventHandle<RebalancerSet>
    }

    struct RemoteChainConfig has store, drop, copy {
        remote_token_address: vector<u8>,
        remote_pools: vector<vector<u8>>
    }

    #[event]
    struct LockedOrBurned has store, drop {
        remote_chain_selector: u64,
        local_token: address,
        amount: u64
    }

    #[event]
    struct ReleasedOrMinted has store, drop {
        remote_chain_selector: u64,
        local_token: address,
        recipient: address,
        amount: u64
    }

    #[event]
    struct AllowlistRemove has store, drop {
        sender: address
    }

    #[event]
    struct AllowlistAdd has store, drop {
        sender: address
    }

    #[event]
    struct RemotePoolAdded has store, drop {
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    }

    #[event]
    struct RemotePoolRemoved has store, drop {
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    }

    #[event]
    struct ChainAdded has store, drop {
        remote_chain_selector: u64,
        remote_token_address: vector<u8>
    }

    #[event]
    struct ChainRemoved has store, drop {
        remote_chain_selector: u64
    }

    #[event]
    struct LiquidityAdded has store, drop {
        local_token: address,
        provider: address,
        amount: u64
    }

    #[event]
    struct LiquidityRemoved has store, drop {
        local_token: address,
        provider: address,
        amount: u64
    }

    #[event]
    struct RebalancerSet has store, drop {
        old_rebalancer: address,
        new_rebalancer: address
    }

    const E_NOT_ALLOWED_CALLER: u64 = 1;
    const E_UNKNOWN_FUNGIBLE_ASSET: u64 = 2;
    const E_UNKNOWN_REMOTE_CHAIN_SELECTOR: u64 = 3;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 4;
    const E_REMOTE_POOL_ALREADY_ADDED: u64 = 5;
    const E_UNKNOWN_REMOTE_POOL: u64 = 6;
    const E_REMOTE_CHAIN_TO_ADD_MISMATCH: u64 = 7;
    const E_REMOTE_CHAIN_ALREADY_EXISTS: u64 = 8;
    const E_INVALID_REMOTE_CHAIN_DECIMALS: u64 = 9;
    const E_INVALID_ENCODED_AMOUNT: u64 = 10;
    const E_DECIMAL_OVERFLOW: u64 = 11;
    const E_CURSED_CHAIN: u64 = 12;

    // ================================================================
    // |                    Initialize and state                      |
    // ================================================================

    /// This function should be called from the init_module function to ensure the events
    /// are created on the correct object.
    public fun initialize(
        event_account: &signer, local_token: address, allowlist: vector<address>
    ): TokenPoolState {
        let fa_metadata = object::address_to_object<Metadata>(local_token);

        TokenPoolState {
            allowlist_state: allowlist::new(event_account, allowlist),
            fa_metadata,
            remote_chain_configs: smart_table::new(),
            rate_limiter_config: token_pool_rate_limiter::new(event_account),
            locked_events: account::new_event_handle(event_account),
            released_events: account::new_event_handle(event_account),
            remote_pool_added_events: account::new_event_handle(event_account),
            remote_pool_removed_events: account::new_event_handle(event_account),
            chain_added_events: account::new_event_handle(event_account),
            chain_removed_events: account::new_event_handle(event_account),
            liquidity_added_events: account::new_event_handle(event_account),
            liquidity_removed_events: account::new_event_handle(event_account),
            rebalancer_set_events: account::new_event_handle(event_account)
        }
    }

    #[view]
    public fun get_router(): address {
        @ccip
    }

    public fun get_token(state: &TokenPoolState): address {
        object::object_address(&state.fa_metadata)
    }

    public fun get_token_decimals(state: &TokenPoolState): u8 {
        fungible_asset::decimals(state.fa_metadata)
    }

    public fun get_fa_metadata(state: &TokenPoolState): Object<Metadata> {
        state.fa_metadata
    }

    // ================================================================
    // |                        Remote Chains                         |
    // ================================================================
    public fun get_supported_chains(state: &TokenPoolState): vector<u64> {
        state.remote_chain_configs.keys()
    }

    public fun is_supported_chain(
        state: &TokenPoolState, remote_chain_selector: u64
    ): bool {
        state.remote_chain_configs.contains(remote_chain_selector)
    }

    public fun apply_chain_updates(
        state: &mut TokenPoolState,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) {
        remote_chain_selectors_to_remove.for_each_ref(
            |remote_chain_selector| {
                let remote_chain_selector: u64 = *remote_chain_selector;
                assert!(
                    state.remote_chain_configs.contains(remote_chain_selector),
                    error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
                );
                state.remote_chain_configs.remove(remote_chain_selector);

                event::emit_event(
                    &mut state.chain_removed_events,
                    ChainRemoved { remote_chain_selector }
                );
            }
        );

        let add_len = remote_chain_selectors_to_add.length();
        assert!(
            add_len == remote_pool_addresses_to_add.length(),
            error::invalid_argument(E_REMOTE_CHAIN_TO_ADD_MISMATCH)
        );
        assert!(
            add_len == remote_token_addresses_to_add.length(),
            error::invalid_argument(E_REMOTE_CHAIN_TO_ADD_MISMATCH)
        );

        for (i in 0..add_len) {
            let remote_chain_selector = remote_chain_selectors_to_add[i];
            assert!(
                !state.remote_chain_configs.contains(remote_chain_selector),
                error::invalid_argument(E_REMOTE_CHAIN_ALREADY_EXISTS)
            );
            let remote_pool_addresses = remote_pool_addresses_to_add[i];
            let remote_token_address = remote_token_addresses_to_add[i];
            address::assert_non_zero_address_vector(&remote_token_address);

            let remote_chain_config = RemoteChainConfig {
                remote_token_address,
                remote_pools: vector[]
            };

            remote_pool_addresses.for_each(
                |remote_pool_address| {
                    let remote_pool_address: vector<u8> = remote_pool_address;
                    address::assert_non_zero_address_vector(&remote_pool_address);

                    let (found, _) =
                        remote_chain_config.remote_pools.index_of(&remote_pool_address);
                    assert!(
                        !found, error::invalid_argument(E_REMOTE_POOL_ALREADY_ADDED)
                    );

                    remote_chain_config.remote_pools.push_back(remote_pool_address);

                    event::emit_event(
                        &mut state.remote_pool_added_events,
                        RemotePoolAdded { remote_chain_selector, remote_pool_address }
                    );
                }
            );

            state.remote_chain_configs.add(remote_chain_selector, remote_chain_config);

            event::emit_event(
                &mut state.chain_added_events,
                ChainAdded { remote_chain_selector, remote_token_address }
            );
        };
    }

    // ================================================================
    // |                        Remote Pools                          |
    // ================================================================
    public fun get_remote_pools(
        state: &TokenPoolState, remote_chain_selector: u64
    ): vector<vector<u8>> {
        assert!(
            state.remote_chain_configs.contains(remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            state.remote_chain_configs.borrow(remote_chain_selector);
        remote_chain_config.remote_pools
    }

    public fun is_remote_pool(
        state: &TokenPoolState, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool {
        let remote_pools = get_remote_pools(state, remote_chain_selector);
        let (found, _) = remote_pools.index_of(&remote_pool_address);
        found
    }

    public fun get_remote_token(
        state: &TokenPoolState, remote_chain_selector: u64
    ): vector<u8> {
        assert!(
            state.remote_chain_configs.contains(remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            state.remote_chain_configs.borrow(remote_chain_selector);
        remote_chain_config.remote_token_address
    }

    public fun add_remote_pool(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    ) {
        address::assert_non_zero_address_vector(&remote_pool_address);

        assert!(
            state.remote_chain_configs.contains(remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            state.remote_chain_configs.borrow_mut(remote_chain_selector);

        let (found, _) = remote_chain_config.remote_pools.index_of(&remote_pool_address);
        assert!(!found, error::invalid_argument(E_REMOTE_POOL_ALREADY_ADDED));

        remote_chain_config.remote_pools.push_back(remote_pool_address);

        event::emit_event(
            &mut state.remote_pool_added_events,
            RemotePoolAdded { remote_chain_selector, remote_pool_address }
        );
    }

    public fun remove_remote_pool(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    ) {
        assert!(
            state.remote_chain_configs.contains(remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            state.remote_chain_configs.borrow_mut(remote_chain_selector);

        let (found, i) = remote_chain_config.remote_pools.index_of(&remote_pool_address);
        assert!(found, error::invalid_argument(E_UNKNOWN_REMOTE_POOL));

        // remove instead of swap_remove for readability, so the newest added pool is always at the end.
        remote_chain_config.remote_pools.remove(i);

        event::emit_event(
            &mut state.remote_pool_removed_events,
            RemotePoolRemoved { remote_chain_selector, remote_pool_address }
        );
    }

    // ================================================================
    // |                         Validation                           |
    // ================================================================

    // Returns the remote token as bytes
    public fun validate_lock_or_burn(
        state: &mut TokenPoolState,
        fa: &FungibleAsset,
        input: &token_admin_registry::LockOrBurnInputV1,
        local_amount: u64
    ): vector<u8> {
        // Validate the fungible asset
        let fa_metadata = fungible_asset::metadata_from_asset(fa);
        let configured_token = get_token(state);

        // make sure the caller is requesting this pool's fungible asset.
        assert!(
            configured_token == object::object_address(&fa_metadata),
            error::invalid_argument(E_UNKNOWN_FUNGIBLE_ASSET)
        );

        // Check RMN curse status
        let remote_chain_selector =
            token_admin_registry::get_lock_or_burn_remote_chain_selector(input);
        assert!(
            !rmn_remote::is_cursed_u128((remote_chain_selector as u128)),
            error::invalid_state(E_CURSED_CHAIN)
        );

        let sender = token_admin_registry::get_lock_or_burn_sender(input);
        // Allowlist check
        assert!(
            allowlist::is_allowed(&state.allowlist_state, sender),
            error::permission_denied(E_NOT_ALLOWED_CALLER)
        );

        if (!is_supported_chain(state, remote_chain_selector)) {
            abort error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        };

        token_pool_rate_limiter::consume_outbound(
            &mut state.rate_limiter_config,
            remote_chain_selector,
            local_amount
        );

        get_remote_token(state, remote_chain_selector)
    }

    public fun validate_release_or_mint(
        state: &mut TokenPoolState,
        input: &token_admin_registry::ReleaseOrMintInputV1,
        local_amount: u64
    ) {
        // Validate the fungible asset
        let local_token = token_admin_registry::get_release_or_mint_local_token(input);
        let configured_token = get_token(state);

        // make sure the caller is requesting this pool's fungible asset.
        assert!(
            configured_token == local_token,
            error::invalid_argument(E_UNKNOWN_FUNGIBLE_ASSET)
        );

        // Check RMN curse status
        let remote_chain_selector =
            token_admin_registry::get_release_or_mint_remote_chain_selector(input);
        assert!(
            !rmn_remote::is_cursed_u128((remote_chain_selector as u128)),
            error::invalid_state(E_CURSED_CHAIN)
        );

        let source_pool_address =
            token_admin_registry::get_release_or_mint_source_pool_address(input);

        // This checks if the remote chain selector and the source pool are valid.
        assert!(
            is_remote_pool(state, remote_chain_selector, source_pool_address),
            error::invalid_argument(E_UNKNOWN_REMOTE_POOL)
        );

        token_pool_rate_limiter::consume_inbound(
            &mut state.rate_limiter_config,
            remote_chain_selector,
            local_amount
        );
    }

    // ================================================================
    // |                           Events                             |
    // ================================================================
    public fun emit_released_or_minted(
        state: &mut TokenPoolState,
        recipient: address,
        amount: u64,
        remote_chain_selector: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit_event(
            &mut state.released_events,
            ReleasedOrMinted {
                remote_chain_selector,
                local_token,
                recipient,
                amount
            }
        );
    }

    public fun emit_locked_or_burned(
        state: &mut TokenPoolState, amount: u64, remote_chain_selector: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit_event(
            &mut state.locked_events,
            LockedOrBurned { remote_chain_selector, local_token, amount }
        );
    }

    public fun emit_liquidity_added(
        state: &mut TokenPoolState, provider: address, amount: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit_event(
            &mut state.liquidity_added_events,
            LiquidityAdded { local_token, provider, amount }
        );
    }

    public fun emit_liquidity_removed(
        state: &mut TokenPoolState, provider: address, amount: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit_event(
            &mut state.liquidity_removed_events,
            LiquidityRemoved { local_token, provider, amount }
        );
    }

    public fun emit_rebalancer_set(
        state: &mut TokenPoolState, old_rebalancer: address, new_rebalancer: address
    ) {
        event::emit_event(
            &mut state.rebalancer_set_events,
            RebalancerSet { old_rebalancer, new_rebalancer }
        );
    }

    // ================================================================
    // |                          Decimals                            |
    // ================================================================
    public fun encode_local_decimals(state: &TokenPoolState): vector<u8> {
        let fa_decimals = fungible_asset::decimals(state.fa_metadata);
        let ret = vector[];
        eth_abi::encode_u8(&mut ret, fa_decimals);
        ret
    }

    #[view]
    public fun parse_remote_decimals(
        source_pool_data: vector<u8>, local_decimals: u8
    ): u8 {
        let data_len = source_pool_data.length();
        if (data_len == 0) {
            // Fallback to the local value.
            return local_decimals
        };

        assert!(data_len == 32, error::invalid_state(E_INVALID_REMOTE_CHAIN_DECIMALS));

        let remote_decimals = eth_abi::decode_u256_value(source_pool_data);
        assert!(
            remote_decimals <= 255,
            error::invalid_state(E_INVALID_REMOTE_CHAIN_DECIMALS)
        );

        remote_decimals as u8
    }

    #[view]
    public fun calculate_local_amount(
        remote_amount: u256, remote_decimals: u8, local_decimals: u8
    ): u64 {
        let local_amount =
            calculate_local_amount_internal(
                remote_amount, remote_decimals, local_decimals
            );
        assert!(local_amount <= MAX_U64, error::invalid_state(E_INVALID_ENCODED_AMOUNT));
        local_amount as u64
    }

    #[view]
    fun calculate_local_amount_internal(
        remote_amount: u256, remote_decimals: u8, local_decimals: u8
    ): u256 {
        if (remote_decimals == local_decimals) {
            return remote_amount
        } else if (remote_decimals > local_decimals) {
            let decimals_diff = remote_decimals - local_decimals;
            let current_amount = remote_amount;
            for (i in 0..decimals_diff) {
                current_amount /= 10;
            };
            return current_amount
        } else {
            let decimals_diff = local_decimals - remote_decimals;
            // This is a safety check to prevent overflow in the next calculation.
            // More than 77 would never fit in a uint256 and would cause an overflow. We also check if the resulting amount
            // would overflow.
            assert!(decimals_diff <= 77, error::invalid_state(E_DECIMAL_OVERFLOW));

            let multiplier: u256 = 1;
            let base: u256 = 10;
            for (i in 0..decimals_diff) {
                multiplier = multiplier * base;
            };

            assert!(
                remote_amount <= (MAX_U256 / multiplier),
                error::invalid_state(E_DECIMAL_OVERFLOW)
            );

            return remote_amount * multiplier
        }
    }

    public fun calculate_release_or_mint_amount(
        state: &TokenPoolState, input: &token_admin_registry::ReleaseOrMintInputV1
    ): u64 {
        let local_decimals = get_token_decimals(state);
        let source_amount =
            token_admin_registry::get_release_or_mint_source_amount(input);
        let source_pool_data =
            token_admin_registry::get_release_or_mint_source_pool_data(input);
        let remote_decimals = parse_remote_decimals(source_pool_data, local_decimals);
        let local_amount =
            calculate_local_amount(source_amount, remote_decimals, local_decimals);
        local_amount
    }

    // ================================================================
    // |                    Rate limit config                         |
    // ================================================================
    public fun set_chain_rate_limiter_config(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    ) {
        token_pool_rate_limiter::set_chain_rate_limiter_config(
            &mut state.rate_limiter_config,
            remote_chain_selector,
            outbound_is_enabled,
            outbound_capacity,
            outbound_rate,
            inbound_is_enabled,
            inbound_capacity,
            inbound_rate
        );
    }

    public fun get_current_inbound_rate_limiter_state(
        state: &TokenPoolState, remote_chain_selector: u64
    ): rate_limiter::TokenBucket {
        token_pool_rate_limiter::get_current_inbound_rate_limiter_state(
            &state.rate_limiter_config, remote_chain_selector
        )
    }

    public fun get_current_outbound_rate_limiter_state(
        state: &TokenPoolState, remote_chain_selector: u64
    ): rate_limiter::TokenBucket {
        token_pool_rate_limiter::get_current_outbound_rate_limiter_state(
            &state.rate_limiter_config, remote_chain_selector
        )
    }

    // ================================================================
    // |                          Allowlist                           |
    // ================================================================
    public fun get_allowlist_enabled(state: &TokenPoolState): bool {
        allowlist::get_allowlist_enabled(&state.allowlist_state)
    }

    public fun set_allowlist_enabled(
        state: &mut TokenPoolState, enabled: bool
    ) {
        allowlist::set_allowlist_enabled(&mut state.allowlist_state, enabled);
    }

    public fun get_allowlist(state: &TokenPoolState): vector<address> {
        allowlist::get_allowlist(&state.allowlist_state)
    }

    public fun apply_allowlist_updates(
        state: &mut TokenPoolState, removes: vector<address>, adds: vector<address>
    ) {
        allowlist::apply_allowlist_updates(&mut state.allowlist_state, removes, adds);
    }

    // ================================================================
    // |                          Test functions                       |
    // ================================================================
    #[test_only]
    public fun destroy_token_pool(state: TokenPoolState) {
        let TokenPoolState {
            allowlist_state,
            fa_metadata: _fa_metadata,
            remote_chain_configs,
            rate_limiter_config,
            locked_events,
            released_events,
            remote_pool_added_events,
            remote_pool_removed_events,
            chain_added_events,
            chain_removed_events,
            liquidity_added_events,
            liquidity_removed_events,
            rebalancer_set_events
        } = state;

        allowlist::destroy_allowlist(allowlist_state);
        remote_chain_configs.destroy();
        event::destroy_handle(locked_events);
        event::destroy_handle(released_events);
        event::destroy_handle(remote_pool_added_events);
        event::destroy_handle(remote_pool_removed_events);
        event::destroy_handle(chain_added_events);
        event::destroy_handle(chain_removed_events);
        event::destroy_handle(liquidity_added_events);
        event::destroy_handle(liquidity_removed_events);
        event::destroy_handle(rebalancer_set_events);

        token_pool_rate_limiter::destroy_rate_limiter(rate_limiter_config);
    }

    #[test_only]
    public fun get_locked_or_burned_events(state: &TokenPoolState): vector<LockedOrBurned> {
        event::emitted_events_by_handle<LockedOrBurned>(&state.locked_events)
    }

    #[test_only]
    public fun get_released_or_minted_events(state: &TokenPoolState)
        : vector<ReleasedOrMinted> {
        event::emitted_events_by_handle<ReleasedOrMinted>(&state.released_events)
    }
}
