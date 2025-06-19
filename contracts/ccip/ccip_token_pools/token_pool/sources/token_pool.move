    module ccip_token_pool::token_pool {

    use sui::clock::Clock;
    use sui::coin::CoinMetadata;
    use sui::event;
    use sui::vec_map::{Self, VecMap};

    use ccip::address;
    use ccip::eth_abi;
    use ccip::state_object;
    use ccip::rmn_remote;
    use ccip::allowlist;

    use ccip_token_pool::token_pool_rate_limiter;

    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const MAX_U64: u256 = 18446744073709551615;

    public struct TokenPoolState has store {
        allowlist_state: allowlist::AllowlistState,
        coin_metadata: address,
        local_decimals: u8,
        remote_chain_configs: VecMap<u64, RemoteChainConfig>,
        rate_limiter_config: token_pool_rate_limiter::RateLimitState
    }

    public struct RemoteChainConfig has store, drop, copy {
        remote_token_address: vector<u8>,
        remote_pools: vector<vector<u8>>
    }

    public struct LockedOrBurned has copy, drop {
        remote_chain_selector: u64,
        local_token: address,
        amount: u64
    }

    public struct ReleasedOrMinted has copy, drop {
        remote_chain_selector: u64,
        local_token: address,
        recipient: address,
        amount: u64
    }

    public struct RemotePoolAdded has copy, drop {
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    }

    public struct RemotePoolRemoved has copy, drop {
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    }

    public struct ChainAdded has copy, drop {
        remote_chain_selector: u64,
        remote_token_address: vector<u8>
    }

    public struct LiquidityAdded has copy, drop {
        local_token: address,
        provider: address,
        amount: u64,
    }

    public struct LiquidityRemoved has copy, drop {
        local_token: address,
        provider: address,
        amount: u64,
    }

    public struct RebalancerSet has copy, drop {
        local_token: address,
        previous_rebalancer: address,
        rebalancer: address,
    }

    const ENotPublisher: u64 = 1;
    const EUnknownRemoteChainSelector: u64 = 2;
    const ECursedChain: u64 = 3;
    const ERemotePoolAlreadyAdded: u64 = 4;
    const EUnknownRemotePool: u64 = 5;
    const ERemoateChainToAddMismatch: u64 = 6;
    const ERemoteChainAlreadyExists: u64 = 7;
    const EInvalidRemoteChainDecimals: u64 = 8;
    const EInvalidEncodedAmount: u64 = 9;
    const EUnknownToken: u64 = 10;
    const EDecimalOverflow: u64 = 11;

    // ================================================================
    // |                    Initialize and state                      |
    // ================================================================

    // this can be called by any token pool implementation
    public fun initialize(
        coin_metadata_address: address,
        local_decimals: u8,
        allowlist: vector<address>,
        ctx: &mut TxContext
    ): TokenPoolState {
        TokenPoolState {
            allowlist_state: allowlist::new(allowlist, ctx),
            coin_metadata: coin_metadata_address,
            local_decimals,
            remote_chain_configs: vec_map::empty<u64, RemoteChainConfig>(),
            rate_limiter_config: token_pool_rate_limiter::new(ctx)
        }
    }

    // TODO: is this ccip_router?
    public fun get_router(): address {
        @ccip_router
    }

    public fun get_token(state: &TokenPoolState): address {
        state.coin_metadata
    }

    public fun get_token_decimals<T>(coin_metadata: &CoinMetadata<T>): u8 {
        coin_metadata.get_decimals()
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
        state.remote_chain_configs.contains(&remote_chain_selector)
    }

    public fun apply_chain_updates(
        state: &mut TokenPoolState,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) {
        remote_chain_selectors_to_remove.do_ref!(
            |remote_chain_selector| {
                assert!(
                    state.remote_chain_configs.contains(remote_chain_selector),
                    EUnknownRemoteChainSelector
                );
                state.remote_chain_configs.remove(remote_chain_selector);
            }
        );

        let add_len = remote_chain_selectors_to_add.length();
        assert!(
            add_len == remote_pool_addresses_to_add.length(),
            ERemoateChainToAddMismatch
        );
        assert!(
            add_len == remote_token_addresses_to_add.length(),
            ERemoateChainToAddMismatch
        );

        let mut i = 0;
        while (i < add_len) {
            let remote_chain_selector = remote_chain_selectors_to_add[i];
            assert!(
                !state.remote_chain_configs.contains(&remote_chain_selector),
                ERemoteChainAlreadyExists
            );
            let remote_pool_addresses = remote_pool_addresses_to_add[i];
            let remote_token_address = remote_token_addresses_to_add[i];
            address::assert_non_zero_address_vector(&remote_token_address);

            let mut remote_chain_config = RemoteChainConfig {
                remote_token_address,
                remote_pools: vector[]
            };

            remote_pool_addresses.do_ref!(
                |remote_pool_address| {
                    let remote_pool_address: vector<u8> = *remote_pool_address;
                    address::assert_non_zero_address_vector(&remote_pool_address);

                    let (found, _) =
                        remote_chain_config.remote_pools.index_of(&remote_pool_address);
                    assert!(!found, ERemotePoolAlreadyAdded);

                    remote_chain_config.remote_pools.push_back(remote_pool_address);

                    event::emit(
                        RemotePoolAdded { remote_chain_selector, remote_pool_address }
                    );
                }
            );

            state.remote_chain_configs.insert(remote_chain_selector, remote_chain_config);

            event::emit(ChainAdded { remote_chain_selector, remote_token_address });
            i = i + 1;
        };
    }

    // ================================================================
    // |                        Remote Pools                          |
    // ================================================================

    public fun get_remote_pools(
        state: &TokenPoolState, remote_chain_selector: u64
    ): vector<vector<u8>> {
        assert!(
            state.remote_chain_configs.contains(&remote_chain_selector),
            EUnknownRemoteChainSelector
        );
        let remote_chain_config =
            state.remote_chain_configs.get(&remote_chain_selector);
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
            state.remote_chain_configs.contains(&remote_chain_selector),
            EUnknownRemoteChainSelector
        );
        let remote_chain_config =
            state.remote_chain_configs.get(&remote_chain_selector);
        remote_chain_config.remote_token_address
    }

    public fun add_remote_pool(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    ) {
        address::assert_non_zero_address_vector(&remote_pool_address);

        assert!(
            state.remote_chain_configs.contains(&remote_chain_selector),
            EUnknownRemoteChainSelector
        );
        let remote_chain_config =
            state.remote_chain_configs.get_mut(&remote_chain_selector);

        let (found, _) = remote_chain_config.remote_pools.index_of(&remote_pool_address);
        assert!(!found, ERemotePoolAlreadyAdded);

        remote_chain_config.remote_pools.push_back(remote_pool_address);

        event::emit(RemotePoolAdded { remote_chain_selector, remote_pool_address });
    }

    public fun remove_remote_pool(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    ) {
        assert!(
            state.remote_chain_configs.contains(&remote_chain_selector),
            EUnknownRemoteChainSelector
        );
        let remote_chain_config =
            state.remote_chain_configs.get_mut(&remote_chain_selector);

        let (found, i) = remote_chain_config.remote_pools.index_of(&remote_pool_address);
        assert!(found, EUnknownRemotePool);

        // remove instead of swap_remove for readability, so the newest added pool is always at the end.
        remote_chain_config.remote_pools.remove(i);

        event::emit(RemotePoolRemoved { remote_chain_selector, remote_pool_address });
    }

    // ================================================================
    // |                         Validation                           |
    // ================================================================

    // Returns the remote token as bytes
    public fun validate_lock_or_burn(
        ref: &state_object::CCIPObjectRef,
        clock: &Clock,
        state: &mut TokenPoolState,
        sender: address,
        remote_chain_selector: u64,
        local_amount: u64
    ): vector<u8> {
        assert!(!rmn_remote::is_cursed_u128(ref, (remote_chain_selector as u128)), ECursedChain);

        // Allowlist check
        if (allowlist::get_allowlist_enabled(&state.allowlist_state)) {
            assert!(
                allowlist::is_allowed(&state.allowlist_state, sender),
                ENotPublisher
            );
        };

        if (!is_supported_chain(state, remote_chain_selector)) {
            abort EUnknownRemoteChainSelector
        };

        token_pool_rate_limiter::consume_outbound(
            clock, &mut state.rate_limiter_config, remote_chain_selector, local_amount
        );

        get_remote_token(state, remote_chain_selector)
    }

    public fun validate_release_or_mint(
        ref: &state_object::CCIPObjectRef,
        clock: &Clock,
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        dest_token_address: address,
        source_pool_address: vector<u8>,
        local_amount: u64
    ) {
        let configured_token = get_token(state);

        assert!(
            configured_token == dest_token_address,
            EUnknownToken
        );

        // Check RMN curse status
        assert!(!rmn_remote::is_cursed_u128(ref, (remote_chain_selector as u128)), ECursedChain);

        // This checks if the remote chain selector and the source pool are valid.
        assert!(
            is_remote_pool(state, remote_chain_selector, source_pool_address),
            EUnknownRemotePool
        );

        token_pool_rate_limiter::consume_inbound(
            clock, &mut state.rate_limiter_config, remote_chain_selector, local_amount
        );
    }

    // ================================================================
    // |                           Events                             |
    // ================================================================

    public fun emit_released_or_minted(
        state: &mut TokenPoolState,
        recipient: address,
        amount: u64,
        remote_chain_selector: u64,
    ) {
        event::emit(
            ReleasedOrMinted { remote_chain_selector, local_token: state.coin_metadata, recipient, amount }
        );
    }

    public fun emit_locked_or_burned(
        state: &mut TokenPoolState, amount: u64, remote_chain_selector: u64
    ) {
        event::emit(LockedOrBurned { remote_chain_selector, local_token: state.coin_metadata, amount });
    }

    public fun emit_rebalancer_set(
        state: &mut TokenPoolState, previous_rebalancer: address, rebalancer: address
    ) {
        event::emit(RebalancerSet {
            local_token: state.coin_metadata,
            previous_rebalancer,
            rebalancer,
        });
    }

    public fun emit_liquidity_added(
        state: &mut TokenPoolState, provider: address, amount: u64
    ) {
        event::emit(LiquidityAdded { local_token: state.coin_metadata, provider, amount });
    }

    public fun emit_liquidity_removed(
        state: &mut TokenPoolState, provider: address, amount: u64
    ) {
        event::emit(LiquidityRemoved { local_token: state.coin_metadata, provider, amount });
    }

    // ================================================================
    // |                          Decimals                            |
    // ================================================================

    public fun get_local_decimals(pool: &TokenPoolState): u8 {
        pool.local_decimals
    }

    // for a token, CoinMetadata is supposed to be shared
    public fun encode_local_decimals<T>(coin_metadata: &CoinMetadata<T>): vector<u8> {
        let decimals = coin_metadata.get_decimals();
        let mut ret = vector[];
        eth_abi::encode_u8(&mut ret, decimals);
        ret
    }

    public fun parse_remote_decimals(
        source_pool_data: vector<u8>, local_decimals: u8
    ): u8 {
        let data_len = source_pool_data.length();
        if (data_len == 0) {
            // Fallback to the local value.
            return local_decimals
        };

        assert!(data_len == 32, EInvalidRemoteChainDecimals);

        let remote_decimals = eth_abi::decode_u256_value(source_pool_data);
        assert!(
            remote_decimals <= 255,
            EInvalidRemoteChainDecimals
        );

        remote_decimals as u8
    }

    public fun calculate_local_amount(
        remote_amount: u256, remote_decimals: u8, local_decimals: u8
    ): u64 {
        let local_amount =
            calculate_local_amount_internal(
                remote_amount, remote_decimals, local_decimals
            );
        assert!(local_amount <= MAX_U64, EInvalidEncodedAmount);
        local_amount as u64
    }

    fun calculate_local_amount_internal(
        remote_amount: u256, remote_decimals: u8, local_decimals: u8
    ): u256 {
        if (remote_decimals == local_decimals) {
            return remote_amount
        } else if (remote_decimals > local_decimals) {
            let decimals_diff = remote_decimals - local_decimals;
            let mut current_amount = remote_amount;
            let mut i = 0;
            while (i < decimals_diff) {
                current_amount = current_amount / 10;
                i = i + 1;
            };
            return current_amount
        } else {
            let decimals_diff = local_decimals - remote_decimals;
            // This is a safety check to prevent overflow in the next calculation.
            // More than 77 would never fit in a uint256 and would cause an overflow. We also check if the resulting amount
            // would overflow.
            assert!(decimals_diff <= 77, EDecimalOverflow);

            let mut multiplier: u256 = 1;
            let base: u256 = 10;
            let mut i = 0;
            while (i < decimals_diff) {
                multiplier = multiplier * base;
                i = i + 1;
            };
            assert!(remote_amount <= (MAX_U256 / multiplier), EDecimalOverflow);

            return remote_amount * multiplier
        }
    }

    // ================================================================
    // |                    Rate limit config                         |
    // ================================================================

    public fun set_chain_rate_limiter_config(
        clock: &Clock,
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
            clock,
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
    // |                          Deconstruction                           |
    // ================================================================

    public fun destroy_token_pool(state: TokenPoolState) {
        let TokenPoolState {
            allowlist_state,
            coin_metadata: _coin_metadata,
            local_decimals: _local_decimals,
            remote_chain_configs: _remote_chain_configs,
            rate_limiter_config,
        } = state;

        allowlist::destroy_allowlist(allowlist_state);
        token_pool_rate_limiter::destroy_rate_limiter(rate_limiter_config);
    }
}