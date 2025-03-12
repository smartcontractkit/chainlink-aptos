module ccip_token_pool::token_pool {
    use std::account::{Self};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::{Self, FungibleAsset, Metadata};
    use std::object::{Self, Object, ObjectCore};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::vector;

    use ccip::eth_abi;
    use ccip::token_admin_registry;
    use ccip::rmn_remote;
    use chainlink_common::allowlist;

    const STORE_OBJECT_SEED: vector<u8> = b"CCIPTokenPool";

    struct TokenPoolState has key, store {
        allowlist_state: allowlist::AllowlistState,
        fa_metadata: Object<Metadata>,
        remote_chain_configs: SmartTable<u64, RemoteChainConfig>,
        locked_events: EventHandle<Locked>,
        released_events: EventHandle<Released>,
        remote_pool_added_events: EventHandle<RemotePoolAdded>,
        remote_pool_removed_events: EventHandle<RemotePoolRemoved>,
        chain_added_events: EventHandle<ChainAdded>
    }

    struct RemoteChainConfig has store, drop, copy {
        remote_token_address: vector<u8>,
        remote_pools: vector<vector<u8>>
    }

    // the callback proof type used as authentication to retrieve and set input and output arguments.
    struct CallbackProof has drop {}

    #[event]
    struct Locked has store, drop {
        local_token: address,
        amount: u64
    }

    #[event]
    struct Released has store, drop {
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

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INVALID_FUNGIBLE_ASSET: u64 = 3;
    const E_UNKNOWN_FUNGIBLE_ASSET: u64 = 4;
    const E_ALLOWLIST_NOT_ENABLED: u64 = 5;
    const E_LOCAL_TOKEN_MISMATCH: u64 = 6;
    const E_UNKNOWN_REMOTE_CHAIN_SELECTOR: u64 = 7;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 8;
    const E_REMOTE_POOL_ALREADY_ADDED: u64 = 9;
    const E_UNKNOWN_REMOTE_POOL: u64 = 10;
    const E_REMOTE_CHAIN_TO_ADD_MISMATCH: u64 = 11;
    const E_REMOTE_CHAIN_ALREADY_EXISTS: u64 = 12;
    const E_INVALID_REMOTE_CHAIN_DECIMALS: u64 = 13;
    const E_INVALID_ENCODED_AMOUNT: u64 = 14;

    // ================================================================
    // |                    Initialize and state                      |
    // ================================================================

    public fun initialize(
        caller: &signer, local_token: address, allowlist: vector<address>
    ): TokenPoolState {
        assert_can_initialize(signer::address_of(caller));

        let fa_metadata = object::address_to_object<Metadata>(local_token);

        TokenPoolState {
            allowlist_state: allowlist::new(caller, allowlist),
            fa_metadata,
            remote_chain_configs: smart_table::new(),
            locked_events: account::new_event_handle(caller),
            released_events: account::new_event_handle(caller),
            remote_pool_added_events: account::new_event_handle(caller),
            remote_pool_removed_events: account::new_event_handle(caller),
            chain_added_events: account::new_event_handle(caller)
        }
    }

    fun assert_can_initialize(caller_address: address) {
        if (caller_address == @ccip_token_pool) { return };

        if (object::is_object(@ccip_token_pool)) {
            let ccip_lock_release_pool_object =
                object::address_to_object<ObjectCore>(@ccip_token_pool);
            if (caller_address == object::owner(ccip_lock_release_pool_object)
                || caller_address == object::root_owner(ccip_lock_release_pool_object)) {
                return
            };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }

    inline fun store_address(): address {
        account::create_resource_address(&@ccip_token_pool, STORE_OBJECT_SEED)
    }

    inline fun borrow_pool(): &TokenPoolState {
        borrow_global<TokenPoolState>(store_address())
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
        smart_table::keys(&state.remote_chain_configs)
    }

    public fun is_supported_chain(
        state: &TokenPoolState, remote_chain_selector: u64
    ): bool {
        smart_table::contains(&state.remote_chain_configs, remote_chain_selector)
    }

    public fun apply_chain_updates(
        state: &mut TokenPoolState,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) {
        vector::for_each_ref(
            &remote_chain_selectors_to_remove,
            |remote_chain_selector| {
                let remote_chain_selector: u64 = *remote_chain_selector;
                assert!(
                    smart_table::contains(
                        &state.remote_chain_configs, remote_chain_selector
                    ),
                    error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
                );
                smart_table::remove(
                    &mut state.remote_chain_configs, remote_chain_selector
                );
            }
        );

        let add_len = vector::length(&remote_chain_selectors_to_add);
        assert!(
            add_len == vector::length(&remote_pool_addresses_to_add),
            error::invalid_argument(E_REMOTE_CHAIN_TO_ADD_MISMATCH)
        );
        assert!(
            add_len == vector::length(&remote_token_addresses_to_add),
            error::invalid_argument(E_REMOTE_CHAIN_TO_ADD_MISMATCH)
        );

        for (i in 0..add_len) {
            let remote_chain_selector = *vector::borrow(
                &remote_chain_selectors_to_add, i
            );
            assert!(
                !smart_table::contains(
                    &state.remote_chain_configs, remote_chain_selector
                ),
                error::invalid_argument(E_REMOTE_CHAIN_ALREADY_EXISTS)
            );
            let remote_pool_addresses = vector::borrow(&remote_pool_addresses_to_add, i);
            let remote_token_address = *vector::borrow(
                &remote_token_addresses_to_add, i
            );
            assert!(
                !vector::is_empty(&remote_token_address),
                error::invalid_argument(E_ZERO_ADDRESS_NOT_ALLOWED)
            );

            let remote_chain_config = RemoteChainConfig {
                remote_token_address,
                remote_pools: vector[]
            };

            vector::for_each_ref(
                remote_pool_addresses,
                |remote_pool_address| {
                    let remote_pool_address: vector<u8> = *remote_pool_address;
                    let (found, _) = vector::index_of(
                        &remote_chain_config.remote_pools, &remote_pool_address
                    );
                    assert!(
                        !found, error::invalid_argument(E_REMOTE_POOL_ALREADY_ADDED)
                    );

                    vector::push_back(
                        &mut remote_chain_config.remote_pools, remote_pool_address
                    );

                    event::emit(
                        RemotePoolAdded { remote_chain_selector, remote_pool_address }
                    );
                    event::emit_event(
                        &mut state.remote_pool_added_events,
                        RemotePoolAdded { remote_chain_selector, remote_pool_address }
                    );
                }
            );

            smart_table::add(
                &mut state.remote_chain_configs,
                remote_chain_selector,
                remote_chain_config
            );

            event::emit(ChainAdded { remote_chain_selector, remote_token_address });
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
            smart_table::contains(&state.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow(&state.remote_chain_configs, remote_chain_selector);
        remote_chain_config.remote_pools
    }

    public fun is_remote_pool(
        state: &TokenPoolState, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool {
        let remote_pools = get_remote_pools(state, remote_chain_selector);
        let (found, _) = vector::index_of(&remote_pools, &remote_pool_address);
        found
    }

    public fun get_remote_token(
        state: &TokenPoolState, remote_chain_selector: u64
    ): vector<u8> {
        assert!(
            smart_table::contains(&state.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow(&state.remote_chain_configs, remote_chain_selector);
        remote_chain_config.remote_token_address
    }

    public fun add_remote_pool(
        state: &mut TokenPoolState,
        remote_chain_selector: u64,
        remote_pool_address: vector<u8>
    ) {
        assert!(
            !vector::is_empty(&remote_pool_address),
            error::invalid_argument(E_ZERO_ADDRESS_NOT_ALLOWED)
        );

        assert!(
            smart_table::contains(&state.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow_mut(
                &mut state.remote_chain_configs, remote_chain_selector
            );

        let (found, _) = vector::index_of(
            &remote_chain_config.remote_pools, &remote_pool_address
        );
        assert!(!found, error::invalid_argument(E_REMOTE_POOL_ALREADY_ADDED));

        vector::push_back(&mut remote_chain_config.remote_pools, remote_pool_address);

        event::emit(RemotePoolAdded { remote_chain_selector, remote_pool_address });
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
            smart_table::contains(&state.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow_mut(
                &mut state.remote_chain_configs, remote_chain_selector
            );

        let (found, i) = vector::index_of(
            &remote_chain_config.remote_pools, &remote_pool_address
        );
        assert!(found, error::invalid_argument(E_UNKNOWN_REMOTE_POOL));

        // remove instead of swap_remove for readability, so the newest added pool is always at the end.
        vector::remove(&mut remote_chain_config.remote_pools, i);

        event::emit(RemotePoolRemoved { remote_chain_selector, remote_pool_address });
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
        state: &TokenPoolState,
        fa: &FungibleAsset,
        input: &token_admin_registry::LockOrBurnInputV1
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
        assert!(!rmn_remote::is_cursed_u128((remote_chain_selector as u128)));

        // Allowlist check
        let _sender = token_admin_registry::get_lock_or_burn_sender(input);
        if (allowlist::get_allowlist_enabled(&state.allowlist_state)) {
            assert!(
                allowlist::is_allowed(&state.allowlist_state, &_sender),
                error::permission_denied(E_NOT_PUBLISHER)
            );
        };

        if (!is_supported_chain(state, remote_chain_selector)) {
            abort error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        };

        // TODO Rate limits
        get_remote_token(state, remote_chain_selector)
    }

    public fun validate_release_or_mint(
        state: &TokenPoolState, input: &token_admin_registry::ReleaseOrMintInputV1
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
        assert!(!rmn_remote::is_cursed_u128((remote_chain_selector as u128)));

        let source_pool_address =
            token_admin_registry::get_release_or_mint_source_pool_address(input);

        // This checks if the remote chain selector and the source pool are valid.
        assert!(
            is_remote_pool(state, remote_chain_selector, source_pool_address),
            error::invalid_argument(E_UNKNOWN_REMOTE_POOL)
        );

        // TODO Rate limits
    }

    // ================================================================
    // |                           Events                             |
    // ================================================================

    public fun emit_released_or_minted(
        state: &mut TokenPoolState, recipient: address, amount: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit(Released { local_token, recipient, amount });
        event::emit_event(
            &mut state.released_events,
            Released { local_token, recipient, amount }
        );
    }

    public fun emit_locked_or_burned(
        state: &mut TokenPoolState, amount: u64
    ) {
        let local_token = object::object_address(&state.fa_metadata);

        event::emit(Locked { local_token, amount });
        event::emit_event(
            &mut state.locked_events,
            Locked { local_token, amount }
        );
    }

    // ================================================================
    // |                          Decimals                            |
    // ================================================================

    public fun encode_local_decimals(fa: &FungibleAsset): vector<u8> {
        let fa_metadata = fungible_asset::metadata_from_asset(fa);
        let fa_decimals = fungible_asset::decimals(fa_metadata);
        let ret = vector[];
        eth_abi::encode_u8(&mut ret, fa_decimals);
        ret
    }

    #[view]
    public fun parse_remote_decimals(
        source_pool_data: vector<u8>, local_decimals: u8
    ): u8 {
        let data_len = vector::length(&source_pool_data);
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
        // check that the calculated amount fits in a u64
        assert!(
            local_amount <= 18446744073709551615,
            error::invalid_state(E_INVALID_ENCODED_AMOUNT)
        );
        local_amount as u64
    }

    #[view]
    fun calculate_local_amount_internal(
        remote_amount: u256, remote_decimals: u8, local_decimals: u8
    ): u256 {
        // TODO: check for overflows
        if (remote_decimals == local_decimals) {
            return remote_amount
        } else if (remote_decimals > local_decimals) {
            let decimals_diff = remote_decimals - local_decimals;
            let current_amount = remote_amount;
            for (i in 0..decimals_diff) {
                current_amount = current_amount / 10;
            };
            return current_amount
        } else {
            let decimals_diff = local_decimals - remote_decimals;
            let current_amount = remote_amount;
            for (i in 0..decimals_diff) {
                current_amount = current_amount * 10;
            };
            return current_amount
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
    // |                          Allowlist                           |
    // ================================================================

    public fun get_allowlist_enabled(state: &TokenPoolState): bool {
        allowlist::get_allowlist_enabled(&state.allowlist_state)
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
    // |                          Destroy                             |
    // ================================================================

    public fun destroy_token_pool(state: TokenPoolState) {
        let TokenPoolState {
            allowlist_state,
            fa_metadata: _fa_metadata,
            remote_chain_configs,
            locked_events,
            released_events,
            remote_pool_added_events,
            remote_pool_removed_events,
            chain_added_events
        } = state;

        allowlist::destroy_allowlist(allowlist_state);
        smart_table::destroy(remote_chain_configs);
        event::destroy_handle(locked_events);
        event::destroy_handle(released_events);
        event::destroy_handle(remote_pool_added_events);
        event::destroy_handle(remote_pool_removed_events);
        event::destroy_handle(chain_added_events);
    }
}

#[test_only]
module ccip_token_pool::token_pool_test {
    use std::account;
    use std::signer;
    use std::object;
    use std::option;
    use std::string;
    use std::primary_fungible_store;
    use std::fungible_asset;
    use std::vector;
    use ccip_token_pool::token_pool::TokenPoolState;

    use ccip_token_pool::token_pool;

    struct TestToken has key {}

    const Decimals: u8 = 8;
    const OwnerInitbalance: u64 = 1_000_000;

    const DefaultRemoteChain: u64 = 2000;
    const DefaultRemoteToken: vector<u8> = b"default_remote_token";
    const DefaultRemotePool: vector<u8> = b"default_remote_pool";

    #[test(owner = @ccip_token_pool)]
    fun initialize_correctly_sets_state(owner: &signer) {
        let state = set_up_test(owner);

        assert!(token_pool::get_token_decimals(&state) == Decimals, 1);
        assert!(token_pool::is_supported_chain(&state, DefaultRemoteChain), 1);

        token_pool::destroy_token_pool(state);
    }

    #[test(owner = @ccip_token_pool)]
    fun add_remote_pool_existing_chain(owner: &signer) {
        let state = set_up_test(owner);
        let new_remote_pool = b"new_pool";

        assert!(
            !token_pool::is_remote_pool(&state, DefaultRemoteChain, new_remote_pool),
            1
        );
        assert!(
            vector::length(&token_pool::get_remote_pools(&state, DefaultRemoteChain))
                == 1,
            1
        );

        token_pool::add_remote_pool(&mut state, DefaultRemoteChain, new_remote_pool);

        assert!(
            token_pool::is_remote_pool(&state, DefaultRemoteChain, new_remote_pool),
            1
        );
        assert!(
            vector::length(&token_pool::get_remote_pools(&state, DefaultRemoteChain))
                == 2,
            1
        );

        token_pool::destroy_token_pool(state);
    }

    // ================================================================
    // |                           Setup                              |
    // ================================================================

    inline fun set_up_test(owner: &signer): token_pool::TokenPoolState {
        let signer_address = signer::address_of(owner);
        account::create_account_for_test(signer_address);

        let constructor_ref = &object::create_named_object(owner, b"CCIPTokenPool");
        move_to(owner, TestToken {});

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            string::utf8(b"TEST"),
            string::utf8(b"TEST"),
            Decimals,
            string::utf8(b""),
            string::utf8(b"")
        );

        let fungible_asset_mint_ref = fungible_asset::generate_mint_ref(constructor_ref);

        primary_fungible_store::mint(
            &fungible_asset_mint_ref, signer_address, OwnerInitbalance
        );

        let token_address = object::address_from_constructor_ref(constructor_ref);

        let state = token_pool::initialize(owner, token_address, vector[]);

        // Set state in the pool
        set_up_default_remote_chain(&mut state);

        state
    }

    inline fun set_up_default_remote_chain(state: &mut TokenPoolState) {
        token_pool::apply_chain_updates(
            state,
            vector[],
            vector[DefaultRemoteChain],
            vector[vector[DefaultRemotePool]],
            vector[DefaultRemoteToken]
        )
    }
}
