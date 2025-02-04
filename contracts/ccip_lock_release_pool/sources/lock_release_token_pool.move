module ccip_lock_release_pool::lock_release_token_pool {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::vector;

    use ccip::ownable;
    use ccip::token_admin_registry;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipLockReleaseTokenPool";

    struct LockReleaseTokenPoolDeployment has key {
        store_signer_cap: SignerCapability,
        locked_events: EventHandle<Locked>,
        released_events: EventHandle<Released>,
        allowlist_remove_events: EventHandle<AllowlistRemove>,
        allowlist_add_events: EventHandle<AllowlistAdd>,
        remote_pool_added_events: EventHandle<RemotePoolAdded>,
        remote_pool_removed_events: EventHandle<RemotePoolRemoved>,
        chain_added_events: EventHandle<ChainAdded>
    }

    struct LockReleaseTokenPool has key, store {
        ownable_state: ownable::OwnableState,
        fa_metadata: Object<Metadata>,
        allowlist_enabled: bool,
        allowlist: vector<address>,
        remote_chain_configs: SmartTable<u64, RemoteChainConfig>,
        store_signer_address: address,
        store_signer_cap: SignerCapability,
        locked_events: EventHandle<Locked>,
        released_events: EventHandle<Released>,
        allowlist_remove_events: EventHandle<AllowlistRemove>,
        allowlist_add_events: EventHandle<AllowlistAdd>,
        remote_pool_added_events: EventHandle<RemotePoolAdded>,
        remote_pool_removed_events: EventHandle<RemotePoolRemoved>,
        chain_added_events: EventHandle<ChainAdded>
    }

    struct RemoteChainConfig has store, drop, copy {
        remote_token_address: vector<u8>,
        remote_pools: vector<vector<u8>>
    }

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

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @ccip_lock_release_pool.
        assert!(
            !object::object_exists<Metadata>(@local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"lock_release_token_pool";

        token_admin_registry::register_pool(
            publisher,
            token_pool_module_name,
            @local_token,
            CallbackProof {}
        );

        // create a resource account to be the owner of the primary FungibleStore we will use.
        let (store_signer, store_signer_cap) =
            account::create_resource_account(publisher, STORE_OBJECT_SEED);

        move_to(
            publisher,
            LockReleaseTokenPoolDeployment {
                store_signer_cap,
                locked_events: account::new_event_handle(&store_signer),
                released_events: account::new_event_handle(&store_signer),
                allowlist_remove_events: account::new_event_handle(&store_signer),
                allowlist_add_events: account::new_event_handle(&store_signer),
                remote_pool_added_events: account::new_event_handle(&store_signer),
                remote_pool_removed_events: account::new_event_handle(&store_signer),
                chain_added_events: account::new_event_handle(&store_signer)
            }
        );
    }

    public fun initialize(
        caller: &signer, local_token: address, allowlist: vector<address>
    ) acquires LockReleaseTokenPoolDeployment {
        assert_can_initialize(signer::address_of(caller));

        assert!(
            exists<LockReleaseTokenPoolDeployment>(@ccip_lock_release_pool),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        assert!(
            @local_token == local_token,
            error::invalid_argument(E_LOCAL_TOKEN_MISMATCH)
        );

        let LockReleaseTokenPoolDeployment {
            store_signer_cap,
            locked_events,
            released_events,
            allowlist_remove_events,
            allowlist_add_events,
            remote_pool_added_events,
            remote_pool_removed_events,
            chain_added_events
        } = move_from<LockReleaseTokenPoolDeployment>(@ccip_lock_release_pool);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        let fa_metadata = object::address_to_object<Metadata>(local_token);

        let allowlist_enabled = !vector::is_empty(&allowlist);

        let pool = LockReleaseTokenPool {
            ownable_state: ownable::new(&store_signer, signer::address_of(caller), @0x0),
            fa_metadata,
            allowlist_enabled,
            allowlist: vector[],
            store_signer_address: signer::address_of(&store_signer),
            store_signer_cap,
            remote_chain_configs: smart_table::new(),
            locked_events,
            released_events,
            allowlist_remove_events,
            allowlist_add_events,
            remote_pool_added_events,
            remote_pool_removed_events,
            chain_added_events
        };

        if (allowlist_enabled) {
            apply_allowlist_updates_internal(&mut pool, vector[], allowlist);
        };

        move_to(&store_signer, pool);
    }

    #[view]
    public fun get_token(): address acquires LockReleaseTokenPool {
        object::object_address(&borrow_pool().fa_metadata)
    }

    #[view]
    public fun get_router(): address {
        @ccip
    }

    #[view]
    public fun get_token_decimals(): u8 acquires LockReleaseTokenPool {
        fungible_asset::decimals(borrow_pool().fa_metadata)
    }

    #[view]
    public fun get_remote_pools(
        remote_chain_selector: u64
    ): vector<vector<u8>> acquires LockReleaseTokenPool {
        let pool = borrow_pool();
        assert!(
            smart_table::contains(&pool.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow(&pool.remote_chain_configs, remote_chain_selector);
        remote_chain_config.remote_pools
    }

    #[view]
    public fun is_remote_pool(
        remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool acquires LockReleaseTokenPool {
        let remote_pools = get_remote_pools(remote_chain_selector);
        let (found, _) = vector::index_of(&remote_pools, &remote_pool_address);
        found
    }

    #[view]
    public fun get_remote_token(
        remote_chain_selector: u64
    ): vector<u8> acquires LockReleaseTokenPool {
        let pool = borrow_pool();
        assert!(
            smart_table::contains(&pool.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow(&pool.remote_chain_configs, remote_chain_selector);
        remote_chain_config.remote_token_address
    }

    public entry fun add_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires LockReleaseTokenPool {
        assert!(
            !vector::is_empty(&remote_pool_address),
            error::invalid_argument(E_ZERO_ADDRESS_NOT_ALLOWED)
        );

        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        assert!(
            smart_table::contains(&pool.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow_mut(
                &mut pool.remote_chain_configs, remote_chain_selector
            );

        let (found, _) = vector::index_of(
            &remote_chain_config.remote_pools, &remote_pool_address
        );
        assert!(!found, error::invalid_argument(E_REMOTE_POOL_ALREADY_ADDED));

        vector::push_back(&mut remote_chain_config.remote_pools, remote_pool_address);

        event::emit(RemotePoolAdded { remote_chain_selector, remote_pool_address });
        event::emit_event(
            &mut pool.remote_pool_added_events,
            RemotePoolAdded { remote_chain_selector, remote_pool_address }
        );
    }

    public entry fun remove_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires LockReleaseTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        assert!(
            smart_table::contains(&pool.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow_mut(
                &mut pool.remote_chain_configs, remote_chain_selector
            );

        let (found, i) = vector::index_of(
            &remote_chain_config.remote_pools, &remote_pool_address
        );
        assert!(found, error::invalid_argument(E_UNKNOWN_REMOTE_POOL));

        // remove instead of swap_remove for readability, so the newest added pool is always at the end.
        vector::remove(&mut remote_chain_config.remote_pools, i);

        event::emit(RemotePoolRemoved { remote_chain_selector, remote_pool_address });
        event::emit_event(
            &mut pool.remote_pool_removed_events,
            RemotePoolRemoved { remote_chain_selector, remote_pool_address }
        );
    }

    #[view]
    public fun is_supported_chain(remote_chain_selector: u64): bool acquires LockReleaseTokenPool {
        let pool = borrow_pool();

        smart_table::contains(&pool.remote_chain_configs, remote_chain_selector)
    }

    #[view]
    public fun get_supported_chains(): vector<u64> acquires LockReleaseTokenPool {
        let pool = borrow_pool();
        smart_table::keys(&pool.remote_chain_configs)
    }

    public entry fun apply_chain_updates(
        caller: &signer,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) acquires LockReleaseTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        vector::for_each_ref(
            &remote_chain_selectors_to_remove,
            |remote_chain_selector| {
                let remote_chain_selector: u64 = *remote_chain_selector;
                assert!(
                    smart_table::contains(
                        &pool.remote_chain_configs, remote_chain_selector
                    ),
                    error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
                );
                smart_table::remove(
                    &mut pool.remote_chain_configs, remote_chain_selector
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

        let i = 0;
        while (i < add_len) {
            let remote_chain_selector = *vector::borrow(
                &remote_chain_selectors_to_add, i
            );
            assert!(
                !smart_table::contains(
                    &pool.remote_chain_configs, remote_chain_selector
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
                        &mut pool.remote_pool_added_events,
                        RemotePoolAdded { remote_chain_selector, remote_pool_address }
                    );
                }
            );

            smart_table::add(
                &mut pool.remote_chain_configs,
                remote_chain_selector,
                remote_chain_config
            );

            event::emit(ChainAdded { remote_chain_selector, remote_token_address });
            event::emit_event(
                &mut pool.chain_added_events,
                ChainAdded { remote_chain_selector, remote_token_address }
            );

            i = i + 1;
        };
    }

    #[view]
    public fun get_allowlist_enabled(): bool acquires LockReleaseTokenPool {
        borrow_pool().allowlist_enabled
    }

    #[view]
    public fun get_allowlist(): vector<address> acquires LockReleaseTokenPool {
        borrow_pool().allowlist
    }

    public entry fun apply_allowlist_updates(
        caller: &signer, removes: vector<address>, adds: vector<address>
    ) acquires LockReleaseTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);
        apply_allowlist_updates_internal(pool, removes, adds);
    }

    // the callback proof type used as authentication to retrieve and set input and output arguments.
    struct CallbackProof has drop {}

    public fun lock_or_burn<T: key>(
        _store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
    ) acquires LockReleaseTokenPool {
        // retrieve the input for this lock or burn operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_lock_or_burn_input(
                @ccip_lock_release_pool, CallbackProof {}
            );

        // TODO: do something with these fields.
        let _sender = token_admin_registry::get_lock_or_burn_sender(&input);
        let remote_chain_selector =
            token_admin_registry::get_lock_or_burn_remote_chain_selector(&input);
        let _receiver = token_admin_registry::get_lock_or_burn_receiver(&input);

        let pool = borrow_pool_mut();

        let fa_metadata = fungible_asset::metadata_from_asset(&fa);
        let fa_amount = fungible_asset::amount(&fa);

        // make sure this is the expected fungible asset.
        assert!(
            object::object_address(&fa_metadata)
                == object::object_address(&pool.fa_metadata),
            error::invalid_argument(E_UNKNOWN_FUNGIBLE_ASSET)
        );

        primary_fungible_store::deposit(pool.store_signer_address, fa);

        assert!(
            smart_table::contains(&pool.remote_chain_configs, remote_chain_selector),
            error::invalid_argument(E_UNKNOWN_REMOTE_CHAIN_SELECTOR)
        );
        let remote_chain_config =
            smart_table::borrow(&pool.remote_chain_configs, remote_chain_selector);
        let dest_token_address = remote_chain_config.remote_token_address;

        // set the output for this lock or burn operation.
        token_admin_registry::set_lock_or_burn_output(
            @ccip_lock_release_pool,
            CallbackProof {},
            dest_token_address
        );

        event::emit(
            Locked {
                local_token: object::object_address(&pool.fa_metadata),
                amount: fa_amount
            }
        );
        event::emit_event(
            &mut pool.locked_events,
            Locked {
                local_token: object::object_address(&pool.fa_metadata),
                amount: fa_amount
            }
        );
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, amount: u64, _transfer_ref: &TransferRef
    ): FungibleAsset acquires LockReleaseTokenPool {
        // retrieve the input for this release or mint operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_release_or_mint_input(
                @ccip_lock_release_pool, CallbackProof {}
            );

        let recipient = token_admin_registry::get_release_or_mint_receiver(&input);
        let local_token = token_admin_registry::get_release_or_mint_local_token(&input);

        let pool = borrow_pool_mut();

        // make sure the caller is requesting this pool's fungible asset.
        assert!(
            object::object_address(&pool.fa_metadata) == local_token,
            error::invalid_argument(E_UNKNOWN_FUNGIBLE_ASSET)
        );

        // TODO: do something with these fields.
        let _sender = token_admin_registry::get_release_or_mint_sender(&input);
        let _remote_chain_selector =
            token_admin_registry::get_release_or_mint_remote_chain_selector(&input);
        let _source_pool_address =
            token_admin_registry::get_release_or_mint_source_pool_address(&input);
        let _source_pool_data =
            token_admin_registry::get_release_or_mint_source_pool_data(&input);
        let _offchain_token_data =
            token_admin_registry::get_release_or_mint_offchain_token_data(&input);

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);

        // withdraw the amount from the store for release. this will revert if the store has insufficient balance.
        let fa = primary_fungible_store::withdraw(
            &store_signer, pool.fa_metadata, amount
        );

        // set the output for this release or mint operation.
        token_admin_registry::set_release_or_mint_output(
            @ccip_lock_release_pool, CallbackProof {}
        );

        event::emit(
            Released {
                local_token: object::object_address(&pool.fa_metadata),
                recipient,
                amount
            }
        );
        event::emit_event(
            &mut pool.released_events,
            Released {
                local_token: object::object_address(&pool.fa_metadata),
                recipient,
                amount
            }
        );

        // return the withdrawn fungible asset.
        fa
    }

    // TODO: separate functions due to deploy error, see ccip::state_object
    #[view]
    public fun get_store_address(): address {
        store_address()
    }

    inline fun store_address(): address {
        account::create_resource_address(&@ccip_lock_release_pool, STORE_OBJECT_SEED)
    }

    fun assert_can_initialize(caller_address: address) {
        if (caller_address == @ccip_lock_release_pool) { return };

        if (object::is_object(@ccip_lock_release_pool)) {
            let ccip_lock_release_pool_object =
                object::address_to_object<ObjectCore>(@ccip_lock_release_pool);
            if (caller_address == object::owner(ccip_lock_release_pool_object)
                || caller_address == object::root_owner(ccip_lock_release_pool_object)) {
                return
            };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }

    inline fun borrow_pool(): &LockReleaseTokenPool {
        borrow_global<LockReleaseTokenPool>(store_address())
    }

    inline fun borrow_pool_mut(): &mut LockReleaseTokenPool {
        borrow_global_mut<LockReleaseTokenPool>(store_address())
    }

    inline fun apply_allowlist_updates_internal(
        pool: &mut LockReleaseTokenPool, removes: vector<address>, adds: vector<address>
    ) {
        vector::for_each_ref(
            &removes,
            |remove_address| {
                let (found, i) = vector::index_of(&pool.allowlist, remove_address);
                if (found) {
                    vector::swap_remove(&mut pool.allowlist, i);
                    event::emit(AllowlistRemove { sender: *remove_address });
                    event::emit_event(
                        &mut pool.allowlist_remove_events,
                        AllowlistRemove { sender: *remove_address }
                    );
                }
            }
        );

        if (!vector::is_empty(&adds)) {
            assert!(
                pool.allowlist_enabled, error::invalid_state(E_ALLOWLIST_NOT_ENABLED)
            );

            vector::for_each_ref(
                &adds,
                |add_address| {
                    let add_address: address = *add_address;
                    let (found, _) = vector::index_of(&pool.allowlist, &add_address);
                    if (add_address != @0x0 && !found) {
                        vector::push_back(&mut pool.allowlist, add_address);
                        event::emit(AllowlistAdd { sender: add_address });
                        event::emit_event(
                            &mut pool.allowlist_add_events,
                            AllowlistAdd { sender: add_address }
                        );
                    }
                }
            );
        }
    }

    //
    // ccip::ownable functions
    //

    #[view]
    public fun owner(): address acquires LockReleaseTokenPool {
        let pool = borrow_pool();
        ownable::owner(&pool.ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires LockReleaseTokenPool {
        let pool = borrow_pool_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut pool.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires LockReleaseTokenPool {
        let pool = borrow_pool_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut pool.ownable_state)
    }
}
