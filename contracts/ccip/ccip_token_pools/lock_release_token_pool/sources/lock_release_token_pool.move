module lock_release_token_pool::lock_release_token_pool {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};
    use std::option;
    use std::signer;
    use std::string::{Self, String};

    use ccip::ownable;
    use ccip::token_admin_registry;
    use ccip_token_pool::token_pool;

    use mcms::mcms_registry;
    use mcms::bcs_stream;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipLockReleaseTokenPool";

    struct LockReleaseTokenPoolDeployment has key {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState
    }

    struct LockReleaseTokenPoolState has key, store {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState,
        store_signer_address: address
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INVALID_FUNGIBLE_ASSET: u64 = 3;
    const E_INVALID_ARGUMENTS: u64 = 4;
    const E_UNKNOWN_FUNCTION: u64 = 5;

    // ================================================================
    // |                             Init                             |
    // ================================================================

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"LockReleaseTokenPool 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @ccip_lock_release_pool.
        assert!(
            object::object_exists<Metadata>(@local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );
        let metadata = object::address_to_object<Metadata>(@local_token);

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"lock_release_token_pool";

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(token_pool_module_name), McmsCallback {}
            );
        };

        token_admin_registry::register_pool(
            publisher,
            token_pool_module_name,
            @local_token,
            CallbackProof {}
        );

        // create a resource account to be the owner of the primary FungibleStore we will use.
        let (store_signer, store_signer_cap) =
            account::create_resource_account(publisher, STORE_OBJECT_SEED);

        // make sure this is a valid fungible asset that is primary fungible store enabled,
        // ie. created with primary_fungible_store::create_primary_store_enabled_fungible_asset
        primary_fungible_store::ensure_primary_store_exists(
            signer::address_of(&store_signer), metadata
        );

        move_to(
            publisher,
            LockReleaseTokenPoolDeployment {
                store_signer_cap,
                ownable_state: ownable::new(publisher, @lock_release_token_pool),
                token_pool_state: token_pool::initialize(
                    publisher, @local_token, vector[]
                )
            }
        );
    }

    public fun initialize(caller: &signer) acquires LockReleaseTokenPoolDeployment {
        assert_can_initialize(signer::address_of(caller));

        assert!(
            exists<LockReleaseTokenPoolDeployment>(@lock_release_token_pool),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let LockReleaseTokenPoolDeployment {
            store_signer_cap,
            ownable_state,
            token_pool_state
        } = move_from<LockReleaseTokenPoolDeployment>(@lock_release_token_pool);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        let pool = LockReleaseTokenPoolState {
            ownable_state,
            store_signer_address: signer::address_of(&store_signer),
            store_signer_cap,
            token_pool_state
        };
        move_to(&store_signer, pool);
    }

    // ================================================================
    // |                 Exposing token_pool functions                |
    // ================================================================

    #[view]
    public fun get_token(): address acquires LockReleaseTokenPoolState {
        token_pool::get_token(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_router(): address {
        token_pool::get_router()
    }

    #[view]
    public fun get_token_decimals(): u8 acquires LockReleaseTokenPoolState {
        token_pool::get_token_decimals(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_remote_pools(
        remote_chain_selector: u64
    ): vector<vector<u8>> acquires LockReleaseTokenPoolState {
        token_pool::get_remote_pools(
            &borrow_pool().token_pool_state, remote_chain_selector
        )
    }

    #[view]
    public fun is_remote_pool(
        remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool acquires LockReleaseTokenPoolState {
        token_pool::is_remote_pool(
            &borrow_pool().token_pool_state,
            remote_chain_selector,
            remote_pool_address
        )
    }

    #[view]
    public fun get_remote_token(
        remote_chain_selector: u64
    ): vector<u8> acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_remote_token(&pool.token_pool_state, remote_chain_selector)
    }

    public entry fun add_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::add_remote_pool(
            &mut pool.token_pool_state, remote_chain_selector, remote_pool_address
        );
    }

    public entry fun remove_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::remove_remote_pool(
            &mut pool.token_pool_state, remote_chain_selector, remote_pool_address
        );
    }

    #[view]
    public fun is_supported_chain(
        remote_chain_selector: u64
    ): bool acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        token_pool::is_supported_chain(&pool.token_pool_state, remote_chain_selector)
    }

    #[view]
    public fun get_supported_chains(): vector<u64> acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_supported_chains(&pool.token_pool_state)
    }

    public entry fun apply_chain_updates(
        caller: &signer,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::apply_chain_updates(
            &mut pool.token_pool_state,
            remote_chain_selectors_to_remove,
            remote_chain_selectors_to_add,
            remote_pool_addresses_to_add,
            remote_token_addresses_to_add
        );
    }

    #[view]
    public fun get_allowlist_enabled(): bool acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_allowlist_enabled(&pool.token_pool_state)
    }

    #[view]
    public fun get_allowlist(): vector<address> acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_allowlist(&pool.token_pool_state)
    }

    public entry fun apply_allowlist_updates(
        caller: &signer, removes: vector<address>, adds: vector<address>
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);
        token_pool::apply_allowlist_updates(&mut pool.token_pool_state, removes, adds);
    }

    // ================================================================
    // |                       Lock/Release                           |
    // ================================================================

    // the callback proof type used as authentication to retrieve and set input and output arguments.
    struct CallbackProof has drop {}

    public fun lock_or_burn<T: key>(
        _store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
    ) acquires LockReleaseTokenPoolState {
        // retrieve the input for this lock or burn operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_lock_or_burn_input_v1(
                @lock_release_token_pool, CallbackProof {}
            );

        let pool = borrow_pool_mut();
        let fa_amount = fungible_asset::amount(&fa);

        // This metod validates various aspects of the lock or burn operation. If any of the
        // validations fail, the transaction will abort.
        let dest_token_address =
            token_pool::validate_lock_or_burn(
                &mut pool.token_pool_state,
                &fa,
                &input,
                fa_amount
            );

        // Construct lock_or_burn output before we lose access to fa
        let dest_pool_data = token_pool::encode_local_decimals(&fa);

        // Lock the funds in the pool
        primary_fungible_store::deposit(pool.store_signer_address, fa);

        // set the output for this lock or burn operation.
        token_admin_registry::set_lock_or_burn_output_v1(
            @lock_release_token_pool,
            CallbackProof {},
            dest_token_address,
            dest_pool_data
        );

        token_pool::emit_locked_or_burned(&mut pool.token_pool_state, fa_amount);
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, _amount: u64, _transfer_ref: &TransferRef
    ): FungibleAsset acquires LockReleaseTokenPoolState {
        // retrieve the input for this release or mint operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_release_or_mint_input_v1(
                @lock_release_token_pool, CallbackProof {}
            );
        let pool = borrow_pool_mut();
        let local_amount =
            token_pool::calculate_release_or_mint_amount(&pool.token_pool_state, &input);

        token_pool::validate_release_or_mint(
            &mut pool.token_pool_state, &input, local_amount
        );

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);
        let fa_metadata = token_pool::get_fa_metadata(&pool.token_pool_state);
        // Withdraw the amount from the store for release. this will revert if the store has insufficient balance.
        let fa = primary_fungible_store::withdraw(
            &store_signer, fa_metadata, local_amount
        );

        // set the output for this release or mint operation.
        token_admin_registry::set_release_or_mint_output_v1(
            @lock_release_token_pool, CallbackProof {}, local_amount
        );

        let recipient = token_admin_registry::get_release_or_mint_receiver(&input);

        token_pool::emit_released_or_minted(
            &mut pool.token_pool_state,
            recipient,
            local_amount
        );

        // return the withdrawn fungible asset.
        fa
    }

    // ================================================================
    // |                    Rate limit config                         |
    // ================================================================

    public fun set_chain_rate_limiter_configs(
        caller: &signer,
        remote_chain_selectors: vector<u64>,
        outbound_is_enableds: vector<bool>,
        outbound_capacities: vector<u64>,
        outbound_rates: vector<u64>,
        inbound_is_enableds: vector<bool>,
        inbound_capacities: vector<u64>,
        inbound_rates: vector<u64>
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        let number_of_chains = remote_chain_selectors.length();

        assert!(
            number_of_chains == outbound_is_enableds.length()
                && number_of_chains == outbound_capacities.length()
                && number_of_chains == outbound_rates.length()
                && number_of_chains == inbound_is_enableds.length()
                && number_of_chains == inbound_capacities.length()
                && number_of_chains == inbound_rates.length(),
            error::invalid_argument(E_INVALID_ARGUMENTS)
        );

        for (i in 0..number_of_chains) {
            token_pool::set_chain_rate_limiter_config(
                &mut pool.token_pool_state,
                remote_chain_selectors[i],
                outbound_is_enableds[i],
                outbound_capacities[i],
                outbound_rates[i],
                inbound_is_enableds[i],
                inbound_capacities[i],
                inbound_rates[i]
            );
        };
    }

    public fun set_chain_rate_limiter_config(
        caller: &signer,
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::set_chain_rate_limiter_config(
            &mut pool.token_pool_state,
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
    // |                      Storage helpers                         |
    // ================================================================

    // TODO: separate functions due to deploy error, see ccip::state_object
    #[view]
    public fun get_store_address(): address {
        store_address()
    }

    inline fun store_address(): address {
        account::create_resource_address(&@lock_release_token_pool, STORE_OBJECT_SEED)
    }

    fun assert_can_initialize(caller_address: address) {
        if (caller_address == @lock_release_token_pool) { return };

        if (object::is_object(@lock_release_token_pool)) {
            let ccip_lock_release_pool_object =
                object::address_to_object<ObjectCore>(@lock_release_token_pool);
            if (caller_address == object::owner(ccip_lock_release_pool_object)
                || caller_address == object::root_owner(ccip_lock_release_pool_object)) {
                return
            };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }

    inline fun borrow_pool(): &LockReleaseTokenPoolState {
        borrow_global<LockReleaseTokenPoolState>(store_address())
    }

    inline fun borrow_pool_mut(): &mut LockReleaseTokenPoolState {
        borrow_global_mut<LockReleaseTokenPoolState>(store_address())
    }

    // ================================================================
    // |                       Expose ownable                         |
    // ================================================================

    #[view]
    public fun owner(): address acquires LockReleaseTokenPoolState {
        let pool = borrow_pool();
        ownable::owner(&pool.ownable_state)
    }

    public entry fun transfer_ownership(
        caller: &signer, to: address
    ) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut pool.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires LockReleaseTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut pool.ownable_state)
    }

    // ================================================================
    // |                      MCMS entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires LockReleaseTokenPoolState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@lock_release_token_pool, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"add_remote_pool") {
            let remote_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let remote_pool_address = bcs_stream::deserialize_vector_u8(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            add_remote_pool(&caller, remote_chain_selector, remote_pool_address);
        } else if (function_bytes == b"remove_remote_pool") {
            let remote_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let remote_pool_address = bcs_stream::deserialize_vector_u8(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            remove_remote_pool(&caller, remote_chain_selector, remote_pool_address);
        } else if (function_bytes == b"apply_chain_updates") {
            let remote_chain_selectors_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let remote_chain_selectors_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let remote_pool_addresses_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector(
                        stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                    )
                );
            let remote_token_addresses_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_chain_updates(
                &caller,
                remote_chain_selectors_to_remove,
                remote_chain_selectors_to_add,
                remote_pool_addresses_to_add,
                remote_token_addresses_to_add
            );
        } else if (function_bytes == b"apply_allowlist_updates") {
            let removes =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let adds =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_allowlist_updates(&caller, removes, adds);
        } else if (function_bytes == b"set_chain_rate_limiter_configs") {
            let remote_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let outbound_is_enableds =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let outbound_capacities =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let outbound_rates =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let inbound_is_enableds =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            let inbound_capacities =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let inbound_rates =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            set_chain_rate_limiter_configs(
                &caller,
                remote_chain_selectors,
                outbound_is_enableds,
                outbound_capacities,
                outbound_rates,
                inbound_is_enableds,
                inbound_capacities,
                inbound_rates
            );
        } else if (function_bytes == b"set_chain_rate_limiter_config") {
            let remote_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            let outbound_is_enabled = bcs_stream::deserialize_bool(&mut stream);
            let outbound_capacity = bcs_stream::deserialize_u64(&mut stream);
            let outbound_rate = bcs_stream::deserialize_u64(&mut stream);
            let inbound_is_enabled = bcs_stream::deserialize_bool(&mut stream);
            let inbound_capacity = bcs_stream::deserialize_u64(&mut stream);
            let inbound_rate = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_chain_rate_limiter_config(
                &caller,
                remote_chain_selector,
                outbound_is_enabled,
                outbound_capacity,
                outbound_rate,
                inbound_is_enabled,
                inbound_capacity,
                inbound_rate
            );
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            transfer_ownership(&caller, to);
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);
            accept_ownership(&caller);
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }
}
