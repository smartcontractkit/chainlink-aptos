module usdc_token_pool::usdc_token_pool {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};
    use aptos_framework::fungible_asset::{BurnRef, MintRef};

    use ccip::eth_abi;
    use ccip::ownable;
    use ccip::token_admin_registry;
    use ccip_token_pool::token_pool;

    use token_messenger_minter::token_messenger;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipUSDCTokenPool";

    struct USDCTokenPoolDeployment has key {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState
    }

    struct USDCTokenPool has key, store {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState,
        chain_to_domain: SmartTable<u64, Domain>,
        store_signer_address: address,
        burn_ref: BurnRef,
        mint_ref: MintRef
    }

    /// A domain is a USDC representation of a destination chain.
    /// @dev Zero is a valid domain identifier.
    /// @dev The address to mint on the destination chain is the corresponding USDC pool.
    /// @dev The allowedCaller represents the contract authorized to call receiveMessage on the destination CCTP message transmitter.
    /// For EVM dest pool version 1.6.1, this is the MessageTransmitterProxy of the destination chain.
    /// For EVM dest pool version 1.5.1, this is the destination chain's token pool.
    struct Domain has key, store, drop {
        allow_caller: address, //  Address allowed to mint on the domain
        domain_identifier: u32, // Unique domain ID
        enabled: bool
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INVALID_FUNGIBLE_ASSET: u64 = 3;
    const E_LOCAL_TOKEN_MISMATCH: u64 = 4;
    const E_INVALID_ARGUMENTS: u64 = 5;
    const E_DOMAIN_NOT_FOUND: u64 = 6;
    const E_DOMAIN_ENABLED: u64 = 6;

    // ================================================================
    // |                             Init                             |
    // ================================================================

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"USDCTokenPool 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @ccip_usdc_pool.
        assert!(
            !object::object_exists<Metadata>(@local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );
        let metadata = object::address_to_object<Metadata>(@local_token);

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"usdc_token_pool";

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
            USDCTokenPoolDeployment {
                store_signer_cap,
                ownable_state: ownable::new(publisher, signer::address_of(publisher)),
                token_pool_state: token_pool::initialize(
                    publisher, @local_token, vector[]
                )
            }
        );
    }

    public fun initialize(
        caller: &signer,
        local_token: address,
        burn_ref: BurnRef,
        mint_ref: MintRef
    ) acquires USDCTokenPoolDeployment {
        assert_can_initialize(signer::address_of(caller));

        assert!(
            exists<USDCTokenPoolDeployment>(@usdc_token_pool),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        assert!(
            @local_token == local_token,
            error::invalid_argument(E_LOCAL_TOKEN_MISMATCH)
        );

        let USDCTokenPoolDeployment { store_signer_cap, ownable_state, token_pool_state } =
            move_from<USDCTokenPoolDeployment>(@usdc_token_pool);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        let pool = USDCTokenPool {
            ownable_state,
            store_signer_address: signer::address_of(&store_signer),
            chain_to_domain: smart_table::new(),
            store_signer_cap,
            token_pool_state,
            burn_ref,
            mint_ref
        };

        move_to(&store_signer, pool);
    }

    // ================================================================
    // |                 Exposing token_pool functions                |
    // ================================================================

    #[view]
    public fun get_token(): address acquires USDCTokenPool {
        token_pool::get_token(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_router(): address {
        token_pool::get_router()
    }

    #[view]
    public fun get_token_decimals(): u8 acquires USDCTokenPool {
        token_pool::get_token_decimals(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_remote_pools(
        remote_chain_selector: u64
    ): vector<vector<u8>> acquires USDCTokenPool {
        token_pool::get_remote_pools(
            &borrow_pool().token_pool_state, remote_chain_selector
        )
    }

    #[view]
    public fun is_remote_pool(
        remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool acquires USDCTokenPool {
        token_pool::is_remote_pool(
            &borrow_pool().token_pool_state,
            remote_chain_selector,
            remote_pool_address
        )
    }

    #[view]
    public fun get_remote_token(remote_chain_selector: u64): vector<u8> acquires USDCTokenPool {
        let pool = borrow_pool();
        token_pool::get_remote_token(&pool.token_pool_state, remote_chain_selector)
    }

    public entry fun add_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires USDCTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::add_remote_pool(
            &mut pool.token_pool_state, remote_chain_selector, remote_pool_address
        );
    }

    public entry fun remove_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires USDCTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::remove_remote_pool(
            &mut pool.token_pool_state, remote_chain_selector, remote_pool_address
        );
    }

    #[view]
    public fun is_supported_chain(remote_chain_selector: u64): bool acquires USDCTokenPool {
        let pool = borrow_pool();
        token_pool::is_supported_chain(&pool.token_pool_state, remote_chain_selector)
    }

    #[view]
    public fun get_supported_chains(): vector<u64> acquires USDCTokenPool {
        let pool = borrow_pool();
        token_pool::get_supported_chains(&pool.token_pool_state)
    }

    public entry fun apply_chain_updates(
        caller: &signer,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) acquires USDCTokenPool {
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
    public fun get_allowlist_enabled(): bool acquires USDCTokenPool {
        let pool = borrow_pool();
        token_pool::get_allowlist_enabled(&pool.token_pool_state)
    }

    #[view]
    public fun get_allowlist(): vector<address> acquires USDCTokenPool {
        let pool = borrow_pool();
        token_pool::get_allowlist(&pool.token_pool_state)
    }

    public entry fun apply_allowlist_updates(
        caller: &signer, removes: vector<address>, adds: vector<address>
    ) acquires USDCTokenPool {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);
        token_pool::apply_allowlist_updates(&mut pool.token_pool_state, removes, adds);
    }

    // ================================================================
    // |                         Burn/Mint                            |
    // ================================================================

    // the callback proof type used as authentication to retrieve and set input and output arguments.
    struct CallbackProof has drop {}

    public fun lock_or_burn<T: key>(
        _store: Object<T>, fa: FungibleAsset, _transfer_ref: &BurnRef
    ) acquires USDCTokenPool {
        // retrieve the input for this lock or burn operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_lock_or_burn_input_v1(
                @usdc_token_pool, CallbackProof {}
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

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);

        let remote_chain_selector =
            token_admin_registry::get_lock_or_burn_remote_chain_selector(&input);
        assert!(
            smart_table::contains(&pool.chain_to_domain, remote_chain_selector),
            error::invalid_argument(E_DOMAIN_NOT_FOUND)
        );

        let remote_domain_info = pool.chain_to_domain.borrow(remote_chain_selector);

        assert!(
            remote_domain_info.enabled,
            error::invalid_argument(E_DOMAIN_ENABLED)
        );

        let mint_recipient_bytes =
            token_admin_registry::get_lock_or_burn_receiver(&input); // TODO mint_recipient
        let mint_recipient = @0x404; // TODO mint_recipient
        let nonce =
            token_messenger::deposit_for_burn_with_caller(
                &store_signer,
                fa,
                remote_domain_info.domain_identifier,
                mint_recipient,
                remote_domain_info.allow_caller
            );

        // USDC Pools use the nonce as dest pool data
        let dest_pool_data = vector[];
        eth_abi::encode_u64(&mut dest_pool_data, nonce);

        // set the output for this lock or burn operation.
        token_admin_registry::set_lock_or_burn_output_v1(
            @usdc_token_pool,
            CallbackProof {},
            dest_token_address,
            dest_pool_data
        );

        token_pool::emit_locked_or_burned(&mut pool.token_pool_state, fa_amount);
    }

    public fun encode_local_decimals(fa: &FungibleAsset): vector<u8> {
        let fa_metadata = fungible_asset::metadata_from_asset(fa);
        let fa_decimals = fungible_asset::decimals(fa_metadata);
        let ret = vector[];
        eth_abi::encode_u8(&mut ret, fa_decimals);
        ret
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, _amount: u64, _transfer_ref: &TransferRef
    ): FungibleAsset acquires USDCTokenPool {
        // retrieve the input for this release or mint operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_release_or_mint_input_v1(
                @usdc_token_pool, CallbackProof {}
            );
        let pool = borrow_pool_mut();
        let local_amount =
            token_pool::calculate_release_or_mint_amount(&pool.token_pool_state, &input);

        token_pool::validate_release_or_mint(
            &mut pool.token_pool_state, &input, local_amount
        );

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);
        let store_address =
            account::get_signer_capability_address(&pool.store_signer_cap);
        let fa_metadata = token_pool::get_fa_metadata(&pool.token_pool_state);
        // Mint and withdraw the amount from the store for release. this will revert if the store has insufficient balance.
        primary_fungible_store::mint(&pool.mint_ref, store_address, local_amount);
        let fa = primary_fungible_store::withdraw(
            &store_signer, fa_metadata, local_amount
        );

        // set the output for this release or mint operation.
        token_admin_registry::set_release_or_mint_output_v1(
            @usdc_token_pool, CallbackProof {}, local_amount
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
    // |                      USDC Domains                            |
    // ================================================================

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
    ) acquires USDCTokenPool {
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
    ) acquires USDCTokenPool {
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
        account::create_resource_address(&@usdc_token_pool, STORE_OBJECT_SEED)
    }

    fun assert_can_initialize(caller_address: address) {
        if (caller_address == @usdc_token_pool) { return };

        if (object::is_object(@usdc_token_pool)) {
            let usdc_token_pool_object =
                object::address_to_object<ObjectCore>(@usdc_token_pool);
            if (caller_address == object::owner(usdc_token_pool_object)
                || caller_address == object::root_owner(usdc_token_pool_object)) { return };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }

    inline fun borrow_pool(): &USDCTokenPool {
        borrow_global<USDCTokenPool>(store_address())
    }

    inline fun borrow_pool_mut(): &mut USDCTokenPool {
        borrow_global_mut<USDCTokenPool>(store_address())
    }

    // ================================================================
    // |                       Expose ownable                         |
    // ================================================================

    #[view]
    public fun owner(): address acquires USDCTokenPool {
        let pool = borrow_pool();
        ownable::owner(&pool.ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires USDCTokenPool {
        let pool = borrow_pool_mut();
        ownable::transfer_ownership(
            signer::address_of(caller), &mut pool.ownable_state, to
        )
    }

    public entry fun accept_ownership(caller: &signer) acquires USDCTokenPool {
        let pool = borrow_pool_mut();
        ownable::accept_ownership(signer::address_of(caller), &mut pool.ownable_state)
    }
}
