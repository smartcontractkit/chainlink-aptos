module usdc_token_pool::usdc_token_pool {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::from_bcs;
    use std::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};
    use std::option::{Self, Option};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};

    use ccip::address;
    use ccip::eth_abi;
    use ccip::token_admin_registry::{Self, LockOrBurnInputV1, ReleaseOrMintInputV1};
    use ccip_token_pool::ownable;
    use ccip_token_pool::rate_limiter;
    use ccip_token_pool::token_pool;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    use message_transmitter::message;
    use message_transmitter::message_transmitter;
    use token_messenger_minter::token_messenger;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipUSDCTokenPool";

    // We restrict to the first version. New pool may be required for subsequent versions.
    const SUPPORTED_USDC_VERSION: u32 = 0;

    struct USDCTokenPoolDeployment has key {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState,
        domain_set_events: EventHandle<DomainsSet>
    }

    struct USDCTokenPoolState has key, store {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState,
        chain_to_domain: SmartTable<u64, Domain>,
        local_domain_identifier: u32,
        store_signer_address: address,
        domain_set_events: EventHandle<DomainsSet>
    }

    /// A domain is a USDC representation of a destination chain.
    /// @dev Zero is a valid domain identifier.
    /// @dev The address to mint on the destination chain is the corresponding USDC pool.
    /// @dev The allowedCaller represents the contract authorized to call receiveMessage on the destination CCTP message transmitter.
    /// For EVM dest pool version 1.6.1, this is the MessageTransmitterProxy of the destination chain.
    /// For EVM dest pool version 1.5.1, this is the destination chain's token pool.
    struct Domain has key, store, drop, copy {
        allowed_caller: vector<u8>, //  Address allowed to mint on the domain
        domain_identifier: u32, // Unique domain ID
        enabled: bool
    }

    #[event]
    struct DomainsSet has store, drop {
        allowed_caller: vector<u8>,
        domain_identifier: u32,
        remote_chain_selector: u64,
        enabled: bool
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INVALID_FUNGIBLE_ASSET: u64 = 3;
    const E_INVALID_ARGUMENTS: u64 = 4;
    const E_DOMAIN_NOT_FOUND: u64 = 5;
    const E_DOMAIN_ENABLED: u64 = 6;
    const E_UNKNOWN_FUNCTION: u64 = 7;
    const E_DOMAIN_MISMATCH: u64 = 8;
    const E_NONCE_MISMATCH: u64 = 9;
    const E_DESTINATION_MISMATCH: u64 = 10;
    const E_DOMAIN_DISABLED: u64 = 11;
    const E_ZERO_CHAIN_SELECTOR: u64 = 12;
    const E_EMPTY_ALLOWED_CALLER: u64 = 13;
    const E_INVALID_MESSAGE_VERSION: u64 = 14;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 15;

    // ================================================================
    // |                             Init                             |
    // ================================================================
    #[view]
    public fun type_and_version(): String {
        string::utf8(b"USDCTokenPool 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @usdc_token_pool.
        assert!(
            object::object_exists<Metadata>(@local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );
        let metadata = object::address_to_object<Metadata>(@local_token);

        // create an Account on the object for event handles.
        account::create_account_if_does_not_exist(@usdc_token_pool);

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"usdc_token_pool";

        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher, token_pool_module_name);
        };

        // Register V2 pool with closure-based callbacks
        register_v2_callbacks(publisher);

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
                ownable_state: ownable::new(&store_signer, @usdc_token_pool),
                token_pool_state: token_pool::initialize(
                    &store_signer, @local_token, vector[]
                ),
                domain_set_events: account::new_event_handle(&store_signer)
            }
        );
    }

    public fun register_v2_callbacks(publisher: &signer) {
        assert!(
            signer::address_of(publisher) == @usdc_token_pool,
            error::permission_denied(E_NOT_PUBLISHER)
        );
        token_admin_registry::register_pool_v2(
            publisher,
            @local_token,
            lock_or_burn_v2,
            release_or_mint_v2
        );
    }

    public fun initialize(caller: &signer) acquires USDCTokenPoolDeployment {
        assert_can_initialize(signer::address_of(caller));

        assert!(
            exists<USDCTokenPoolDeployment>(@usdc_token_pool),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let USDCTokenPoolDeployment {
            store_signer_cap,
            ownable_state,
            token_pool_state,
            domain_set_events
        } = move_from<USDCTokenPoolDeployment>(@usdc_token_pool);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        let pool = USDCTokenPoolState {
            ownable_state,
            store_signer_address: signer::address_of(&store_signer),
            chain_to_domain: smart_table::new(),
            local_domain_identifier: message_transmitter::local_domain(),
            store_signer_cap,
            token_pool_state,
            domain_set_events
        };

        move_to(&store_signer, pool);
    }

    // ================================================================
    // |                 Exposing token_pool functions                |
    // ================================================================
    #[view]
    public fun get_token(): address acquires USDCTokenPoolState {
        token_pool::get_token(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_router(): address {
        token_pool::get_router()
    }

    #[view]
    public fun get_token_decimals(): u8 acquires USDCTokenPoolState {
        token_pool::get_token_decimals(&borrow_pool().token_pool_state)
    }

    #[view]
    public fun get_remote_pools(
        remote_chain_selector: u64
    ): vector<vector<u8>> acquires USDCTokenPoolState {
        token_pool::get_remote_pools(
            &borrow_pool().token_pool_state, remote_chain_selector
        )
    }

    #[view]
    public fun is_remote_pool(
        remote_chain_selector: u64, remote_pool_address: vector<u8>
    ): bool acquires USDCTokenPoolState {
        token_pool::is_remote_pool(
            &borrow_pool().token_pool_state,
            remote_chain_selector,
            remote_pool_address
        )
    }

    #[view]
    public fun get_remote_token(remote_chain_selector: u64): vector<u8> acquires USDCTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_remote_token(&pool.token_pool_state, remote_chain_selector)
    }

    public entry fun add_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::add_remote_pool(
            &mut pool.token_pool_state,
            remote_chain_selector,
            remote_pool_address
        );
    }

    public entry fun remove_remote_pool(
        caller: &signer, remote_chain_selector: u64, remote_pool_address: vector<u8>
    ) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        token_pool::remove_remote_pool(
            &mut pool.token_pool_state,
            remote_chain_selector,
            remote_pool_address
        );
    }

    #[view]
    public fun is_supported_chain(remote_chain_selector: u64): bool acquires USDCTokenPoolState {
        let pool = borrow_pool();
        token_pool::is_supported_chain(&pool.token_pool_state, remote_chain_selector)
    }

    #[view]
    public fun get_supported_chains(): vector<u64> acquires USDCTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_supported_chains(&pool.token_pool_state)
    }

    public entry fun apply_chain_updates(
        caller: &signer,
        remote_chain_selectors_to_remove: vector<u64>,
        remote_chain_selectors_to_add: vector<u64>,
        remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
        remote_token_addresses_to_add: vector<vector<u8>>
    ) acquires USDCTokenPoolState {
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
    public fun get_allowlist_enabled(): bool acquires USDCTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_allowlist_enabled(&pool.token_pool_state)
    }

    public entry fun set_allowlist_enabled(caller: &signer, enabled: bool) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);
        token_pool::set_allowlist_enabled(&mut pool.token_pool_state, enabled);
    }

    #[view]
    public fun get_allowlist(): vector<address> acquires USDCTokenPoolState {
        let pool = borrow_pool();
        token_pool::get_allowlist(&pool.token_pool_state)
    }

    public entry fun apply_allowlist_updates(
        caller: &signer, removes: vector<address>, adds: vector<address>
    ) acquires USDCTokenPoolState {
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
        _store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
    ) acquires USDCTokenPoolState {
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

        assert!(remote_domain_info.enabled, error::invalid_argument(E_DOMAIN_DISABLED));

        let mint_recipient_bytes =
            token_admin_registry::get_lock_or_burn_receiver(&input);
        let mint_recipient = from_bcs::to_address(mint_recipient_bytes);
        let nonce =
            token_messenger::deposit_for_burn_with_caller(
                &store_signer,
                fa,
                remote_domain_info.domain_identifier,
                mint_recipient,
                from_bcs::to_address(remote_domain_info.allowed_caller)
            );

        let dest_pool_data = encode_dest_pool_data(pool.local_domain_identifier, nonce);

        // set the output for this lock or burn operation.
        token_admin_registry::set_lock_or_burn_output_v1(
            @usdc_token_pool,
            CallbackProof {},
            dest_token_address,
            dest_pool_data
        );

        token_pool::emit_locked_or_burned(
            &mut pool.token_pool_state, fa_amount, remote_chain_selector
        );
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, _amount: u64, _transfer_ref: &TransferRef
    ): FungibleAsset acquires USDCTokenPoolState {
        // retrieve the input for this release or mint operation. if this function is invoked
        // outside of ccip::token_admin_registry, the transaction will abort.
        let input =
            token_admin_registry::get_release_or_mint_input_v1(
                @usdc_token_pool, CallbackProof {}
            );
        let pool = borrow_pool_mut();
        let local_amount =
            token_admin_registry::get_release_or_mint_source_amount(&input) as u64;

        token_pool::validate_release_or_mint(
            &mut pool.token_pool_state, &input, local_amount
        );

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);

        let (source_domain_identifier, nonce) =
            decode_dest_pool_data(
                token_admin_registry::get_release_or_mint_source_pool_data(&input)
            );
        let offchain_token_data =
            token_admin_registry::get_release_or_mint_offchain_token_data(&input);

        let (message_bytes, attestation) =
            parse_message_and_attestation(offchain_token_data);

        validate_message(
            &message_bytes,
            source_domain_identifier,
            nonce,
            pool.local_domain_identifier
        );

        let receipt =
            message_transmitter::receive_message(
                &store_signer, &message_bytes, &attestation
            );

        assert!(token_messenger::handle_receive_message(receipt));

        // set the output for this release or mint operation.
        token_admin_registry::set_release_or_mint_output_v1(
            @usdc_token_pool, CallbackProof {}, local_amount
        );

        let recipient = token_admin_registry::get_release_or_mint_receiver(&input);
        let remote_chain_selector =
            token_admin_registry::get_release_or_mint_remote_chain_selector(&input);

        token_pool::emit_released_or_minted(
            &mut pool.token_pool_state,
            recipient,
            local_amount,
            remote_chain_selector
        );

        let fa_metadata = token_pool::get_fa_metadata(&pool.token_pool_state);

        // return the withdrawn fungible asset.
        fungible_asset::zero(fa_metadata)
    }

    inline fun parse_message_and_attestation(payload: vector<u8>): (vector<u8>, vector<u8>) {
        let stream = eth_abi::new_stream(payload);

        let message = eth_abi::decode_bytes(&mut stream);
        let attestation = eth_abi::decode_bytes(&mut stream);

        (message, attestation)
    }

    inline fun encode_dest_pool_data(
        local_domain_identifier: u32, nonce: u64
    ): vector<u8> {
        let dest_pool_data = vector[];
        eth_abi::encode_u64(&mut dest_pool_data, nonce);
        eth_abi::encode_u32(&mut dest_pool_data, local_domain_identifier);

        dest_pool_data
    }

    inline fun decode_dest_pool_data(dest_pool_data: vector<u8>): (u32, u64) {
        let stream = eth_abi::new_stream(dest_pool_data);
        let nonce = eth_abi::decode_u64(&mut stream);
        let local_domain_identifier = eth_abi::decode_u32(&mut stream);

        (local_domain_identifier, nonce)
    }

    inline fun validate_message(
        usdc_message: &vector<u8>,
        expected_source_domain: u32,
        expected_nonce: u64,
        expected_local_domain: u32
    ) {
        let version = message::get_message_version(usdc_message);
        assert!(
            version == SUPPORTED_USDC_VERSION,
            error::invalid_argument(E_INVALID_MESSAGE_VERSION)
        );

        let source_domain = message::get_src_domain_id(usdc_message);
        let nonce = message::get_nonce(usdc_message);
        let destination_domain = message::get_destination_domain_id(usdc_message);

        assert!(
            source_domain == expected_source_domain,
            error::invalid_argument(E_DOMAIN_MISMATCH)
        );

        assert!(nonce == expected_nonce, error::invalid_argument(E_NONCE_MISMATCH));

        assert!(
            destination_domain == expected_local_domain,
            error::invalid_argument(E_DESTINATION_MISMATCH)
        );
    }

    #[persistent]
    fun lock_or_burn_v2(
        fa: FungibleAsset, input: LockOrBurnInputV1
    ): (vector<u8>, vector<u8>) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        let fa_amount = fungible_asset::amount(&fa);

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
            pool.chain_to_domain.contains(remote_chain_selector),
            error::invalid_argument(E_DOMAIN_NOT_FOUND)
        );

        let remote_domain_info = pool.chain_to_domain.borrow(remote_chain_selector);

        assert!(remote_domain_info.enabled, error::invalid_argument(E_DOMAIN_DISABLED));

        let mint_recipient_bytes =
            token_admin_registry::get_lock_or_burn_receiver(&input);
        let mint_recipient = from_bcs::to_address(mint_recipient_bytes);
        let nonce =
            token_messenger::deposit_for_burn_with_caller(
                &store_signer,
                fa,
                remote_domain_info.domain_identifier,
                mint_recipient,
                from_bcs::to_address(remote_domain_info.allowed_caller)
            );

        let dest_pool_data = encode_dest_pool_data(pool.local_domain_identifier, nonce);

        token_pool::emit_locked_or_burned(
            &mut pool.token_pool_state, fa_amount, remote_chain_selector
        );

        (dest_token_address, dest_pool_data)
    }

    #[persistent]
    fun release_or_mint_v2(
        input: ReleaseOrMintInputV1
    ): (FungibleAsset, u64) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        let local_amount =
            token_admin_registry::get_release_or_mint_source_amount(&input) as u64;

        token_pool::validate_release_or_mint(
            &mut pool.token_pool_state, &input, local_amount
        );

        let store_signer = account::create_signer_with_capability(&pool.store_signer_cap);

        let (source_domain_identifier, nonce) =
            decode_dest_pool_data(
                token_admin_registry::get_release_or_mint_source_pool_data(&input)
            );
        let offchain_token_data =
            token_admin_registry::get_release_or_mint_offchain_token_data(&input);

        let (message_bytes, attestation) =
            parse_message_and_attestation(offchain_token_data);

        validate_message(
            &message_bytes,
            source_domain_identifier,
            nonce,
            pool.local_domain_identifier
        );

        let receipt =
            message_transmitter::receive_message(
                &store_signer, &message_bytes, &attestation
            );

        assert!(token_messenger::handle_receive_message(receipt));

        let recipient = token_admin_registry::get_release_or_mint_receiver(&input);
        let remote_chain_selector =
            token_admin_registry::get_release_or_mint_remote_chain_selector(&input);

        token_pool::emit_released_or_minted(
            &mut pool.token_pool_state,
            recipient,
            local_amount,
            remote_chain_selector
        );

        let fa_metadata = token_pool::get_fa_metadata(&pool.token_pool_state);

        (fungible_asset::zero(fa_metadata), local_amount)
    }

    // ================================================================
    // |                      USDC Domains                            |
    // ================================================================
    #[view]
    public fun get_domain(chain_selector: u64): Domain acquires USDCTokenPoolState {
        let pool = borrow_pool();
        *pool.chain_to_domain.borrow(chain_selector)
    }

    public fun set_domains(
        caller: &signer,
        remote_chain_selectors: vector<u64>,
        remote_domain_identifiers: vector<u32>,
        allowed_remote_callers: vector<vector<u8>>,
        enableds: vector<bool>
    ) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::assert_only_owner(signer::address_of(caller), &pool.ownable_state);

        let number_of_chains = remote_chain_selectors.length();

        assert!(
            number_of_chains == remote_domain_identifiers.length()
                && number_of_chains == allowed_remote_callers.length()
                && number_of_chains == enableds.length(),
            error::invalid_argument(E_INVALID_ARGUMENTS)
        );

        for (i in 0..number_of_chains) {
            let allowed_caller = allowed_remote_callers[i];
            let domain_identifier = remote_domain_identifiers[i];
            let remote_chain_selector = remote_chain_selectors[i];
            let enabled = enableds[i];

            assert!(
                remote_chain_selector != 0,
                error::invalid_argument(E_ZERO_CHAIN_SELECTOR)
            );

            address::assert_non_zero_address_vector(&allowed_caller);

            pool.chain_to_domain.upsert(
                remote_chain_selector,
                Domain { allowed_caller, domain_identifier, enabled }
            );

            event::emit_event(
                &mut pool.domain_set_events,
                DomainsSet {
                    allowed_caller,
                    domain_identifier,
                    remote_chain_selector,
                    enabled
                }
            );
        };
    }

    // ================================================================
    // |                    Rate limit config                         |
    // ================================================================
    public entry fun set_chain_rate_limiter_configs(
        caller: &signer,
        remote_chain_selectors: vector<u64>,
        outbound_is_enableds: vector<bool>,
        outbound_capacities: vector<u64>,
        outbound_rates: vector<u64>,
        inbound_is_enableds: vector<bool>,
        inbound_capacities: vector<u64>,
        inbound_rates: vector<u64>
    ) acquires USDCTokenPoolState {
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

    public entry fun set_chain_rate_limiter_config(
        caller: &signer,
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    ) acquires USDCTokenPoolState {
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

    #[view]
    public fun get_current_inbound_rate_limiter_state(
        remote_chain_selector: u64
    ): rate_limiter::TokenBucket acquires USDCTokenPoolState {
        token_pool::get_current_inbound_rate_limiter_state(
            &borrow_pool().token_pool_state, remote_chain_selector
        )
    }

    #[view]
    public fun get_current_outbound_rate_limiter_state(
        remote_chain_selector: u64
    ): rate_limiter::TokenBucket acquires USDCTokenPoolState {
        token_pool::get_current_outbound_rate_limiter_state(
            &borrow_pool().token_pool_state, remote_chain_selector
        )
    }

    // ================================================================
    // |                      Storage helpers                         |
    // ================================================================
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

    inline fun borrow_pool(): &USDCTokenPoolState {
        borrow_global<USDCTokenPoolState>(store_address())
    }

    inline fun borrow_pool_mut(): &mut USDCTokenPoolState {
        borrow_global_mut<USDCTokenPoolState>(store_address())
    }

    // ================================================================
    // |                       Expose ownable                         |
    // ================================================================
    #[view]
    public fun owner(): address acquires USDCTokenPoolState {
        ownable::owner(&borrow_pool().ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires USDCTokenPoolState {
        ownable::has_pending_transfer(&borrow_pool().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires USDCTokenPoolState {
        ownable::pending_transfer_from(&borrow_pool().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires USDCTokenPoolState {
        ownable::pending_transfer_to(&borrow_pool().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires USDCTokenPoolState {
        ownable::pending_transfer_accepted(&borrow_pool().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::transfer_ownership(caller, &mut pool.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::accept_ownership(caller, &mut pool.ownable_state)
    }

    public entry fun execute_ownership_transfer(
        caller: &signer, to: address
    ) acquires USDCTokenPoolState {
        let pool = borrow_pool_mut();
        ownable::execute_ownership_transfer(caller, &mut pool.ownable_state, to)
    }

    public fun domain_allowed_caller(domain: &Domain): vector<u8> {
        domain.allowed_caller
    }

    public fun domain_domain_identifier(domain: &Domain): u32 {
        domain.domain_identifier
    }

    public fun domain_enabled(domain: &Domain): bool {
        domain.enabled
    }

    // ================================================================
    // |                      MCMS entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires USDCTokenPoolDeployment, USDCTokenPoolState {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@usdc_token_pool, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            bcs_stream::assert_is_consumed(&stream);
            initialize(&caller);
        } else if (function_bytes == b"add_remote_pool") {
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
        } else if (function_bytes == b"set_allowlist_enabled") {
            let enabled = bcs_stream::deserialize_bool(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_allowlist_enabled(&caller, enabled);
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
        } else if (function_bytes == b"set_domains") {
            let remote_chain_selectors =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let remote_domain_identifiers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u32(stream)
                );
            let allowed_remote_callers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            let enableds =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            set_domains(
                &caller,
                remote_chain_selectors,
                remote_domain_identifiers,
                allowed_remote_callers,
                enableds
            );
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
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            execute_ownership_transfer(&caller, to)
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(
        publisher: &signer, module_name: vector<u8>
    ) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(module_name), McmsCallback {}
        );
    }

    // ============== Test functions ==============
    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    /// Used for registering the pool with V2 closure-based callbacks.
    public fun create_callback_proof(): CallbackProof {
        CallbackProof {}
    }
}
