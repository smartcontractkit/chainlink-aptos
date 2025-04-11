module usdc_token_pool::usdc_token_pool {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::from_bcs;
    use std::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use std::string::{Self, String};

    use ccip::eth_abi;
    use ccip::ownable;
    use ccip::token_admin_registry;
    use ccip_token_pool::token_pool;

    use message_transmitter::message;
    use message_transmitter::message_transmitter;
    use token_messenger_minter::token_messenger;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipUSDCTokenPool";

    struct USDCTokenPoolDeployment has key {
        store_signer_cap: SignerCapability,
        ownable_state: ownable::OwnableState,
        token_pool_state: token_pool::TokenPoolState,
        domain_set_events: EventHandle<DomainsSet>
    }

    struct USDCTokenPool has key, store {
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
    struct Domain has key, store, drop {
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
                ),
                domain_set_events: account::new_event_handle(publisher),
            }
        );
    }

    public fun initialize(caller: &signer, local_token: address) acquires USDCTokenPoolDeployment {
        assert_can_initialize(signer::address_of(caller));

        assert!(
            exists<USDCTokenPoolDeployment>(@usdc_token_pool),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        assert!(
            @local_token == local_token,
            error::invalid_argument(E_LOCAL_TOKEN_MISMATCH)
        );

        let USDCTokenPoolDeployment { store_signer_cap, ownable_state, token_pool_state, domain_set_events } =
            move_from<USDCTokenPoolDeployment>(@usdc_token_pool);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        let pool = USDCTokenPool {
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
        _store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
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
            token_admin_registry::get_lock_or_burn_receiver(&input);
        let mint_recipient = from_bcs::to_address(mint_recipient_bytes);
        let nonce =
            token_messenger::deposit_for_burn_with_caller(
                &store_signer,
                fa,
                remote_domain_info.domain_identifier,
                mint_recipient,
                from_bcs::to_address(remote_domain_info.allowed_caller),
            );

        let dest_pool_data = encode_dest_pool_data(pool.local_domain_identifier, nonce);

        // set the output for this lock or burn operation.
        token_admin_registry::set_lock_or_burn_output_v1(
            @usdc_token_pool,
            CallbackProof {},
            dest_token_address,
            dest_pool_data
        );

        token_pool::emit_locked_or_burned(&mut pool.token_pool_state, fa_amount);
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

        token_pool::emit_released_or_minted(
            &mut pool.token_pool_state,
            recipient,
            local_amount
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
        // This manually packs the values into a single slot, which mirrors EVM struct packing.
        let abi_encoded_data = ((nonce as u256) << 32) + (local_domain_identifier as u256);
        let dest_pool_data = vector[];
        eth_abi::encode_u256(&mut dest_pool_data, abi_encoded_data);
        dest_pool_data
    }

    inline fun decode_dest_pool_data(dest_pool_data: vector<u8>): (u32, u64) {
        let stream = eth_abi::new_stream(dest_pool_data);
        let abi_encoded_data = eth_abi::decode_u256(&mut stream);

        let local_domain_identifier = abi_encoded_data as u32;
        let nonce = (abi_encoded_data >> 32) as u64;

        (local_domain_identifier, nonce)
    }

    inline fun validate_message(
        usdc_message: &vector<u8>,
        expected_source_domain: u32,
        expected_nonce: u64,
        expected_local_domain: u32
    ) {
        message::validate_message(usdc_message);
        let source_domain = message::get_src_domain_id(usdc_message);
        let nonce = message::get_nonce(usdc_message);
        let destination_domain = message::get_destination_domain_id(usdc_message);

        assert!(
            source_domain == expected_source_domain,
            error::invalid_argument(E_INVALID_ARGUMENTS)
        );

        assert!(
            nonce == expected_nonce,
            error::invalid_argument(E_INVALID_ARGUMENTS)
        );

        assert!(
            destination_domain == expected_local_domain,
            error::invalid_argument(E_INVALID_ARGUMENTS)
        );
    }

    // ================================================================
    // |                      USDC Domains                            |
    // ================================================================

    public fun set_domains(
        caller: &signer,
        remote_chain_selectors: vector<u64>,
        remote_domain_identifiers: vector<u32>,
        allowed_remote_callers: vector<vector<u8>>,
        enableds: vector<bool>
    ) acquires USDCTokenPool {
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
                error::invalid_argument(E_DOMAIN_ENABLED)
            );

            assert!(
                allowed_caller.length() != 0,
                error::invalid_argument(E_DOMAIN_NOT_FOUND)
            );

            pool.chain_to_domain.upsert(
                remote_chain_selector,
                Domain {
                    allowed_caller,
                    domain_identifier,
                    enabled
                }
            );

            event::emit(DomainsSet { allowed_caller, domain_identifier, remote_chain_selector, enabled });
            event::emit_event(
                &mut pool.domain_set_events,
                DomainsSet { allowed_caller, domain_identifier, remote_chain_selector, enabled }
            );
        };
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
