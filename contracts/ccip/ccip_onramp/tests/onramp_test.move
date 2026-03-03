#[test_only]
module ccip_onramp::onramp_test {
    use std::signer;
    use std::string::{Self};
    use std::option;
    use std::vector;
    use std::object::{Self, Object, ExtendRef, ObjectCore};
    use std::bcs;
    use std::account;
    use std::fungible_asset::{Self, Metadata, MintRef, BurnRef, TransferRef};
    use std::primary_fungible_store;
    use std::timestamp;

    use ccip::token_admin_registry;
    use ccip::rmn_remote;
    use ccip::nonce_manager;
    use ccip::eth_abi;
    use ccip_onramp::onramp;
    use ccip::auth::{Self};
    use ccip::state_object::{Self};
    use ccip::fee_quoter::{Self};

    use burn_mint_token_pool::burn_mint_token_pool;
    use lock_release_token_pool::lock_release_token_pool;

    use mcms::mcms_registry;
    use mcms::mcms_account;

    const SOURCE_CHAIN_SELECTOR: u64 = 1;
    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const CHAIN_FAMILY_SELECTOR_EVM: vector<u8> = x"2812d52c";
    const CHAIN_FAMILY_SELECTOR_SVM: vector<u8> = x"1e10bdc4";
    const CHAIN_FAMILY_SELECTOR_APTOS: vector<u8> = x"ac77ffec";
    const TOKEN_AMOUNT: u64 = 5000;

    const OUTBOUND_CAPACITY: u64 = 1000000000000000000;
    const OUTBOUND_RATE: u64 = 1000000000000000000;
    const INBOUND_CAPACITY: u64 = 1000000000000000000;
    const INBOUND_RATE: u64 = 1000000000000000000;

    const OWNER: address = @0x100;
    const ROUTER: address = @0x200;
    const FEE_AGGREGATOR: address = @0x300;
    const ALLOWLIST_ADMIN: address = @0x400;
    const SENDER: address = @0x500;

    /// POOL TYPES
    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;

    const MOCK_EVM_ADDRESS: address = @0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97;
    const MOCK_EVM_ADDRESS_VECTOR: vector<u8> = x"4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97";

    const TOKEN_POOL_MODULE_NAME: vector<u8> = b"test_token_pool";

    // Extra args constants
    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";
    const GAS_LIMIT: u64 = 5000000;
    const ALLOW_OUT_OF_ORDER_EXECUTION: bool = true;

    struct TestToken has key, store {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    public fun mint_test_tokens(
        token_addr: address, recipient: address, amount: u64
    ) acquires TestToken {
        let token = borrow_global<TestToken>(token_addr);
        let recipient_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient, token.metadata
            );
        fungible_asset::mint_to(&token.mint_ref, recipient_store, amount);
    }

    fun init_timestamp(aptos_framework: &signer, timestamp_seconds: u64) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp_seconds);
    }

    public fun setup(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        pool_type: u8, // 0 for burn_mint, 1 for lock_release
        seed: vector<u8>,
        is_dispatchable: bool,
        use_v1_init: bool
    ): (address, Object<Metadata>) {
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(signer::address_of(burn_mint_token_pool));
        account::create_account_for_test(signer::address_of(lock_release_token_pool));
        init_timestamp(aptos_framework, 100000);

        // Create object for @ccip_onramp
        let _constructor_ref = object::create_named_object(owner, b"ccip_onramp");

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        // Create object for @burn_mint_token_pool
        let constructor_ref = object::create_named_object(
            owner, b"burn_mint_token_pool"
        );
        let burn_mint_token_pool_obj_signer = &object::generate_signer(&constructor_ref);

        // Create object for @lock_release_token_pool
        let constructor_ref =
            object::create_named_object(owner, b"lock_release_token_pool");
        let lock_release_token_pool_obj_signer =
            &object::generate_signer(&constructor_ref);

        // Create object for @ccip_token_pool
        let constructor_ref =
            object::create_named_object(
                burn_mint_token_pool_obj_signer, b"ccip_token_pool"
            );
        let ccip_token_pool_obj =
            object::object_from_constructor_ref<ObjectCore>(&constructor_ref);
        // We need to transfer ownership of ccip_token_pool to lock_release_token_pool
        if (pool_type == LOCK_RELEASE_TOKEN_POOL) {
            // transfer ownership of ccip_token_pool to lock_release_token_pool
            object::transfer(
                burn_mint_token_pool_obj_signer,
                ccip_token_pool_obj,
                signer::address_of(lock_release_token_pool_obj_signer)
            );
        };

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        rmn_remote::initialize(owner, SOURCE_CHAIN_SELECTOR);

        token_admin_registry::init_module_for_testing(ccip);
        onramp::test_init_module(ccip_onramp);
        nonce_manager::test_init_module(ccip_onramp);

        let (token_obj, token_addr) =
            create_test_token_and_pool(
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                pool_type,
                seed,
                is_dispatchable,
                use_v1_init
            );

        let one_e_18 = 1_000_000_000_000_000_000;

        fee_quoter::initialize(
            owner,
            200 * one_e_18, // 200 link
            token_addr,
            12400,
            vector[token_addr]
        );

        initialize_onramp(owner, router);
        assert!(onramp::owner() == owner_addr);

        fee_quoter::apply_fee_token_updates(owner, vector[], vector[token_addr]);
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            DEST_CHAIN_SELECTOR, // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            30_000, // max_data_bytes
            30_000_000, // max_per_msg_gas_limit
            250_000, // dest_gas_overhead
            16, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            CHAIN_FAMILY_SELECTOR_EVM, // chain_family_selector
            false, // enforce_out_of_order
            50, // default_token_fee_usd_cents
            90_000, // default_token_dest_gas_overhead
            200_000, // default_tx_gas_limit
            one_e_18 as u64, // gas_multiplier_wei_per_eth
            1_000_000, // gas_price_staleness_threshold
            50 // network_fee_usd_cents
        );
        fee_quoter::apply_premium_multiplier_wei_per_eth_updates(
            owner,
            vector[token_addr], // tokens
            // 900_000_000_000_000_000 = 90%
            vector[900_000_000_000_000_000] // premium_multiplier_wei_per_eth
        );

        // Configure token transfer fees (needed for token transfers)
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            DEST_CHAIN_SELECTOR,
            vector[token_addr],
            vector[50], // min_fee_usd_cents
            vector[500], // max_fee_usd_cents
            vector[10], // deci_bps
            vector[5000], // dest_gas_overhead
            vector[64], // dest_bytes_overhead
            vector[true], // is_enabled
            vector[]
        );

        // To be able to call token_admin_dispatcher::dispatch_lock_or_burn
        // Need to register onramp state address as an allowed onramp
        auth::apply_allowed_onramp_updates(
            owner,
            vector[], // onramps_to_remove
            vector[onramp::get_state_address()] // onramps_to_add
        );

        // To be able to call fee_quoter::update_prices, need to register as an allowed offramp
        auth::apply_allowed_offramp_updates(
            owner,
            vector[], // offramps_to_remove
            vector[owner_addr] // offramps_to_add
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            // 1e18 per 1e18 tokens. A token with 8 decimals that's worth $15 would be $15e10 * 1e18 = $15e28
            vector[150_000_000_000 * one_e_18], // source_usd_per_token
            vector[DEST_CHAIN_SELECTOR], // gas_dest_chain_selectors
            vector[1_000_000_000_000] // gas_usd_per_unit_gas
        );

        (owner_addr, token_obj)
    }

    public fun create_test_token_and_pool(
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        pool_type: u8, // 0 for burn_mint, 1 for lock_release
        seed: vector<u8>,
        is_dispatchable: bool,
        use_v1_init: bool
    ): (Object<Metadata>, address) {
        let constructor_ref = object::create_named_object(owner, seed);

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(), // maximum supply
            string::utf8(seed), // name
            string::utf8(seed), // symbol
            0, // decimals
            string::utf8(b"http://www.example.com/favicon.ico"), // icon uri
            string::utf8(b"http://www.example.com") // project uri
        );

        let metadata = object::object_from_constructor_ref(&constructor_ref);

        let obj_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref =
            if (is_dispatchable) {
                option::some(fungible_asset::generate_transfer_ref(&constructor_ref))
            } else {
                option::none()
            };

        // ======================== Create token pool ========================
        let token_addr = object::object_address(&metadata);

        let remote_token_address = vector[];
        eth_abi::encode_address(&mut remote_token_address, MOCK_EVM_ADDRESS);

        if (pool_type == BURN_MINT_TOKEN_POOL) {
            if (use_v1_init) {
                burn_mint_token_pool::test_init_v1(burn_mint_token_pool);
            } else {
                burn_mint_token_pool::test_init_module(burn_mint_token_pool);
            };
            burn_mint_token_pool::initialize(owner, burn_ref, mint_ref);
            burn_mint_token_pool::apply_chain_updates(
                owner,
                vector[],
                vector[DEST_CHAIN_SELECTOR],
                vector[vector[remote_token_address]],
                vector[remote_token_address]
            );
            burn_mint_token_pool::set_chain_rate_limiter_config(
                owner,
                DEST_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY, // outbound_capacity
                OUTBOUND_RATE, // outbound_rate
                true,
                INBOUND_CAPACITY, // inbound_capacity
                INBOUND_RATE // inbound_rate
            );
            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(burn_mint_token_pool)
            );
        } else {
            if (use_v1_init) {
                lock_release_token_pool::test_init_v1(lock_release_token_pool);
            } else {
                lock_release_token_pool::test_init_module(lock_release_token_pool);
            };
            lock_release_token_pool::initialize(
                owner, transfer_ref, signer::address_of(owner)
            );
            lock_release_token_pool::apply_chain_updates(
                owner,
                vector[],
                vector[DEST_CHAIN_SELECTOR],
                vector[vector[remote_token_address]],
                vector[remote_token_address]
            );
            lock_release_token_pool::set_chain_rate_limiter_config(
                owner,
                DEST_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY, // outbound_capacity
                OUTBOUND_RATE, // outbound_rate
                true,
                INBOUND_CAPACITY, // inbound_capacity
                INBOUND_RATE // inbound_rate
            );
            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(lock_release_token_pool)
            );
        };

        // Add a delay to allow the token bucket to refill
        timestamp::update_global_time_for_test_secs(timestamp::now_seconds() + 10);

        // =========== Create token refs ==================

        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);
        move_to(
            &obj_signer,
            TestToken {
                metadata,
                extend_ref,
                mint_ref,
                burn_ref,
                transfer_ref
            }
        );

        (metadata, token_addr)
    }

    public fun initialize_onramp(owner: &signer, router: &signer): address {
        onramp::initialize(
            owner,
            SOURCE_CHAIN_SELECTOR,
            FEE_AGGREGATOR,
            ALLOWLIST_ADMIN,
            vector[DEST_CHAIN_SELECTOR], // dest_chain_selectors
            vector[ROUTER], // dest_chain_routers
            vector[false] // dest_chain_allowlist_enabled
        );

        // apply_dest_chain_config_updates_v2 with router state addresses
        let router_state_address = signer::address_of(router);
        onramp::apply_dest_chain_config_updates_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[ROUTER],
            vector[router_state_address],
            vector[false]
        );

        onramp::get_state_address()
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_initialize(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        let static_config = onramp::get_static_config();
        assert!(
            onramp::static_config_chain_selector(&static_config)
                == SOURCE_CHAIN_SELECTOR
        );

        let dynamic_config = onramp::get_dynamic_config();
        assert!(
            onramp::dynamic_config_fee_aggregator(&dynamic_config) == FEE_AGGREGATOR
        );
        assert!(
            onramp::dynamic_config_allowlist_admin(&dynamic_config) == ALLOWLIST_ADMIN
        );

        let (sequence_number, allowlist_enabled, router_addr) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 0);
        assert!(allowlist_enabled == false);
        assert!(router_addr == ROUTER);

        assert!(onramp::owner() == signer::address_of(owner));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_set_dynamic_config(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        // Update dynamic config
        let new_fee_aggregator = @0x300;
        let new_allowlist_admin = @0x400;

        onramp::set_dynamic_config(owner, new_fee_aggregator, new_allowlist_admin);

        // Verify updated config
        let dynamic_config = onramp::get_dynamic_config();
        assert!(
            onramp::dynamic_config_fee_aggregator(&dynamic_config)
                == new_fee_aggregator
        );
        assert!(
            onramp::dynamic_config_allowlist_admin(&dynamic_config)
                == new_allowlist_admin
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    // ownable error code for unauthorized
    fun test_set_dynamic_config_unauthorized(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        // Try to update dynamic config with unauthorized account
        onramp::set_dynamic_config(sender, FEE_AGGREGATOR, ALLOWLIST_ADMIN);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_apply_dest_chain_config_updates(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        let dest_chain_selectors = vector[DEST_CHAIN_SELECTOR];
        let dest_chain_routers = vector[ROUTER];
        let dest_chain_allowlist_enabled = vector[true];

        // Verify existing destination chain config is unchanged
        let (sequence_number, allowlist_enabled, router_addr) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 0);
        assert!(allowlist_enabled == false);
        assert!(router_addr == ROUTER);

        onramp::apply_dest_chain_config_updates(
            owner,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        // Verify new destination chain config
        let (sequence_number, allowlist_enabled, router_addr) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 0);
        assert!(allowlist_enabled == true);
        assert!(router_addr == ROUTER);

        // Update existing destination chain
        let new_dest_chain_selector = DEST_CHAIN_SELECTOR + 1;
        let new_router = @0x300;
        let dest_chain_selectors = vector[new_dest_chain_selector];
        let dest_chain_routers = vector[new_router];
        let dest_chain_allowlist_enabled = vector[true];

        onramp::apply_dest_chain_config_updates(
            owner,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        // Verify updated config
        let (sequence_number, allowlist_enabled, router_addr) =
            onramp::get_dest_chain_config(new_dest_chain_selector);
        assert!(sequence_number == 0);
        assert!(allowlist_enabled == true);
        assert!(router_addr == new_router);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_apply_allowlist_updates(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        // First enable allowlist for destination chain
        let dest_chain_selectors = vector[DEST_CHAIN_SELECTOR];
        let dest_chain_routers = vector[ROUTER];
        let dest_chain_allowlist_enabled = vector[true];

        onramp::apply_dest_chain_config_updates(
            owner,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        // Add sender to allowlist
        let dest_chain_selectors = vector[DEST_CHAIN_SELECTOR];
        let dest_chain_allowlist_enabled = vector[true];
        let add_senders = vector[vector[SENDER]];
        let remove_senders = vector[vector[]];

        onramp::apply_allowlist_updates(
            owner,
            dest_chain_selectors,
            dest_chain_allowlist_enabled,
            add_senders,
            remove_senders
        );

        // Verify sender is in allowlist
        let (is_enabled, allowed_senders) =
            onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(is_enabled == true);
        assert!(allowed_senders.length() == 1);
        assert!(allowed_senders[0] == SENDER);

        // Remove sender from allowlist
        let remove_senders = vector[vector[SENDER]];
        let add_senders = vector[vector[]];

        onramp::apply_allowlist_updates(
            owner,
            dest_chain_selectors,
            dest_chain_allowlist_enabled,
            add_senders,
            remove_senders
        );

        // Verify sender is removed from allowlist
        let (is_enabled, allowed_senders) =
            onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(is_enabled == true);
        assert!(allowed_senders.length() == 0);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_ccip_send_burn_mint_token_pool(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let (_owner_addr, token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );

        auth::apply_allowed_onramp_updates(
            owner,
            vector[], // onramps_to_remove
            vector[onramp::get_state_address()] // onramps_to_add
        );

        let token_addr = object::object_address(&token_obj);
        let token = borrow_global<TestToken>(token_addr);
        let sent_amount = TOKEN_AMOUNT;

        let sender_store =
            primary_fungible_store::ensure_primary_store_exists(
                signer::address_of(sender), token.metadata
            );

        // Mint tokens to sender store first
        fungible_asset::mint_to(&token.mint_ref, sender_store, sent_amount);

        let receiver = vector[];
        eth_abi::encode_address(&mut receiver, MOCK_EVM_ADDRESS);
        let data = b"hello world";
        let token_addresses = vector[token_addr];
        let token_amounts = vector[TOKEN_AMOUNT];
        let token_store_addresses = vector[@0x0]; // Use primary store
        let fee_token = token_addr; // Using same token for fee
        let fee_token_store = @0x0; // Use primary store
        let extra_args = create_valid_extra_args();

        let fee_token_amount =
            onramp::get_fee(
                DEST_CHAIN_SELECTOR,
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );

        fungible_asset::mint_to(&token.mint_ref, sender_store, fee_token_amount);

        let message_id =
            onramp::ccip_send(
                router,
                sender,
                DEST_CHAIN_SELECTOR,
                receiver,
                data,
                token_addresses,
                token_amounts, // Send this amount to destination chain
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );

        assert!(message_id.length() > 0);

        // Verify sequence number was incremented
        let (sequence_number, _, _) = onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 1);

        // Verify tokens were transferred
        let sender_balance = fungible_asset::balance(sender_store);
        assert!(sender_balance == 0); // All tokens sent

        // Verify fee token was transferred
        let onramp_state_balance =
            primary_fungible_store::balance(onramp::get_state_address(), token.metadata);
        assert!(onramp_state_balance == fee_token_amount);

        assert!(
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            ).length() == 1
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_ccip_send_lock_release_token_pool(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let (_owner_addr, token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                b"LockReleaseToken",
                false,
                false
            );

        auth::apply_allowed_onramp_updates(
            owner,
            vector[], // onramps_to_remove
            vector[onramp::get_state_address()] // onramps_to_add
        );

        let token_addr = object::object_address(&token_obj);
        let token = borrow_global<TestToken>(token_addr);
        let sent_amount = TOKEN_AMOUNT;

        let sender_store =
            primary_fungible_store::ensure_primary_store_exists(
                signer::address_of(sender), token.metadata
            );

        // Mint tokens to sender store first
        fungible_asset::mint_to(&token.mint_ref, sender_store, sent_amount);

        let receiver = vector[];
        eth_abi::encode_address(&mut receiver, MOCK_EVM_ADDRESS);
        let data = b"hello world";
        let token_addresses = vector[token_addr];
        let token_amounts = vector[TOKEN_AMOUNT];
        let token_store_addresses = vector[@0x0]; // Use primary store
        let fee_token = token_addr; // Using same token for fee
        let fee_token_store = @0x0; // Use primary store
        let extra_args = create_valid_extra_args();

        let fee_token_amount =
            onramp::get_fee(
                DEST_CHAIN_SELECTOR,
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );

        fungible_asset::mint_to(&token.mint_ref, sender_store, fee_token_amount);

        let message_id =
            onramp::ccip_send(
                router,
                sender,
                DEST_CHAIN_SELECTOR,
                receiver,
                data,
                token_addresses,
                token_amounts,
                token_store_addresses,
                fee_token,
                fee_token_store,
                extra_args
            );

        assert!(message_id.length() > 0);

        // Verify sequence number was incremented
        let (sequence_number, _, _) = onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 1);

        // Verify tokens were transferred
        let sender_balance = fungible_asset::balance(sender_store);
        assert!(sender_balance == 0); // All tokens sent

        // Verify fee token was transferred
        let onramp_state_balance =
            primary_fungible_store::balance(onramp::get_state_address(), token.metadata);
        assert!(onramp_state_balance == fee_token_amount);

        // Check token pool balance to see if tokens are locked
        let token_pool_addr = lock_release_token_pool::get_store_address();
        let token_pool_balance =
            primary_fungible_store::balance(token_pool_addr, token.metadata);
        assert!(token_pool_balance == sent_amount);

        assert!(
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            ).length() == 1
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        ),
        expected_failure(abort_code = 196609, location = ccip_onramp::onramp) // E_ALREADY_INITIALIZED
    ]
    fun test_initialize_twice_fails(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );
        initialize_onramp(owner, router);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        ),
        expected_failure(
            abort_code = ccip::address::E_ZERO_ADDRESS_NOT_ALLOWED, location = ccip::address
        )
    ]
    fun test_set_dynamic_config_failure_when_fee_aggregator_is_zero_address(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_, _) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );

        // Set fee_aggregator to 0, this should revert with E_ZERO_ADDRESS_NOT_ALLOWED
        onramp::set_dynamic_config(owner, @0x0, ALLOWLIST_ADMIN);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_is_chain_supported(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));

        let unsupported_chain_selector = 999999;
        assert!(!onramp::is_chain_supported(unsupported_chain_selector));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_get_expected_next_sequence_number(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        // After initialization, sequence number should be 0, so next expected is 1
        let expected_next_sequence =
            onramp::get_expected_next_sequence_number(DEST_CHAIN_SELECTOR);
        assert!(expected_next_sequence == 1);

        // Create a new destination chain config with a higher sequence number
        let new_chain_selector = DEST_CHAIN_SELECTOR + 1;
        let new_router = @0x300;
        let dest_chain_selectors = vector[new_chain_selector];
        let dest_chain_routers = vector[new_router];
        let dest_chain_allowlist_enabled = vector[false];

        onramp::apply_dest_chain_config_updates(
            owner,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        // Verify sequence number is 0 for the new chain, so next expected is 1
        let expected_next_sequence =
            onramp::get_expected_next_sequence_number(new_chain_selector);
        assert!(expected_next_sequence == 1);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_ownership_transfer(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        assert!(onramp::owner() == signer::address_of(owner));

        let new_owner_addr = signer::address_of(sender);
        onramp::transfer_ownership(owner, new_owner_addr);
        // Ownership is still with original owner until accepted
        assert!(onramp::owner() == signer::address_of(owner));

        onramp::accept_ownership(sender);
        assert!(onramp::owner() == signer::address_of(owner));

        onramp::execute_ownership_transfer(owner, new_owner_addr);
        assert!(onramp::owner() == new_owner_addr);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_get_outbound_nonce(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        let nonce =
            onramp::get_outbound_nonce(DEST_CHAIN_SELECTOR, signer::address_of(sender));
        assert!(nonce == 0);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_withdraw_fee_tokens_success_burn_mint_token_pool(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let (_, token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );

        let token_addr = object::object_address(&token_obj);
        let token = borrow_global<TestToken>(token_addr);

        let state_addr = onramp::get_state_address();

        let state_store =
            primary_fungible_store::ensure_primary_store_exists(
                state_addr, token.metadata
            );

        // Mint some tokens to the onramp state (simulating fees collected)
        let fee_amount = 1000;
        fungible_asset::mint_to(&token.mint_ref, state_store, fee_amount);

        let balance_before = primary_fungible_store::balance(state_addr, token.metadata);
        assert!(balance_before == fee_amount);

        let fee_aggregator_balance_before =
            primary_fungible_store::balance(FEE_AGGREGATOR, token.metadata);
        assert!(fee_aggregator_balance_before == 0);

        let fee_tokens = vector[token_addr];
        onramp::withdraw_fee_tokens(fee_tokens);

        let balance_after = primary_fungible_store::balance(state_addr, token.metadata);
        assert!(balance_after == 0);

        let fee_aggregator_balance_after =
            primary_fungible_store::balance(FEE_AGGREGATOR, token.metadata);
        assert!(fee_aggregator_balance_after == fee_amount);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        ),
        expected_failure(abort_code = 65544, location = ccip_onramp::onramp) // E_INVALID_ALLOWLIST_REQUEST with correct code
    ]
    fun test_apply_allowlist_updates_error_add_sender_when_disabled(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        let dest_chain_selectors = vector[DEST_CHAIN_SELECTOR];
        let dest_chain_routers = vector[ROUTER];
        let dest_chain_allowlist_enabled = vector[false]; // Disabled!

        onramp::apply_dest_chain_config_updates(
            owner,
            dest_chain_selectors,
            dest_chain_routers,
            dest_chain_allowlist_enabled
        );

        // This should fail because allowlist is disabled but we're trying to add a sender
        onramp::apply_allowlist_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR], // dest_chain_selectors
            vector[false], // dest_chain_allowlist_enabled
            vector[vector[SENDER]], // add_senders
            vector[vector[]] // remove_senders
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            unauthorized = @0x600,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        ),
        expected_failure(abort_code = 327687, location = ccip_onramp::onramp) // E_ONLY_CALLABLE_BY_OWNER_OR_ALLOWLIST_ADMIN
    ]
    fun test_apply_allowlist_updates_unauthorized(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        unauthorized: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        setup(
            aptos_framework,
            router,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false,
            false
        );

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR], // dest_chain_selectors
            vector[ROUTER], // dest_chain_routers
            vector[true] // dest_chain_allowlist_enabled
        );

        // This should fail because the caller is neither owner nor allowlist admin
        onramp::apply_allowlist_updates(
            unauthorized, // unauthorized user
            vector[DEST_CHAIN_SELECTOR], // dest_chain_selectors
            vector[true], // dest_chain_allowlist_enabled
            vector[vector[SENDER]], // add_senders
            vector[vector[]] // remove_senders
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_all_getter_functions(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_owner_addr, _token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );

        let type_version = onramp::type_and_version();
        assert!(std::string::utf8(b"OnRamp 1.6.0") == type_version);

        let state_address = onramp::get_state_address();
        assert!(state_address != @0x0);

        let static_config = onramp::get_static_config();
        assert!(
            onramp::static_config_chain_selector(&static_config)
                == SOURCE_CHAIN_SELECTOR
        );

        let dynamic_config = onramp::get_dynamic_config();
        assert!(
            onramp::dynamic_config_fee_aggregator(&dynamic_config) == FEE_AGGREGATOR
        );
        assert!(
            onramp::dynamic_config_allowlist_admin(&dynamic_config) == ALLOWLIST_ADMIN
        );

        let (sequence_number, allowlist_enabled, dest_router) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 0);
        assert!(allowlist_enabled == false);
        assert!(dest_router == ROUTER);

        let (is_enabled, allowed_senders) =
            onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(is_enabled == false);
        assert!(allowed_senders.length() == 0);

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(!onramp::is_chain_supported(999999));

        let expected_next_sequence =
            onramp::get_expected_next_sequence_number(DEST_CHAIN_SELECTOR);
        assert!(expected_next_sequence == 1);

        assert!(onramp::owner() == signer::address_of(owner));
    }

    // ================================ MCMS tests ================================ //
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            mcms = @mcms,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_mcms_entrypoint_dispatch_functionality(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        mcms: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_owner, _token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );
        setup_mcms(mcms);
        onramp::test_register_mcms_entrypoint(ccip_onramp);
        transfer_onramp_ownership(owner, ccip_onramp);

        let new_fee_aggregator = @0x789;
        let new_allowlist_admin = @0x987;

        let data = vector[];
        vector::append(&mut data, std::bcs::to_bytes(&new_fee_aggregator));
        vector::append(&mut data, std::bcs::to_bytes(&new_allowlist_admin));

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip_onramp,
                string::utf8(b"onramp"),
                string::utf8(b"set_dynamic_config"),
                data
            );

        onramp::mcms_entrypoint(metadata);

        mcms_registry::test_finish_dispatch(@ccip_onramp);

        // Verify the dynamic config was updated
        let dynamic_config = onramp::get_dynamic_config();
        let fee_aggregator = onramp::dynamic_config_fee_aggregator(&dynamic_config);
        let allowlist_admin = onramp::dynamic_config_allowlist_admin(&dynamic_config);

        assert!(fee_aggregator == new_fee_aggregator);
        assert!(allowlist_admin == new_allowlist_admin);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            mcms = @mcms,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_mcms_entrypoint_apply_dest_chain_config(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        mcms: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_owner, _token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );
        setup_mcms(mcms);
        onramp::test_register_mcms_entrypoint(ccip_onramp);
        transfer_onramp_ownership(owner, ccip_onramp);

        let new_dest_chain_selector = DEST_CHAIN_SELECTOR + 999;
        let new_router = @0x999;
        let dest_chain_selectors = vector[new_dest_chain_selector];
        let dest_chain_routers = vector[new_router];
        let dest_chain_allowlist_enabled = vector[true];

        let data = vector[];
        let selectors_data = bcs::to_bytes(&dest_chain_selectors);
        vector::append(&mut data, selectors_data);

        let routers_data = bcs::to_bytes(&dest_chain_routers);
        vector::append(&mut data, routers_data);

        let allowlist_data = bcs::to_bytes(&dest_chain_allowlist_enabled);
        vector::append(&mut data, allowlist_data);

        let function_name = string::utf8(b"apply_dest_chain_config_updates");
        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip_onramp,
                string::utf8(b"onramp"),
                function_name,
                data
            );
        onramp::mcms_entrypoint(metadata);

        mcms_registry::test_finish_dispatch(@ccip_onramp);

        assert!(onramp::is_chain_supported(new_dest_chain_selector));

        let (_, allowlist_enabled, router) =
            onramp::get_dest_chain_config(new_dest_chain_selector);
        assert!(allowlist_enabled == true);
        assert!(router == new_router);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            mcms = @mcms,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_mcms_entrypoint_apply_allowlist_updates(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        mcms: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_owner, _token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );
        setup_mcms(mcms);
        onramp::test_register_mcms_entrypoint(ccip_onramp);

        let new_dest_chain_selector = DEST_CHAIN_SELECTOR + 888;
        let new_router = @0x888;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[new_dest_chain_selector],
            vector[new_router],
            vector[true]
        );

        transfer_onramp_ownership(owner, ccip_onramp);

        let sender_to_add = @0x123;
        let dest_chain_selectors = vector[new_dest_chain_selector];
        let dest_chain_allowlist_enabled = vector[true];
        let dest_chain_add_allowed_senders = vector[vector[sender_to_add]];
        let dest_chain_remove_allowed_senders = vector[vector<address>[]];

        let data = vector[];
        vector::append(&mut data, bcs::to_bytes(&dest_chain_selectors));
        vector::append(&mut data, bcs::to_bytes(&dest_chain_allowlist_enabled));
        vector::append(&mut data, bcs::to_bytes(&dest_chain_add_allowed_senders));
        vector::append(&mut data, bcs::to_bytes(&dest_chain_remove_allowed_senders));

        let function_name = string::utf8(b"apply_allowlist_updates");
        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip_onramp,
                string::utf8(b"onramp"),
                function_name,
                data
            );

        onramp::mcms_entrypoint(metadata);

        mcms_registry::test_finish_dispatch(@ccip_onramp);

        // Verify the allowlist was updated
        let (is_enabled, allowed_senders) =
            onramp::get_allowed_senders_list(new_dest_chain_selector);
        assert!(is_enabled == true);
        assert!(allowed_senders.length() == 1);
        assert!(allowed_senders[0] == sender_to_add);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            mcms = @mcms,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        ),
        expected_failure(abort_code = 65541, location = ccip_onramp::onramp)
    ]
    fun test_mcms_entrypoint_unknown_function(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        mcms: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let (_, token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                false,
                false
            );
        setup_mcms(mcms);
        onramp::test_register_mcms_entrypoint(ccip_onramp);
        transfer_onramp_ownership(owner, ccip_onramp);

        mcms_registry::test_start_dispatch(
            @ccip_onramp,
            string::utf8(b"onramp"),
            string::utf8(b"unknown_function"),
            vector[]
        );

        // Aborts with E_UNKNOWN_FUNCTION
        onramp::mcms_entrypoint(token_obj);
    }

    // #[
    //     test(
    //         aptos_framework = @aptos_framework,
    //         ccip = @ccip,
    //         ccip_onramp = @ccip_onramp,
    //         owner = @0x100,
    //         mcms = @mcms
    //     )
    // ]
    // fun test_mcms_entrypoint_initialize(
    //     aptos_framework: &signer,
    //     ccip: &signer,
    //     ccip_onramp: &signer,
    //     owner: &signer,
    //     mcms: &signer
    // ) {
    //     // Create object for @ccip_onramp
    //     let constructor_ref = object::create_named_object(owner, b"ccip_onramp");
    //     let _obj_signer = &object::generate_signer(&constructor_ref);

    //     // Create object for @ccip
    //     let constructor_ref = object::create_named_object(owner, b"ccip");
    //     let _obj_signer = &object::generate_signer(&constructor_ref);

    //     state_object::init_module_for_testing(ccip);
    //     auth::test_init_module(owner);
    //     rmn_remote::initialize(owner, SOURCE_CHAIN_SELECTOR);

    //     token_admin_registry::init_module_for_testing(ccip_onramp);
    //     onramp::test_init_module(ccip_onramp);
    //     nonce_manager::test_init_module(ccip_onramp);

    //     let (token_obj, token_addr) =
    //         create_test_token_and_pool(owner, ccip, 0, b"TestToken");

    //     fee_quoter::initialize(
    //         owner,
    //         20000000000000,
    //         token_addr,
    //         12400,
    //         vector[token_addr]
    //     );

    //     setup_mcms(mcms);
    //     onramp::register_mcms_entrypoint(ccip_onramp);
    //     transfer_onramp_ownership(owner, ccip_onramp);

    //     let init_chain_selector = SOURCE_CHAIN_SELECTOR;
    //     let init_fee_aggregator = FEE_AGGREGATOR;
    //     let init_allowlist_admin = ALLOWLIST_ADMIN;
    //     let init_dest_chain_selectors = vector[DEST_CHAIN_SELECTOR];
    //     let init_dest_chain_routers = vector[ROUTER];
    //     let init_dest_chain_allowlist_enabled = vector[false];

    //     let data = vector[];
    //     vector::append(&mut data, bcs::to_bytes(&init_chain_selector));
    //     vector::append(&mut data, bcs::to_bytes(&init_fee_aggregator));
    //     vector::append(&mut data, bcs::to_bytes(&init_allowlist_admin));
    //     vector::append(&mut data, bcs::to_bytes(&init_dest_chain_selectors));
    //     vector::append(&mut data, bcs::to_bytes(&init_dest_chain_routers));
    //     vector::append(&mut data, bcs::to_bytes(&init_dest_chain_allowlist_enabled));

    //     let metadata =
    //         mcms_registry::test_start_dispatch(
    //             @ccip_onramp,
    //             string::utf8(b"onramp"),
    //             string::utf8(b"initialize"),
    //             data
    //         );

    //     onramp::mcms_entrypoint(metadata);

    //     mcms_registry::test_finish_dispatch(@ccip_onramp);

    //     // Verify the onramp was initialized correctly
    //     let static_config = onramp::get_static_config();
    //     assert!(
    //         onramp::static_config_chain_selector(&static_config)
    //             == SOURCE_CHAIN_SELECTOR,
    //     );

    //     let dynamic_config = onramp::get_dynamic_config();
    //     assert!(
    //         onramp::dynamic_config_fee_aggregator(&dynamic_config) == FEE_AGGREGATOR
    //     );
    //     assert!(
    //         onramp::dynamic_config_allowlist_admin(&dynamic_config) == ALLOWLIST_ADMIN
    //     );

    //     let (sequence_number, allowlist_enabled, router_addr) =
    //         onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
    //     assert!(sequence_number == 0);
    //     assert!(allowlist_enabled == false);
    //     assert!(router_addr == ROUTER);

    //     assert!(onramp::owner() == signer::address_of(owner));
    // }
    fun transfer_onramp_ownership(owner: &signer, ccip_onramp: &signer) {
        let preexisting_owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(
                signer::address_of(ccip_onramp)
            );
        onramp::transfer_ownership(owner, preexisting_owner_address);

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip_onramp,
                string::utf8(b"onramp"),
                string::utf8(b"accept_ownership"),
                vector[]
            );

        onramp::mcms_entrypoint(metadata);

        mcms_registry::test_finish_dispatch(@ccip_onramp);

        onramp::execute_ownership_transfer(owner, preexisting_owner_address);
    }

    fun setup_mcms(mcms: &signer) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);
    }

    fun create_valid_extra_args(): vector<u8> {
        let extra_args = vector[];
        vector::append(&mut extra_args, GENERIC_EXTRA_ARGS_V2_TAG);
        vector::append(&mut extra_args, bcs::to_bytes(&(GAS_LIMIT as u256)));
        vector::append(&mut extra_args, bcs::to_bytes(&ALLOW_OUT_OF_ORDER_EXECUTION));
        extra_args
    }
}
