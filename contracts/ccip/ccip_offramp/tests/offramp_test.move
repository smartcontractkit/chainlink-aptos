#[test_only]
module ccip_offramp::offramp_test {
    use std::signer;
    use std::string;
    use std::option;
    use std::chain_id;
    use std::account;
    use std::object::{Self, Object, ExtendRef, ObjectCore};
    use aptos_framework::fungible_asset::{Self, Metadata, MintRef, BurnRef, TransferRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use ccip_offramp::bcs_helper;
    use ccip_offramp::mock_token;

    use ccip::merkle_proof;
    use ccip::token_admin_registry;
    use ccip::rmn_remote;
    use ccip::nonce_manager;
    use ccip::auth;
    use ccip::state_object;
    use ccip::fee_quoter;
    use ccip_offramp::offramp;
    use ccip_offramp::ocr3_base;

    use burn_mint_token_pool::burn_mint_token_pool;
    use lock_release_token_pool::lock_release_token_pool;
    use managed_token::managed_token;
    use managed_token_pool::managed_token_pool;
    use regulated_token_pool::regulated_token_pool;
    use regulated_token::regulated_token;

    const CHAIN_ID: u8 = 100;
    const EVM_SOURCE_CHAIN_SELECTOR: u64 = 909606746561742123;
    const DEST_CHAIN_SELECTOR: u64 = 743186221051783445;
    const TOKEN_AMOUNT: u64 = 5000;

    const INBOUND_CAPACITY: u64 = 1000000000000000000;
    const INBOUND_RATE: u64 = 1000000000000000000;
    const OUTBOUND_CAPACITY: u64 = 1000000000000000000;
    const OUTBOUND_RATE: u64 = 1000000000000000000;

    const OWNER: address = @0x100;
    const SENDER: address = @0x200;
    const ROUTER: address = @0x300;
    const PERMISSIONLESS_EXECUTION_THRESHOLD_SECONDS: u32 = 3600; // 1 hour

    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;
    const MANAGED_TOKEN_POOL: u8 = 2;
    const REGULATED_TOKEN_POOL: u8 = 3;

    const BURN_MINT_TOKEN_SEED: vector<u8> = b"TestToken";
    const LOCK_RELEASE_TOKEN_SEED: vector<u8> = b"LockReleaseToken";
    const MANAGED_TOKEN_SEED: vector<u8> = b"ManagedToken";
    const REGULATED_TOKEN_SEED: vector<u8> = b"RegulatedToken";

    const MOCK_EVM_ADDRESS: address = @0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97;
    const MOCK_EVM_ADDRESS_VECTOR: vector<u8> = x"4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97";

    struct TestToken has key, store {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    fun init_timestamp(aptos_framework: &signer, timestamp_seconds: u64) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp_seconds);
    }

    /// use_v1_init: if true, uses test_init_v1 for token pools (V1 compatibility mode)
    /// if false, uses test_init_module for token pools (V2 mode, default)
    public fun setup(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer,
        pool_type: u8,
        seed: vector<u8>,
        is_dispatchable: bool,
        use_v1_init: bool
    ): (address, Object<Metadata>) {
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(signer::address_of(burn_mint_token_pool));
        account::create_account_for_test(signer::address_of(lock_release_token_pool));
        init_timestamp(aptos_framework, 100000);

        chain_id::initialize_for_test(aptos_framework, CHAIN_ID);

        // Create object for @ccip_offramp
        let _constructor_ref = object::create_named_object(owner, b"ccip_offramp");

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        // Create objects for token pools similar to onramp_test
        let constructor_ref = object::create_named_object(
            owner, b"burn_mint_token_pool"
        );
        let burn_mint_token_pool_obj_signer = &object::generate_signer(&constructor_ref);

        let constructor_ref =
            object::create_named_object(owner, b"lock_release_token_pool");
        let lock_release_token_pool_obj_signer =
            &object::generate_signer(&constructor_ref);

        // Create token pool object
        let constructor_ref =
            object::create_named_object(
                burn_mint_token_pool_obj_signer, b"ccip_token_pool"
            );
        let ccip_token_pool_obj =
            object::object_from_constructor_ref<ObjectCore>(&constructor_ref);

        // Transfer ownership if needed for lock_release pool
        if (pool_type == LOCK_RELEASE_TOKEN_POOL) {
            object::transfer(
                burn_mint_token_pool_obj_signer,
                ccip_token_pool_obj,
                signer::address_of(lock_release_token_pool_obj_signer)
            );
        };

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        rmn_remote::initialize(owner, EVM_SOURCE_CHAIN_SELECTOR);

        token_admin_registry::init_module_for_testing(ccip);
        offramp::test_init_module(ccip_offramp);
        nonce_manager::test_init_module(ccip);

        let (token_obj, token_addr) =
            create_test_token_and_pool(
                owner,
                ccip_offramp,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                pool_type,
                seed,
                is_dispatchable,
                use_v1_init
            );

        // Initialize fee quoter
        fee_quoter::initialize(
            owner,
            20000000000000,
            token_addr,
            12400,
            vector[token_addr]
        );

        // Initialize offramp
        initialize_offramp(owner);

        // Configure fees
        setup_fee_quoter(owner, ccip_offramp, token_addr);

        // Delay to allow token bucket to refill
        timestamp::update_global_time_for_test_secs(timestamp::now_seconds() + 10);

        (owner_addr, token_obj)
    }

    fun create_test_token_and_pool(
        owner: &signer,
        ccip_offramp_signer: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer,
        pool_type: u8,
        seed: vector<u8>,
        is_dispatchable: bool,
        use_v1_init: bool
    ): (Object<Metadata>, address) {
        let constructor_ref = object::create_named_object(owner, seed);

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(),
            string::utf8(seed),
            string::utf8(seed),
            0,
            string::utf8(b"http://www.example.com/favicon.ico"),
            string::utf8(b"http://www.example.com")
        );

        let metadata = object::object_from_constructor_ref(&constructor_ref);

        let obj_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Add dynamic dispatch function to the token if it is dispatchable
        if (is_dispatchable) {
            mock_token::add_dynamic_dispatch_function(
                ccip_offramp_signer, &constructor_ref
            );
        };

        let token_addr = object::object_address(&metadata);

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
                vector[EVM_SOURCE_CHAIN_SELECTOR],
                vector[vector[MOCK_EVM_ADDRESS_VECTOR]],
                vector[MOCK_EVM_ADDRESS_VECTOR]
            );
            burn_mint_token_pool::set_chain_rate_limiter_config(
                owner,
                EVM_SOURCE_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY,
                OUTBOUND_RATE,
                true,
                INBOUND_CAPACITY,
                INBOUND_RATE
            );
            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(burn_mint_token_pool)
            );
        } else if (pool_type == LOCK_RELEASE_TOKEN_POOL) {
            if (use_v1_init) {
                lock_release_token_pool::test_init_v1(lock_release_token_pool);
            } else {
                lock_release_token_pool::test_init_module(lock_release_token_pool);
            };
            lock_release_token_pool::initialize(
                owner, option::some(transfer_ref), signer::address_of(owner)
            );
            lock_release_token_pool::apply_chain_updates(
                owner,
                vector[],
                vector[EVM_SOURCE_CHAIN_SELECTOR],
                vector[vector[MOCK_EVM_ADDRESS_VECTOR]],
                vector[MOCK_EVM_ADDRESS_VECTOR]
            );
            lock_release_token_pool::set_chain_rate_limiter_config(
                owner,
                EVM_SOURCE_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY,
                OUTBOUND_RATE,
                true,
                INBOUND_CAPACITY,
                INBOUND_RATE
            );
            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(lock_release_token_pool)
            );
        } else if (pool_type == MANAGED_TOKEN_POOL) {
            let seed = b"MT";
            let _constructor_ref = &object::create_named_object(owner, seed);
            let _managed_token_pool_constructor_ref =
                &object::create_named_object(owner, b"ManagedTokenPool");

            managed_token::init_module_for_testing(managed_token);
            managed_token::initialize(
                owner,
                option::none(),
                string::utf8(b"Managed Token"),
                string::utf8(seed),
                6,
                string::utf8(b"https://managedtoken.com/images/pic.png"),
                string::utf8(b"https://managedtoken.com")
            );

            managed_token_pool::test_init_module(managed_token_pool);
            managed_token_pool::apply_chain_updates(
                owner,
                vector[],
                vector[EVM_SOURCE_CHAIN_SELECTOR],
                vector[vector[MOCK_EVM_ADDRESS_VECTOR]],
                vector[MOCK_EVM_ADDRESS_VECTOR]
            );
            managed_token_pool::set_chain_rate_limiter_config(
                owner,
                EVM_SOURCE_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY,
                OUTBOUND_RATE,
                true,
                INBOUND_CAPACITY,
                INBOUND_RATE
            );

            token_addr = managed_token::token_metadata();
            metadata = object::address_to_object(token_addr);

            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(managed_token_pool)
            );
            // Fund managed token pool
            primary_fungible_store::mint(
                &mint_ref, managed_token_pool::get_store_address(), 1000
            );
        } else if (pool_type == REGULATED_TOKEN_POOL) {
            account::create_account_for_test(signer::address_of(owner));
            account::create_account_for_test(signer::address_of(regulated_token_pool));
            account::create_account_for_test(signer::address_of(regulated_token));

            // Create an object at @regulated_token for the ownable functionality
            let regulated_token_pool_constructor_ref =
                object::create_named_object(owner, b"regulated_token_pool");
            account::create_account_for_test(
                object::address_from_constructor_ref(
                    &regulated_token_pool_constructor_ref
                )
            );

            // Setup regulated token first (use admin as the object creator)
            let regulated_token_constructor_ref =
                object::create_named_object(owner, b"regulated_token");
            account::create_account_for_test(
                object::address_from_constructor_ref(&regulated_token_constructor_ref)
            );

            regulated_token::init_module_for_testing(regulated_token);
            regulated_token::initialize(
                owner,
                option::none(),
                string::utf8(b"Regulated Token"),
                string::utf8(b"RT"),
                6,
                string::utf8(
                    b"https://regulatedtoken.com/images/pic.png"
                ),
                string::utf8(b"https://regulatedtoken.com")
            );

            if (use_v1_init) {
                regulated_token_pool::test_init_v1(regulated_token_pool);
            } else {
                regulated_token_pool::test_init_module(regulated_token_pool);
            };
            regulated_token_pool::apply_chain_updates(
                owner,
                vector[],
                vector[EVM_SOURCE_CHAIN_SELECTOR],
                vector[vector[MOCK_EVM_ADDRESS_VECTOR]],
                vector[MOCK_EVM_ADDRESS_VECTOR]
            );
            regulated_token_pool::set_chain_rate_limiter_config(
                owner,
                EVM_SOURCE_CHAIN_SELECTOR,
                true,
                OUTBOUND_CAPACITY,
                OUTBOUND_RATE,
                true,
                INBOUND_CAPACITY,
                INBOUND_RATE
            );

            token_addr = regulated_token::token_address();
            metadata = regulated_token::token_metadata();

            // Set admin for token
            token_admin_registry::propose_administrator(
                owner, token_addr, signer::address_of(owner)
            );
            token_admin_registry::accept_admin_role(owner, token_addr);
            token_admin_registry::set_pool(
                owner, token_addr, signer::address_of(regulated_token_pool)
            );

            // Fund regulated token pool
            primary_fungible_store::mint(
                &mint_ref, regulated_token_pool::get_store_address(), 1000
            );
        };

        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Fund lock/release token pool with sufficient liquidity for tests
        primary_fungible_store::mint(
            &mint_ref,
            lock_release_token_pool::get_store_address(),
            10000000 // 10M tokens for test liquidity
        );

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

    public fun initialize_offramp(owner: &signer): address {
        offramp::initialize(
            owner,
            DEST_CHAIN_SELECTOR,
            PERMISSIONLESS_EXECUTION_THRESHOLD_SECONDS,
            vector[EVM_SOURCE_CHAIN_SELECTOR],
            vector[true], // is_enabled
            vector[false], // is_rmn_verification_disabled
            vector[x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e"] // on_ramp address
        );

        offramp::get_state_address()
    }

    public fun setup_fee_quoter(
        owner: &signer, ccip_offramp: &signer, token_addr: address
    ) {
        fee_quoter::apply_fee_token_updates(owner, vector[], vector[token_addr]);
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            EVM_SOURCE_CHAIN_SELECTOR, // dest_chain_selector
            vector[token_addr], // add_tokens
            vector[50], // add_min_fee_usd_cents
            vector[500], // add_max_fee_usd_cents
            vector[10], // add_deci_bps - 0.01% (1 bps)
            vector[5000], // add_dest_gas_overhead
            vector[64], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            EVM_SOURCE_CHAIN_SELECTOR,
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            1000, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            x"ac77ffec", // chain_family_selector_aptos
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            1000, // default_token_dest_gas_overhead - needs to be non-zero
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        fee_quoter::apply_premium_multiplier_wei_per_eth_updates(
            owner, vector[token_addr], vector[1]
        );

        // Register permissions
        auth::apply_allowed_offramp_updates(
            owner,
            vector[],
            vector[signer::address_of(ccip_offramp)]
        );

        auth::apply_allowed_offramp_updates(
            owner,
            vector[],
            vector[offramp::get_state_address()]
        );

        // Update prices
        fee_quoter::update_prices(
            ccip_offramp,
            vector[token_addr],
            vector[1000],
            vector[EVM_SOURCE_CHAIN_SELECTOR],
            vector[100]
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_initialize(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );

        // Verify initialization was successful
        let static_config = offramp::get_static_config();
        assert!(offramp::chain_selector(&static_config) == DEST_CHAIN_SELECTOR);

        let dynamic_config = offramp::get_dynamic_config();
        assert!(
            offramp::permissionless_execution_threshold_seconds(&dynamic_config)
                == PERMISSIONLESS_EXECUTION_THRESHOLD_SECONDS
        );

        let source_chain_config =
            offramp::get_source_chain_config(EVM_SOURCE_CHAIN_SELECTOR);
        assert!(offramp::is_enabled(&source_chain_config));
        assert!(!offramp::is_rmn_verification_disabled(&source_chain_config));

        assert!(offramp::owner() == signer::address_of(owner));
    }

    #[test]
    fun test_calculate_message_hash() {
        let expected_hash =
            x"c8d6cf666864a60dd6ecd89e5c294734c53b3218d3f83d2d19a3c3f9e200e00d";

        let message_id =
            x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let source_chain_selector = 123456789;
        let dest_chain_selector = 987654321;
        let sequence_number = 42;
        let nonce = 123;

        let message =
            offramp::test_create_any2aptos_ramp_message(
                offramp::test_create_ramp_message_header(
                    message_id,
                    source_chain_selector,
                    dest_chain_selector,
                    sequence_number,
                    nonce
                ),
                x"8765432109fedcba8765432109fedcba87654321",
                b"sample message data",
                @0x1234,
                500000,
                vector[
                    offramp::test_create_any2aptos_token_transfer(
                        x"abcdef1234567890abcdef1234567890abcdef12",
                        @0x5678,
                        10000,
                        x"00112233",
                        1000000
                    ),
                    offramp::test_create_any2aptos_token_transfer(
                        x"123456789abcdef123456789abcdef123456789a",
                        @0x9abc,
                        20000,
                        x"ffeeddcc",
                        5000000
                    )
                ]
            );

        let metadata_hash =
            x"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        let message_hash = offramp::test_calculate_message_hash(&message, metadata_hash);
        assert!(message_hash == expected_hash);
    }

    #[test]
    fun test_calculate_metadata_hash() {
        let expected_hash =
            x"812acb01df318f85be452cf6664891cf5481a69dac01e0df67102a295218dd17";
        let expected_hash_alternate =
            x"6caf8756ae02ee4f12b83b38e0f21b5e43e90d203bd06729486fd4a0fc8bcc5e";

        let source_chain_selector = 123456789;
        let dest_chain_selector = 987654321;
        let on_ramp = b"source-onramp-address";

        let metadata_hash =
            offramp::test_calculate_metadata_hash(
                source_chain_selector, dest_chain_selector, on_ramp
            );
        let metadata_hash_alternate =
            offramp::test_calculate_metadata_hash(
                source_chain_selector + 1, dest_chain_selector, on_ramp
            );

        assert!(metadata_hash == expected_hash);
        assert!(metadata_hash_alternate == expected_hash_alternate);
    }

    #[test]
    fun test_deserialize_execution_report() {
        let expected_sender = x"d87929a32cf0cbdc9e2d07ffc7c33344079de727";
        let expected_data = x"68656c6c6f20434349505265636569766572";
        let expected_receiver =
            @0xbd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490;
        let expected_gas_limit = 100000;
        let expected_message_id =
            x"20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc";
        let expected_EVM_SOURCE_CHAIN_SELECTOR = 909606746561742123;
        let expected_dest_chain_selector = 743186221051783445;
        let expected_sequence_number = 1;
        let expected_nonce = 0;
        let expected_leaf_bytes =
            x"258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e";

        let report_bytes =
            x"2b851c4684929f0c20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc2b851c4684929f0c15a9c133ee53500a0100000000000000000000000000000014d87929a32cf0cbdc9e2d07ffc7c33344079de7271268656c6c6f20434349505265636569766572bd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490a086010000000000000000000000000000000000000000000000000000000000000000";
        let onramp = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";
        let execution_report = offramp::test_deserialize_execution_report(report_bytes);

        assert!(offramp::sender(offramp::message(&execution_report)) == expected_sender);
        assert!(offramp::data(offramp::message(&execution_report)) == expected_data);
        assert!(
            offramp::receiver(offramp::message(&execution_report)) == expected_receiver
        );
        assert!(
            offramp::gas_limit(offramp::message(&execution_report))
                == expected_gas_limit
        );
        assert!(
            offramp::header_message_id(
                offramp::header(offramp::message(&execution_report))
            ) == expected_message_id
        );
        assert!(
            offramp::header_source_chain_selector(
                offramp::header(offramp::message(&execution_report))
            ) == expected_EVM_SOURCE_CHAIN_SELECTOR
        );
        assert!(
            offramp::header_dest_chain_selector(
                offramp::header(offramp::message(&execution_report))
            ) == expected_dest_chain_selector
        );
        assert!(
            offramp::sequence_number(offramp::header(offramp::message(&execution_report)))
            == expected_sequence_number
        );
        assert!(
            offramp::nonce(offramp::header(offramp::message(&execution_report)))
                == expected_nonce
        );

        let metadata_hash =
            offramp::test_calculate_metadata_hash(
                offramp::header_source_chain_selector(
                    offramp::header(offramp::message(&execution_report))
                ),
                offramp::header_dest_chain_selector(
                    offramp::header(offramp::message(&execution_report))
                ),
                onramp
            );
        let hashed_leaf =
            offramp::test_calculate_message_hash(
                offramp::message(&execution_report), metadata_hash
            );

        assert!(expected_leaf_bytes == hashed_leaf);
    }

    #[test]
    fun test_deserialize_commit_report() {
        let expected_source_token = @0xa;
        let expected_usd_per_token = 500000000000000000000;
        let expected_source_chain_selector = 909606746561742123;
        let expected_on_ramp_address = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";
        let expected_min_seq_nr = 1;
        let expected_max_seq_nr = 1;
        let expected_merkle_root =
            x"258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e";

        let commit_report_bytes =
            x"01000000000000000000000000000000000000000000000000000000000000000a000050efe2d6e41a1b00000000000000000000000000000000000000000000000000012b851c4684929f0c1447a1f0a819457f01153f35c6b6b0d42e2e16e91e01000000000000000100000000000000258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e00";

        let commit_report = offramp::test_deserialize_commit_report(commit_report_bytes);

        // PriceUpdates
        let price_updates = offramp::commit_report_price_updates(&commit_report);
        let token_price_updates =
            offramp::price_updates_token_price_updates(price_updates);
        assert!(token_price_updates.length() == 1);
        let token_price_update = &token_price_updates[0];
        assert!(
            offramp::token_price_update_source_token(token_price_update)
                == expected_source_token
        );
        assert!(
            offramp::token_price_update_usd_per_token(token_price_update)
                == expected_usd_per_token
        );
        let gas_price_updates = offramp::price_updates_gas_price_updates(price_updates);
        assert!(gas_price_updates.is_empty());

        // Merkle Roots
        let blessed_merkle_roots =
            offramp::commit_report_blessed_merkle_roots(&commit_report);
        assert!(blessed_merkle_roots.is_empty());

        let unblessed_merkle_roots =
            offramp::commit_report_unblessed_merkle_roots(&commit_report);
        assert!(unblessed_merkle_roots.length() == 1);
        let merkle_root_struct = &unblessed_merkle_roots[0];
        assert!(
            offramp::merkle_root_source_chain_selector(merkle_root_struct)
                == expected_source_chain_selector
        );
        assert!(
            offramp::merkle_root_on_ramp_address(merkle_root_struct)
                == expected_on_ramp_address
        );
        assert!(
            offramp::merkle_root_min_seq_nr(merkle_root_struct) == expected_min_seq_nr
        );
        assert!(
            offramp::merkle_root_max_seq_nr(merkle_root_struct) == expected_max_seq_nr
        );
        assert!(
            offramp::merkle_root_merkle_root(merkle_root_struct)
                == expected_merkle_root
        );

        let rmn_signatures = offramp::commit_report_rmn_signatures(&commit_report);
        assert!(rmn_signatures.is_empty());
    }

    #[test(aptos_framework = @aptos_framework)]
    fun test_create_serialized_execution_report(
        aptos_framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);

        // Message ID (from JSON)
        let message_id =
            x"f3514a995f0ed287f1000a115447dd188f8714cf6187874aa2e9cd89af8d31da";

        // Destination chain selector (from JSON)
        let dest_chain_selector: u64 = 743186221051783445;

        // Sequence number (from JSON)
        let sequence_number: u64 = 6;

        // Sender (from JSON)
        let sender = x"e30b40bfb1baeed9e4c62f145be85eb3d19ae932";

        // Data (from JSON)
        let data = x"4920616d206120746573742063636970206d657373616765"; // "I am a test ccip message"

        // ccip_offramp address
        let receiver =
            @0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba;

        // Token amounts (empty array from JSON)
        let token_amounts: vector<offramp::Any2AptosTokenTransfer> = vector[];

        // Gas limit (from JSON)
        let gas_limit: u256 = 0;

        // Offchain token data (empty array from JSON but nested)
        let empty_vector: vector<u8> = vector[];
        let offchain_token_data: vector<vector<u8>> = vector[empty_vector];

        // Proofs from the JSON
        let proofs = vector[
            x"3a68ff2c8091476723b8312418da36c358cc4ff7e64b4bcc633a96548ee85394",
            x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            x"07ee4ff5528128e49067a01b99835e09746052bb4c6dd2ad1d4297843efa0bec"
        ];
        // vector::append(&mut proofs, bcs::to_bytes(&empty_vector));

        // Use the helper function to create the report bytes with CORRECT serialization
        let nonce: u64 = 0; // nonce must be 0 for out-of-order execution
        let report_bytes =
            bcs_helper::create_execution_report_bytes(
                EVM_SOURCE_CHAIN_SELECTOR,
                message_id,
                dest_chain_selector,
                sequence_number,
                nonce,
                sender,
                data,
                receiver,
                gas_limit,
                token_amounts,
                offchain_token_data,
                proofs
            );

        let deserialized_report =
            offramp::test_deserialize_execution_report(report_bytes);
        let header = offramp::header(offramp::message(&deserialized_report));
        assert!(
            offramp::header_source_chain_selector(header) == EVM_SOURCE_CHAIN_SELECTOR
        );

        let deserialized_message = offramp::message(&deserialized_report);
        let deserialized_header = offramp::header(deserialized_message);

        assert!(
            offramp::header_source_chain_selector(deserialized_header)
                == EVM_SOURCE_CHAIN_SELECTOR
        );
        assert!(
            offramp::header_dest_chain_selector(deserialized_header)
                == dest_chain_selector
        );

        let header_sequence_number = offramp::sequence_number(deserialized_header);
        assert!(header_sequence_number == sequence_number);
    }

    #[test(aptos_framework = @aptos_framework)]
    fun test_proper_serialization(aptos_framework: &signer) {
        timestamp::set_time_has_started_for_testing(aptos_framework);

        let message_id =
            x"f3514a995f0ed287f1000a115447dd188f8714cf6187874aa2e9cd89af8d31da";
        let dest_chain_selector: u64 = 743186221051783445;
        let sequence_number: u64 = 6;
        let sender = x"e30b40bfb1baeed9e4c62f145be85eb3d19ae932";
        let data = x"4920616d206120746573742063636970206d657373616765";
        let receiver =
            @0x096c526aee8e07742b943d8c947344eacca7af4fbaec1c7c3e4c56114534de73;
        let token_amounts: vector<offramp::Any2AptosTokenTransfer> = vector[];
        let gas_limit: u256 = 0;
        let offchain_token_data: vector<vector<u8>> = vector[vector[]];
        let proofs = vector[
            x"3a68ff2c8091476723b8312418da36c358cc4ff7e64b4bcc633a96548ee85394",
            x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            x"07ee4ff5528128e49067a01b99835e09746052bb4c6dd2ad1d4297843efa0bec"
        ];

        // Use the helper function to create the report bytes with CORRECT serialization
        let nonce: u64 = 0; // nonce must be 0 for out-of-order execution
        let report_bytes =
            bcs_helper::create_execution_report_bytes(
                EVM_SOURCE_CHAIN_SELECTOR,
                message_id,
                dest_chain_selector,
                sequence_number,
                nonce,
                sender,
                data,
                receiver,
                gas_limit,
                token_amounts,
                offchain_token_data,
                proofs
            );

        let deserialized_report =
            offramp::test_deserialize_execution_report(report_bytes);

        let header = offramp::header(offramp::message(&deserialized_report));

        assert!(
            offramp::header_source_chain_selector(header) == EVM_SOURCE_CHAIN_SELECTOR
        );

        let deserialized_message = offramp::message(&deserialized_report);
        let deserialized_header = offramp::header(deserialized_message);

        assert!(
            offramp::header_source_chain_selector(deserialized_header)
                == EVM_SOURCE_CHAIN_SELECTOR
        );
        assert!(
            offramp::header_dest_chain_selector(deserialized_header)
                == dest_chain_selector
        );

        let header_sequence_number = offramp::sequence_number(deserialized_header);
        assert!(header_sequence_number == sequence_number);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_commit_and_execute(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );
        let config_digest =
            x"000aed76a87f048dab766bc14ecdbb966f4253e309d742585062a75abfc16c38";
        let sequence_bytes =
            x"0000000000000000000000000000000000000000000000000000000000000005";
        let onramp_address = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";

        offramp::apply_source_chain_config_updates(
            owner,
            vector[EVM_SOURCE_CHAIN_SELECTOR],
            vector[true], // is_enabled
            vector[true], // is_rmn_verification_disabled
            vector[onramp_address]
        );

        // https://explorer.aptoslabs.com/txn/6668426643/payload?network=testnet
        let signers = vector[
            x"23f7c3895726904020bf79ed45e294e9e8f675b3c8ac4ccb6f0365d46ea8f948",
            x"d95f678f5dd5b715f809fc8c7a7848c9e122d9ba04b1480b41ae04eb36d118cb",
            x"61ec5f4bbb6a5f2c4262d3a4aa9dd33b4da6e29a069254d0e0e188a84c31ade7",
            x"326ca02220991762549f59b7d5fc727787d546f5d42fa7a9f4f1f62bec267d2c"
        ];

        let transmitters = vector[signer::address_of(ccip_offramp), signer::address_of(
            owner
        )];
        let f = 1; // BigF value for OCR config

        // Set up OCR3 config for commit plugin with the exact configuration
        // https://explorer.aptoslabs.com/txn/6668426643/payload?network=testnet
        offramp::set_ocr3_config(
            owner,
            config_digest, // config_digest
            ocr3_base::ocr_plugin_type_commit(),
            f,
            true, // is_signature_verification_enabled - must be true for commit plugin
            signers,
            transmitters
        );

        let config = offramp::latest_config_details(ocr3_base::ocr_plugin_type_commit());
        assert!(ocr3_base::config_signers(&config) == signers);
        assert!(ocr3_base::config_transmitters(&config) == transmitters);

        // ===== Build the commit report with exact transaction data =====

        // Create the report context - this is what the transmitters would sign
        let report_context = vector[config_digest, sequence_bytes];

        // https://explorer.aptoslabs.com/txn/6668426995/userTxnOverview?network=testnet

        // Deserialized commit report

        // 0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::CommitReport {
        //   price_updates: 0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::PriceUpdates {
        //     token_price_updates: [
        //       0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::TokenPriceUpdate {
        //         source_token: @0xa,
        //         usd_per_token: 500000000000000000000
        //       }
        //     ],
        //     gas_price_updates: []
        //   },
        //   blessed_merkle_roots: [],
        //   unblessed_merkle_roots: [
        //     0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::MerkleRoot {
        //       EVM_SOURCE_CHAIN_SELECTOR: 909606746561742123,
        //       on_ramp_address: 0x47a1f0a819457f01153f35c6b6b0d42e2e16e91e,
        //       min_seq_nr: 1,
        //       max_seq_nr: 1,
        //       merkle_root: 0x258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e
        //     }
        //   ],
        //   rmn_signatures: []
        // }

        // Create the commit report
        let commit_report_bytes =
            x"01000000000000000000000000000000000000000000000000000000000000000a000050efe2d6e41a1b00000000000000000000000000000000000000000000000000012b851c4684929f0c1447a1f0a819457f01153f35c6b6b0d42e2e16e91e01000000000000000100000000000000258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e00";
        offramp::commit(
            ccip_offramp,
            report_context,
            commit_report_bytes,
            vector[
                x"23f7c3895726904020bf79ed45e294e9e8f675b3c8ac4ccb6f0365d46ea8f948581f47bda72115bed3bc50bba6ddbc56601592524c0527206b035574add85f5258be225f913f08817615854459891e1ccbab3f730a5c3a5caa0cfd742e625c00",
                x"d95f678f5dd5b715f809fc8c7a7848c9e122d9ba04b1480b41ae04eb36d118cb7f8850db30e12a6807f8eefeae6bba136669235602529f993da0139d4895f184444a88510ae7a8247d5d683bb7a5ff5ac26cebdc7b0f88eb1b09f4632160cb08"
            ]
        );

        // ====== Execute ======

        // Set up OCR3 config for commit plugin with the exact configuration
        // https://explorer.aptoslabs.com/txn/6668426658/payload?network=testnet

        let config_digest =
            x"000a616fac87d8b5406dc2f3149e501a3952f3a3af404f8ce58e80875b524819";
        let f = 1; // BigF value for OCR config
        let signers = vector[
            x"23f7c3895726904020bf79ed45e294e9e8f675b3c8ac4ccb6f0365d46ea8f948",
            x"d95f678f5dd5b715f809fc8c7a7848c9e122d9ba04b1480b41ae04eb36d118cb",
            x"61ec5f4bbb6a5f2c4262d3a4aa9dd33b4da6e29a069254d0e0e188a84c31ade7",
            x"326ca02220991762549f59b7d5fc727787d546f5d42fa7a9f4f1f62bec267d2c"
        ];
        let transmitters = vector[signer::address_of(ccip_offramp), signer::address_of(
            owner
        )];

        offramp::set_ocr3_config(
            owner,
            config_digest, // config_digest
            ocr3_base::ocr_plugin_type_execution(),
            f,
            false, // is_signature_verification_enabled
            signers,
            transmitters
        );

        // https://explorer.aptoslabs.com/txn/6668427121/userTxnOverview?network=testnet

        let report_context = vector[
            x"000a616fac87d8b5406dc2f3149e501a3952f3a3af404f8ce58e80875b524819", // config_digest
            x"0000000000000000000000000000000000000000000000000000000000000009" // sequence_number
        ];
        let report =
            x"2b851c4684929f0c20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc2b851c4684929f0c15a9c133ee53500a0100000000000000000000000000000014d87929a32cf0cbdc9e2d07ffc7c33344079de7271268656c6c6f20434349505265636569766572bd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490a086010000000000000000000000000000000000000000000000000000000000000000";

        // Deserialized execute report

        // 0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::ExecutionReport {
        //   EVM_SOURCE_CHAIN_SELECTOR: 909606746561742123,
        //   message: 0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::Any2AptosRampMessage {
        //     header: 0xc6bcb7d2c22391db9b56fc98d6ef142e7d8f7035dc75fae2bfc469daa1b0d0ba::offramp::RampMessageHeader {
        //       message_id: 0x20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc,
        //       EVM_SOURCE_CHAIN_SELECTOR: 909606746561742123,
        //       dest_chain_selector: 743186221051783445,
        //       sequence_number: 1,
        //       nonce: 0
        //     },
        //     sender: 0xd87929a32cf0cbdc9e2d07ffc7c33344079de727,
        //     data: 0x68656c6c6f20434349505265636569766572,
        //     receiver: @0xbd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490,
        //     gas_limit: 100000,
        //     token_amounts: []
        //   },
        //   offchain_token_data: [],
        //   proofs: []
        //  }

        offramp::execute(ccip_offramp, report_context, report);

        let execution_state = offramp::get_execution_state(EVM_SOURCE_CHAIN_SELECTOR, 1); // sequence_number is 1
        assert!(execution_state == 2); // EXECUTION_STATE_SUCCESS is 2
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_manually_execute(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );

        let merkle_root =
            x"258dc7f9ec033388ee50bf3e0debfc841a278054f5b2ce41728f7459267c719e";
        offramp::test_add_root(merkle_root, timestamp::now_seconds() - 3700);

        let report =
            x"2b851c4684929f0c20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc2b851c4684929f0c15a9c133ee53500a0100000000000000000000000000000014d87929a32cf0cbdc9e2d07ffc7c33344079de7271268656c6c6f20434349505265636569766572bd8a1fb0af25dc8700d2d302cfbae718c3b2c3c61cfe47f58a45b1126c006490a086010000000000000000000000000000000000000000000000000000000000000000";
        offramp::manually_execute(report);

        let execution_state = offramp::get_execution_state(EVM_SOURCE_CHAIN_SELECTOR, 1); // sequence_number is 1
        assert!(execution_state == 2); // EXECUTION_STATE_SUCCESS is 2
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token,
            receiver = @0xbed8
        )
    ]
    fun test_burn_mint_pool_execute_single_report_with_token_transfer(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer,
        receiver: &signer
    ) {
        test_execute_single_report_with_token_transfer(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            receiver,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        )
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token,
            receiver = @0xbed8
        )
    ]
    fun test_lock_release_pool_execute_single_report_with_token_transfer(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer,
        receiver: &signer
    ) {
        test_execute_single_report_with_token_transfer(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            receiver,
            LOCK_RELEASE_TOKEN_POOL,
            LOCK_RELEASE_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        )
    }

    // Helper function to test execute single report with token transfer
    // Specifying pool type (burn/mint or lock/release)
    fun test_execute_single_report_with_token_transfer(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer,
        receiver: &signer,
        pool_type: u8,
        token_seed: vector<u8>,
        is_dispatchable: bool,
        use_v1_init: bool
    ) {
        let (_owner_addr, token_obj) =
            setup(
                aptos_framework,
                ccip,
                ccip_offramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                managed_token_pool,
                managed_token,
                regulated_token_pool,
                regulated_token,
                pool_type,
                token_seed,
                is_dispatchable,
                use_v1_init
            );

        let token_addr = object::object_address(&token_obj);
        let receiver_addr = signer::address_of(receiver);
        account::create_account_for_test(receiver_addr);

        let onramp_address = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";

        offramp::apply_source_chain_config_updates(
            owner,
            vector[EVM_SOURCE_CHAIN_SELECTOR],
            vector[true], // is_enabled
            vector[true], // is_rmn_verification_disabled
            vector[onramp_address]
        );

        // Check initial balance (should be 0)
        let initial_balance = primary_fungible_store::balance(receiver_addr, token_obj);
        assert!(initial_balance == 0);

        // Create token transfer with amount
        let token_amount: u256 = 1000;
        let token_transfer =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR, // source_pool_address
                token_addr, // dest_token_address
                0, // dest_gas_amount
                vector[], // extra_data
                token_amount // amount to transfer
            );

        let token_transfers = vector[token_transfer];
        let message_id =
            x"20865dcacbd6afb6a2288daa164caf75517009a289fa3135281fb1e4800b11bc";
        let dest_chain_selector: u64 = 743186221051783445;
        let sequence_number: u64 = 1;
        let nonce: u64 = 0;
        let sender = x"d87929a32cf0cbdc9e2d07ffc7c33344079de727";
        let data = x"68656c6c6f20434349505265636569766572";
        let gas_limit: u256 = 100000;

        let header =
            offramp::test_create_ramp_message_header(
                message_id,
                EVM_SOURCE_CHAIN_SELECTOR,
                dest_chain_selector,
                sequence_number,
                nonce
            );
        let message =
            offramp::test_create_any2aptos_ramp_message(
                header,
                sender,
                data,
                receiver_addr,
                gas_limit,
                token_transfers
            );
        let metadata_hash =
            offramp::test_calculate_metadata_hash(
                EVM_SOURCE_CHAIN_SELECTOR, dest_chain_selector, onramp_address
            );
        let hashed_leaf = offramp::test_calculate_message_hash(&message, metadata_hash);

        let proofs = vector[];
        let root = merkle_proof::merkle_root(hashed_leaf, proofs);

        // Simply commit by adding root to
        offramp::test_add_root(root, timestamp::now_seconds() - 3700);

        // Create offchain token data (needed for token transfers)
        let offchain_token_data: vector<vector<u8>> = vector[vector[]];

        // Create execution report using helper function
        let execution_report =
            offramp::test_create_execution_report(
                EVM_SOURCE_CHAIN_SELECTOR,
                message,
                offchain_token_data,
                vector[] // empty proofs for simplicity
            );

        offramp::test_execute_single_report(execution_report);

        let final_balance = primary_fungible_store::balance(receiver_addr, token_obj);
        assert!(final_balance == (token_amount as u64));

        let execution_state =
            offramp::get_execution_state(EVM_SOURCE_CHAIN_SELECTOR, sequence_number);
        assert!(execution_state == 2); // 2 is EXECUTION_STATE_SUCCESS
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_transfer_ownership_flow(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );
        let new_owner = signer::address_of(aptos_framework);
        account::create_account_for_test(new_owner);

        offramp::transfer_ownership(owner, new_owner);

        offramp::accept_ownership(aptos_framework);

        offramp::execute_ownership_transfer(owner, new_owner);

        assert!(offramp::owner() == new_owner);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    fun test_getters(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );

        let latest_price_sequence_number = offramp::get_latest_price_sequence_number();
        assert!(latest_price_sequence_number == 0);

        let (source_chain_selectors, _source_chain_configs) =
            offramp::get_all_source_chain_configs();
        assert!(source_chain_selectors.length() == 1);
        assert!(source_chain_selectors[0] == EVM_SOURCE_CHAIN_SELECTOR);
    }

    // =============== Error handling tests ===============
    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    #[expected_failure(abort_code = 65540, location = ccip_offramp::offramp)]
    fun test_invalid_source_chain_selector(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );

        // E_UNKNOWN_SOURCE_CHAIN_SELECTOR
        let _execution_state = offramp::get_execution_state(123456789, 1);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_offramp = @ccip_offramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            managed_token_pool = @managed_token_pool,
            managed_token = @managed_token,
            regulated_token_pool = @regulated_token_pool,
            regulated_token = @regulated_token
        )
    ]
    #[expected_failure(abort_code = 65550, location = ccip_offramp::offramp)]
    fun test_invalid_root_retrieval(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_offramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        managed_token_pool: &signer,
        managed_token: &signer,
        regulated_token_pool: &signer,
        regulated_token: &signer
    ) {
        setup(
            aptos_framework,
            ccip,
            ccip_offramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            managed_token_pool,
            managed_token,
            regulated_token_pool,
            regulated_token,
            BURN_MINT_TOKEN_POOL,
            BURN_MINT_TOKEN_SEED,
            false, // is_dispatchable
            false // use_v1_init
        );

        // E_INVALID_ROOT
        let _merkle_root = offramp::get_merkle_root(vector[]);
    }
}
