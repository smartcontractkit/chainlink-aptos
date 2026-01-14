#[test_only]
module ccip_onramp::onramp_dispatchable_token_test {
    use std::signer;
    use std::string::{Self};
    use std::option::{Self};
    use std::vector;
    use std::object::{Self, Object, ExtendRef, ObjectCore};
    use std::account;
    use std::bcs;
    use std::fungible_asset::{
        Self,
        Metadata,
        MintRef,
        BurnRef,
        TransferRef,
        FungibleStore
    };
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
    use ccip_onramp::mock_token;

    use burn_mint_token_pool::burn_mint_token_pool;
    use lock_release_token_pool::lock_release_token_pool;

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

    struct CCIPSendResult has drop {
        message_id: vector<u8>,
        token_obj: Object<Metadata>,
        sender_store: Object<FungibleStore>,
        fee_token_amount: u64,
        sent_amount: u64
    }

    fun execute_ccip_send_test(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        router: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        pool_type: u8,
        token_name: vector<u8>,
        is_dispatchable: bool,
        generate_transfer_ref: bool
    ): CCIPSendResult acquires TestToken {
        let (_owner_addr, token_obj) =
            setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                pool_type,
                token_name,
                is_dispatchable,
                generate_transfer_ref
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

        CCIPSendResult {
            message_id,
            token_obj,
            sender_store,
            fee_token_amount,
            sent_amount
        }
    }

    fun assert_ccip_send_success(result: &CCIPSendResult) {
        assert!(result.message_id.length() > 0);

        // Verify sequence number was incremented
        let (sequence_number, _, _) = onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(sequence_number == 1);

        // Verify tokens were transferred
        let sender_balance = fungible_asset::balance(result.sender_store);
        assert!(sender_balance == 0); // All tokens sent

        // Verify fee token was transferred
        // let token_metadata = object::convert<TestToken, Metadata>(result.token_obj);
        let onramp_state_balance =
            primary_fungible_store::balance(
                onramp::get_state_address(), result.token_obj
            );
        assert!(onramp_state_balance == result.fee_token_amount);
    }

    fun assert_lock_release_pool_success(result: &CCIPSendResult) {
        assert_ccip_send_success(result);

        // Check token pool balance to see if tokens are locked
        let token_pool_addr = lock_release_token_pool::get_store_address();
        let token_pool_balance =
            primary_fungible_store::balance(token_pool_addr, result.token_obj);
        assert!(token_pool_balance == result.sent_amount);

        assert!(
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            ).length() == 1
        );
    }

    fun assert_burn_mint_pool_success(result: &CCIPSendResult) {
        assert_ccip_send_success(result);
        assert!(
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            ).length() == 1
        );
    }

    // ========================== Dynamic Dispatch Tests with Token Pools ==========================
    //
    // These tests are used to verify the dynamic dispatch of the tokens registered with token pools
    //
    // - Dynamic dispatch for `burn_mint_token_pool` works because we use refs
    // - For `lock_release_token_pool`, this takes an `Option<TransferRef>`
    //   Tokens that have dynamic dispatch enabled NEED to provide a `TransferRef`
    //   Tokens that do not have dynamic dispatch enabled can provide `option::none()`
    // ============================================================================================
    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            router = @0x200,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_token_dispatch_ccip_send_lock_release_token_pool(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        router: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let result =
            execute_ccip_send_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                sender,
                router,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                b"LockReleaseToken",
                true, // is_dispatchable
                true // generate_transfer_ref
            );

        assert_lock_release_pool_success(&result);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            router = @0x200,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_token_dispatch_ccip_send_burn_mint_token_pool(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        router: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let result =
            execute_ccip_send_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                sender,
                router,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                b"TestToken",
                true, // is_dispatchable
                false // generate_transfer_ref
            );

        assert_burn_mint_pool_success(&result);
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
    #[
        expected_failure(
            abort_code = lock_release_token_pool::lock_release_token_pool::E_DISPATCHABLE_TOKEN_WITHOUT_TRANSFER_REF,
            location = lock_release_token_pool::lock_release_token_pool
        )
    ]
    fun test_dispatchable_token_without_transfer_ref_lock_release_token_pool(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        // E_DISPATCHABLE_TOKEN_WITHOUT_TRANSFER_REF
        // Cannot register dispatchable token without a transfer ref
        let (_owner_addr, _token_obj) =
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
                true, // is_dispatchable
                false // generate_transfer_ref
            );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            router = @0x200,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_non_dispatchable_token_without_transfer_ref_success(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        router: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let result =
            execute_ccip_send_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                sender,
                router,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                b"LockReleaseToken",
                false, // is_dispatchable
                false // generate_transfer_ref
            );

        assert_lock_release_pool_success(&result);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            sender = @0x500,
            router = @0x200,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_non_dispatchable_token_with_transfer_ref_success(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        sender: &signer,
        router: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) acquires TestToken {
        let result =
            execute_ccip_send_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                sender,
                router,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                b"LockReleaseToken",
                false, // is_dispatchable
                true // generate_transfer_ref
            );

        assert_lock_release_pool_success(&result);
    }

    fun setup(
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
        generate_transfer_ref: bool
    ): (address, Object<Metadata>) {
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(signer::address_of(burn_mint_token_pool));
        account::create_account_for_test(signer::address_of(lock_release_token_pool));
        init_timestamp(aptos_framework, 100000);

        // Create object for @ccip_onramp
        let _constructor_ref = object::create_named_object(owner, b"ccip_onramp");
        let ccip_onramp_obj_signer = object::generate_signer(&_constructor_ref);

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
                &ccip_onramp_obj_signer,
                is_dispatchable,
                generate_transfer_ref
            );

        fee_quoter::initialize(owner, 0, token_addr, 12400, vector[token_addr]);

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
        assert!(onramp::owner() == owner_addr);

        // ========================== Fee Quoter ==========================
        //
        // We set fees to 0 as we want to test the dynamic dispatch of the tokens registered
        // with the token pools.
        //
        // =================================================================

        fee_quoter::apply_fee_token_updates(owner, vector[], vector[token_addr]);
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            DEST_CHAIN_SELECTOR, // dest_chain_selector
            vector[token_addr], // add_tokens
            vector[50], // add_min_fee_usd_cents
            vector[500], // add_max_fee_usd_cents
            vector[25], // add_deci_bps
            vector[5], // add_dest_gas_overhead
            vector[100], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            DEST_CHAIN_SELECTOR, // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            0, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            CHAIN_FAMILY_SELECTOR_EVM, // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );
        fee_quoter::apply_premium_multiplier_wei_per_eth_updates(
            owner,
            vector[token_addr], // tokens
            vector[0] // premium_multiplier_wei_per_eth
        );

        // To be able to call token_admin_dispatcher::dispatch_lock_or_burn
        // Need to register onramp signer as an allowed onramp
        auth::apply_allowed_onramp_updates(
            owner,
            vector[], // onramps_to_remove
            vector[signer::address_of(ccip_onramp)] // onramps_to_add
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
            vector[1000], // source_usd_per_token
            vector[DEST_CHAIN_SELECTOR], // gas_dest_chain_selectors
            vector[0] // gas_usd_per_unit_gas
        );

        (owner_addr, token_obj)
    }

    fun create_test_token_and_pool(
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        pool_type: u8, // 0 for burn_mint, 1 for lock_release
        seed: vector<u8>,
        ccip_onramp_signer: &signer,
        is_dispatchable: bool,
        generate_transfer_ref: bool
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

        // Add dynamic dispatch function to the token if it is dispatchable
        if (is_dispatchable) {
            mock_token::add_dynamic_dispatch_function(
                ccip_onramp_signer, &constructor_ref
            );
        };

        let metadata = object::object_from_constructor_ref(&constructor_ref);

        let obj_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref =
            if (generate_transfer_ref) {
                option::some(fungible_asset::generate_transfer_ref(&constructor_ref))
            } else {
                option::none()
            };

        // ======================== Create token pool ========================
        let token_addr = object::object_address(&metadata);

        let remote_token_address = vector[];
        eth_abi::encode_address(&mut remote_token_address, MOCK_EVM_ADDRESS);

        if (pool_type == BURN_MINT_TOKEN_POOL) {
            burn_mint_token_pool::test_init_module(burn_mint_token_pool);
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
            lock_release_token_pool::test_init_module(lock_release_token_pool);
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

    fun init_timestamp(aptos_framework: &signer, timestamp_seconds: u64) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp_seconds);
    }

    fun create_valid_extra_args(): vector<u8> {
        let extra_args = vector[];
        vector::append(&mut extra_args, GENERIC_EXTRA_ARGS_V2_TAG);
        vector::append(&mut extra_args, bcs::to_bytes(&(GAS_LIMIT as u256)));
        vector::append(&mut extra_args, bcs::to_bytes(&ALLOW_OUT_OF_ORDER_EXECUTION));
        extra_args
    }
}
