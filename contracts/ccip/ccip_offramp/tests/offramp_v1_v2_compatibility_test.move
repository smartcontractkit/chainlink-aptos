#[test_only]
/// Verifies V1 → V2 migration path and that both can coexist
module ccip_offramp::offramp_v1_v2_compatibility_test {
    use std::signer;
    use std::object;
    use std::primary_fungible_store;
    use std::timestamp;

    use ccip_offramp::offramp;
    use ccip_offramp::offramp_test;
    use ccip_offramp::mock_ccip_receiver;
    use ccip::receiver_registry;
    use ccip::token_admin_registry;
    use ccip::merkle_proof;

    use burn_mint_token_pool::upgrade_v2;

    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;
    const BURN_MINT_TOKEN_SEED: vector<u8> = b"TestToken";
    const LOCK_RELEASE_TOKEN_SEED: vector<u8> = b"LockReleaseToken";
    const EVM_SOURCE_CHAIN_SELECTOR: u64 = 909606746561742123;
    const DEST_CHAIN_SELECTOR: u64 = 743186221051783445;
    const MOCK_EVM_ADDRESS_VECTOR: vector<u8> = x"4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97";
    const MOCK_EVM_ADDRESS_VECTOR_2: vector<u8> = x"1234567890abcdef1234567890abcdef12345678";
    const ONRAMP_ADDRESS: vector<u8> = x"47a1f0a819457f01153f35c6b6b0d42e2e16e91e";

    // ============================================
    // Test Helper Functions
    // ============================================
    fun create_and_execute_message(
        message_id: vector<u8>,
        sequence_number: u64,
        receiver: address,
        data: vector<u8>,
        token_transfers: vector<offramp::Any2AptosTokenTransfer>,
        owner: &signer
    ) {
        // Configure source chain if first message
        if (sequence_number == 0) {
            offramp::apply_source_chain_config_updates(
                owner,
                vector[EVM_SOURCE_CHAIN_SELECTOR],
                vector[true], // is_enabled
                vector[true], // is_rmn_verification_disabled
                vector[ONRAMP_ADDRESS]
            );
        };

        let nonce: u64 = 0;
        let sender = x"d87929a32cf0cbdc9e2d07ffc7c33344079de727";
        let gas_limit: u256 = 100000;

        let header =
            offramp::test_create_ramp_message_header(
                message_id,
                EVM_SOURCE_CHAIN_SELECTOR,
                DEST_CHAIN_SELECTOR,
                sequence_number,
                nonce
            );

        // Create offchain_token_data: one empty vector per token transfer
        let num_tokens = token_transfers.length();
        let offchain_token_data: vector<vector<u8>> = vector[];
        let i = 0;
        while (i < num_tokens) {
            offchain_token_data.push_back(vector[]);
            i = i + 1;
        };

        let message =
            offramp::test_create_any2aptos_ramp_message(
                header,
                sender,
                data,
                receiver,
                gas_limit,
                token_transfers
            );

        let metadata_hash =
            offramp::test_calculate_metadata_hash(
                EVM_SOURCE_CHAIN_SELECTOR, DEST_CHAIN_SELECTOR, ONRAMP_ADDRESS
            );

        let hashed_leaf = offramp::test_calculate_message_hash(&message, metadata_hash);
        let proofs = vector[];
        let root = merkle_proof::merkle_root(hashed_leaf, proofs);

        // Commit root (with timestamp in the past to allow execution)
        offramp::test_add_root(root, timestamp::now_seconds() - 3700);

        let execution_report =
            offramp::test_create_execution_report(
                EVM_SOURCE_CHAIN_SELECTOR,
                message,
                offchain_token_data,
                vector[]
            );

        offramp::test_execute_single_report(execution_report);

        // Verify execution state is SUCCESS (2)
        let execution_state =
            offramp::get_execution_state(EVM_SOURCE_CHAIN_SELECTOR, sequence_number);
        assert!(execution_state == 2);
    }

    // ============================================
    // Test 1: V1 Receiver Works (Baseline)
    // ============================================
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
    fun test_v1_receiver_works(
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
        // Setup with V1 pool (use_v1_init = true)
        let (_owner_addr, token_obj) =
            offramp_test::setup(
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
                true // use_v1_init
            );

        // Setup receiver (need receiver_registry initialized)
        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_state_only(ccip_offramp);

        // Register as V1 (dispatchable FA mode)
        mock_ccip_receiver::register_as_v1(ccip_offramp);

        // Verify V1 receiver registered (not V2)
        assert!(
            !receiver_registry::is_registered_receiver_v2(
                signer::address_of(ccip_offramp)
            )
        );
        assert!(
            receiver_registry::is_registered_receiver(signer::address_of(ccip_offramp))
        );

        // Pool is V1-only (test_init_v1 was called in setup)
        // No public function to verify V1 pool registration, but successful execution proves it works
        assert!(
            !token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        let token_addr = object::object_address(&token_obj);
        let token_amount = 1000;

        // Create token transfer
        let token_transfer =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR, // source_pool_address
                token_addr, // dest_token_address
                1000000, // dest_gas_amount
                vector[], // extra_data
                (token_amount as u256) // amount
            );

        // Execute message with tokens
        create_and_execute_message(
            x"0001",
            0,
            signer::address_of(ccip_offramp),
            vector[], // no data, just tokens
            vector[token_transfer],
            owner
        );

        // Verify tokens received by V1 receiver
        let receiver_balance =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(receiver_balance == token_amount);

        // Verify V1 receiver callback was invoked via dispatchable FA
        let events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(events.length() == 1);
    }

    // ============================================
    // Test 2: V1 → V2 Migration Works
    // ============================================
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
    fun test_v1_to_v2_migration(
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
        // Setup with V1 pool (use_v1_init = true)
        let (_owner_addr, token_obj) =
            offramp_test::setup(
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
                true // use_v1_init
            );

        // Setup receiver (need receiver_registry initialized)
        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_state_only(ccip_offramp);

        // STEP 1: Register as V1
        mock_ccip_receiver::register_as_v1(ccip_offramp);
        assert!(
            !receiver_registry::is_registered_receiver_v2(
                signer::address_of(ccip_offramp)
            )
        );
        assert!(
            receiver_registry::is_registered_receiver(signer::address_of(ccip_offramp))
        );

        let token_addr = object::object_address(&token_obj);
        let token_amount = 1000;

        // Execute message with V1 registration
        let token_transfer_v1 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                (token_amount as u256)
            );

        create_and_execute_message(
            x"0002",
            0,
            signer::address_of(ccip_offramp),
            vector[],
            vector[token_transfer_v1],
            owner
        );

        // Verify V1 worked
        let balance_after_v1 =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(balance_after_v1 == token_amount);

        // STEP 2: Upgrade pool to V2 (realistic upgrade pattern)
        upgrade_v2::test_init_module(burn_mint_token_pool);

        // STEP 3: Migrate receiver to V2
        mock_ccip_receiver::migrate_to_v2(ccip_offramp);

        // Verify V2 is now active (V2 registration exists)
        assert!(
            receiver_registry::is_registered_receiver_v2(signer::address_of(ccip_offramp))
        );

        // Execute message with V2 registration (dispatcher should prefer V2)
        let token_transfer_v2 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                (token_amount as u256)
            );

        create_and_execute_message(
            x"0003",
            1,
            signer::address_of(ccip_offramp),
            vector[],
            vector[token_transfer_v2],
            owner
        );

        // Verify V2 worked - should now have 2x token_amount
        let balance_after_v2 =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(balance_after_v2 == token_amount * 2);

        // Verify both V1 and V2 callbacks were invoked
        let events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(events.length() == 2); // 1 from V1 execution, 1 from V2 execution
    }

    // ============================================
    // Test 3: Direct V2 Registration Works
    // ============================================
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
    fun test_v2_receiver_direct(
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
        // Setup with V1 pool initially (use_v1_init = true)
        let (_owner_addr, token_obj) =
            offramp_test::setup(
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
                true // use_v1_init
            );

        // Upgrade pool to V2 immediately (realistic new deployment with V2)
        upgrade_v2::test_init_module(burn_mint_token_pool);

        // Setup V2 receiver directly (default behavior)
        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_module(ccip_offramp);

        // Verify V2 receiver registered
        assert!(
            receiver_registry::is_registered_receiver_v2(signer::address_of(ccip_offramp))
        );

        // Verify V2 pool registered
        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        let token_addr = object::object_address(&token_obj);
        let token_amount = 1000;

        // Create token transfer
        let token_transfer =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                (token_amount as u256)
            );

        // Execute message with tokens
        create_and_execute_message(
            x"0004",
            0,
            signer::address_of(ccip_offramp),
            vector[],
            vector[token_transfer],
            owner
        );

        // Verify tokens received by V2 receiver
        let receiver_balance =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(receiver_balance == token_amount);

        // Verify V2 receiver callback was invoked
        let events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(events.length() == 1);
    }

    // ============================================
    // Test 4: Dispatcher Routes Correctly
    // ============================================
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
    fun test_dispatcher_routing(
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
        // Setup with V1 pool initially (use_v1_init = true)
        let (_owner_addr, token_obj) =
            offramp_test::setup(
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
                true // use_v1_init
            );

        // Upgrade pool to V2 before testing (mixed V1 receiver + V2 pool scenario)
        upgrade_v2::test_init_module(burn_mint_token_pool);

        // Setup receiver (need receiver_registry initialized)
        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_state_only(ccip_offramp);

        let token_addr = object::object_address(&token_obj);
        let token_amount = 500;

        // Phase 1: Register V1, verify dispatcher uses V1 path
        mock_ccip_receiver::register_as_v1(ccip_offramp);
        assert!(
            !receiver_registry::is_registered_receiver_v2(
                signer::address_of(ccip_offramp)
            )
        );

        let token_transfer_1 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                (token_amount as u256)
            );

        create_and_execute_message(
            x"0005",
            0,
            signer::address_of(ccip_offramp),
            vector[],
            vector[token_transfer_1],
            owner
        );

        let balance_1 =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(balance_1 == token_amount);

        // Phase 2: Add V2 registration, verify dispatcher now uses V2 path
        mock_ccip_receiver::migrate_to_v2(ccip_offramp);
        assert!(
            receiver_registry::is_registered_receiver_v2(signer::address_of(ccip_offramp))
        );

        let token_transfer_2 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR,
                token_addr,
                1000000,
                vector[],
                (token_amount as u256)
            );

        create_and_execute_message(
            x"0006",
            1,
            signer::address_of(ccip_offramp),
            vector[],
            vector[token_transfer_2],
            owner
        );

        // Should have received both transfers
        let balance_2 =
            primary_fungible_store::balance(signer::address_of(ccip_offramp), token_obj);
        assert!(balance_2 == token_amount * 2);

        // Both callbacks should have been invoked
        let events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(events.length() == 2);
    }

    // ============================================
    // Test 5: Multi-Transfer Message with V2 Receiver
    // Tests V2 receiver handling multiple token transfers in a single message
    // ============================================
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
    fun test_multi_token_v2_receiver(
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
        // Setup first pool: burn_mint with V2
        let (_owner_addr, token_obj_1) =
            offramp_test::setup(
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
                false // use_v1_init = false (V2 from start)
            );

        let token_addr_1 = object::object_address(&token_obj_1);

        receiver_registry::init_module_for_testing(owner);
        mock_ccip_receiver::test_init_module(ccip_offramp);

        assert!(
            receiver_registry::is_registered_receiver_v2(signer::address_of(ccip_offramp))
        );

        // Verify pool has V2 config
        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        // Create 2 token transfers of the same token
        // This tests that V2 receiver can handle multiple transfers in one message
        // and that pool closures can be invoked multiple times sequentially
        let token_amount_1 = 1000;
        let token_amount_2 = 2000;

        let token_transfer_1 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR, // source_pool_address
                token_addr_1, // dest_token_address
                1000000, // dest_gas_amount
                vector[], // extra_data
                (token_amount_1 as u256) // amount
            );

        let token_transfer_2 =
            offramp::test_create_any2aptos_token_transfer(
                MOCK_EVM_ADDRESS_VECTOR, // same source_pool_address
                token_addr_1, // dest_token_address (same token)
                1000000, // dest_gas_amount
                vector[], // extra_data
                (token_amount_2 as u256) // amount
            );

        // Execute message with 2 transfers
        create_and_execute_message(
            x"0007", // unique message_id
            0, // sequence_number
            signer::address_of(ccip_offramp), // receiver
            vector[], // no data, just tokens
            vector[token_transfer_1, token_transfer_2], // 2 token transfers
            owner
        );

        // Verify BOTH 2 transfers were received (total amount = amount_1 + amount_2)
        let total_balance =
            primary_fungible_store::balance(
                signer::address_of(ccip_offramp), token_obj_1
            );
        assert!(
            total_balance == token_amount_1 + token_amount_2
        );

        // Verify V2 receiver callback was invoked once with multiple tokens
        // The mock receiver's ccip_receive_v2 handles multiple tokens in a loop
        // and emits a single ReceivedTokensOnly event
        let events = mock_ccip_receiver::get_received_tokens_only_events();
        assert!(events.length() == 1);
    }
}
