#[test_only]
/// Verifies V1 → V2 migration path and that both can coexist
module ccip_onramp::onramp_v1_v2_pool_compatibility_test {
    use std::signer;
    use std::object;
    use std::primary_fungible_store;

    use ccip::client;
    use ccip::token_admin_registry;
    use ccip::eth_abi;
    use ccip_onramp::onramp;

    use burn_mint_token_pool::burn_mint_token_pool;
    use burn_mint_token_pool::upgrade_v2 as burn_mint_upgrade_v2;
    use lock_release_token_pool::lock_release_token_pool;
    use lock_release_token_pool::upgrade_v2 as lock_release_upgrade_v2;

    use ccip_onramp::onramp_test;

    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const TOKEN_AMOUNT: u64 = 5000;

    const SENDER: address = @0x500;

    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;

    const BURN_MINT_TOKEN_SEED: vector<u8> = b"TestToken";
    const LOCK_RELEASE_TOKEN_SEED: vector<u8> = b"LockReleaseToken";

    const MOCK_EVM_ADDRESS: address = @0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97;

    const GAS_LIMIT: u64 = 5000000;
    const ALLOW_OUT_OF_ORDER_EXECUTION: bool = true;

    fun create_extra_args_v2(): vector<u8> {
        client::encode_generic_extra_args_v2(
            GAS_LIMIT as u256, ALLOW_OUT_OF_ORDER_EXECUTION
        )
    }

    fun encode_receiver(): vector<u8> {
        let receiver = vector[];
        eth_abi::encode_address(&mut receiver, MOCK_EVM_ADDRESS);
        receiver
    }

    /// Helper to calculate fee and mint enough tokens for sender
    fun mint_tokens_for_transfer(token_addr: address, num_transfers: u64) {
        let receiver = encode_receiver();
        let extra_args = create_extra_args_v2();

        // Calculate fee for one transfer
        let fee_amount =
            onramp::get_fee(
                DEST_CHAIN_SELECTOR,
                receiver,
                vector[], // data
                vector[token_addr],
                vector[TOKEN_AMOUNT],
                vector[@0x0],
                token_addr,
                @0x0,
                extra_args
            );

        // Mint enough for transfers + fees
        let total_needed = (TOKEN_AMOUNT + fee_amount) * num_transfers;
        onramp_test::mint_test_tokens(token_addr, SENDER, total_needed);
    }

    // ============================================
    // Test 1: V1 Burn/Mint Pool Baseline
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v1_burn_mint_pool_baseline(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                BURN_MINT_TOKEN_SEED,
                false, // is_dispatchable
                true // use_v1_init
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for transfer + fees
        mint_tokens_for_transfer(token_addr, 1);

        // Verify V1 pool registered (not V2)
        assert!(
            !token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        // Send tokens via onramp
        let sender_balance_before = primary_fungible_store::balance(SENDER, token_obj);

        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[], // data
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0], // token_store_addresses - use primary store
            token_addr, // fee_token
            @0x0, // fee_token_store - use primary store
            create_extra_args_v2()
        );

        // Verify tokens were burned from sender
        let sender_balance_after = primary_fungible_store::balance(SENDER, token_obj);
        assert!(
            sender_balance_before - sender_balance_after >= TOKEN_AMOUNT
        );

        // Verify V1 callback worked - check events
        let events =
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            );
        assert!(events.length() >= 1);
    }

    // ============================================
    // Test 2: V1 → V2 Burn/Mint Migration
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v1_to_v2_burn_mint_migration(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                BURN_MINT_TOKEN_SEED,
                false, // is_dispatchable
                true // use_v1_init
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for 2 transfers + fees
        mint_tokens_for_transfer(token_addr, 2);

        // STEP 1: Send with V1 pool
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V1 callback worked
        let events_before =
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            );
        assert!(events_before.length() == 1);

        // STEP 2: Upgrade to V2
        burn_mint_upgrade_v2::test_init_module(burn_mint_token_pool);

        // Verify V2 config now exists
        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        // STEP 3: Send with V2 pool
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V2 callback worked
        let events_after =
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            );
        assert!(events_after.length() == 2);
    }

    // ============================================
    // Test 3: V2 Burn/Mint Direct (no migration)
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v2_burn_mint_direct(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                BURN_MINT_TOKEN_POOL,
                BURN_MINT_TOKEN_SEED,
                false, // is_dispatchable
                false // use_v2_init (V2)
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for transfer + fees
        mint_tokens_for_transfer(token_addr, 1);

        // Verify V2 config registered (already done by setup)
        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(burn_mint_token_pool)
            )
        );

        // Send message using V2 pool
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V2 callback worked
        let events =
            burn_mint_token_pool::get_locked_or_burned_events(
                burn_mint_token_pool::get_store_address()
            );
        assert!(events.length() == 1);
    }

    // ============================================
    // Test 4: V1 Lock/Release Pool Baseline
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v1_lock_release_pool_baseline(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                LOCK_RELEASE_TOKEN_SEED,
                false, // is_dispatchable
                true // use_v1_init
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for transfer + fees
        mint_tokens_for_transfer(token_addr, 1);

        // Verify V1 pool registered (not V2)
        assert!(
            !token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(lock_release_token_pool)
            )
        );

        // Send tokens via onramp
        let sender_balance_before = primary_fungible_store::balance(SENDER, token_obj);

        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify tokens were locked from sender
        let sender_balance_after = primary_fungible_store::balance(SENDER, token_obj);
        assert!(
            sender_balance_before - sender_balance_after >= TOKEN_AMOUNT
        );

        // Verify V1 callback worked - check events
        let events =
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            );
        assert!(events.length() >= 1);
    }

    // ============================================
    // Test 5: V1 → V2 Lock/Release Migration
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v1_to_v2_lock_release_migration(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                LOCK_RELEASE_TOKEN_SEED,
                false, // is_dispatchable
                true // use_v1_init
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for 2 transfers + fees
        mint_tokens_for_transfer(token_addr, 2);

        // STEP 1: Send with V1
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V1 callback worked
        let events_before =
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            );
        assert!(events_before.length() == 1);

        // STEP 2: Upgrade to V2
        lock_release_upgrade_v2::test_init_module(lock_release_token_pool);

        // Verify V2 config now exists
        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(lock_release_token_pool)
            )
        );

        // STEP 3: Send with V2 pool
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V2 callback worked
        let events_after =
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            );
        assert!(events_after.length() == 2);
    }

    // ============================================
    // Test 6: V2 Lock/Release Direct (no migration)
    // ============================================
    #[
        test(
            aptos_framework = @aptos_framework,
            router = @0x200,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool,
            sender = @0x500
        )
    ]
    fun test_v2_lock_release_direct(
        aptos_framework: &signer,
        router: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        sender: &signer
    ) {
        let (_owner_addr, token_obj) =
            onramp_test::setup(
                aptos_framework,
                router,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                LOCK_RELEASE_TOKEN_POOL,
                LOCK_RELEASE_TOKEN_SEED,
                false, // is_dispatchable
                false // use_v2_init (V2)
            );

        let token_addr = object::object_address(&token_obj);

        // Fund sender with enough tokens for transfer + fees
        mint_tokens_for_transfer(token_addr, 1);

        assert!(
            token_admin_registry::has_token_pool_registration_v2(
                signer::address_of(lock_release_token_pool)
            )
        );

        // Send message using V2 pool
        onramp::ccip_send(
            router,
            sender,
            DEST_CHAIN_SELECTOR,
            encode_receiver(),
            vector[],
            vector[token_addr],
            vector[TOKEN_AMOUNT],
            vector[@0x0],
            token_addr,
            @0x0,
            create_extra_args_v2()
        );

        // Verify V2 callback worked
        let events =
            lock_release_token_pool::get_locked_or_burned_events(
                lock_release_token_pool::get_store_address()
            );
        assert!(events.length() == 1);
    }
}
