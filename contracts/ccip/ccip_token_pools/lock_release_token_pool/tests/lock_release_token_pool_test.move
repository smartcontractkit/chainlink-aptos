#[test_only]
module lock_release_token_pool::lock_release_token_pool_test {
    use std::signer;
    use std::string::{utf8};
    use std::option::{Self, Option};
    use std::fungible_asset::{Self, Metadata};
    use std::primary_fungible_store;
    use std::object::{Self, Object, ObjectCore};

    use lock_release_token_pool::lock_release_token_pool;
    use ccip::state_object;
    use ccip::token_admin_registry;
    use ccip::auth;

    const INITIAL_LIQUIDITY: u64 = 1000000; // 1M tokens
    const TRANSFER_AMOUNT: u64 = 500000; // 500K tokens
    const WITHDRAW_AMOUNT: u64 = 300000; // 300K tokens
    const SMALL_AMOUNT: u64 = 100;
    const LARGE_AMOUNT: u64 = 200;
    const MAX_SUPPLY: u64 = 1000000000;

    const E_UNAUTHORIZED: u64 = 8;
    const E_INSUFFICIENT_LIQUIDITY: u64 = 9;

    struct TestRefs has key {
        mint_ref: fungible_asset::MintRef,
        transfer_ref: Option<fungible_asset::TransferRef>
    }

    fun setup_test_environment(
        owner: &signer, ccip: &signer, lock_release_token_pool: &signer
    ): Object<Metadata> {
        // Create required objects
        create_named_objects(owner);

        // Create token with primary store enabled
        let token_metadata = create_test_token(owner);

        // Initialize all required modules
        initialize_modules(ccip, owner, lock_release_token_pool);

        token_metadata
    }

    fun create_named_objects(owner: &signer) {
        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        // Create object for @burn_mint_token_pool
        let _constructor_ref = object::create_named_object(
            owner, b"burn_mint_token_pool"
        );

        // Create object for @lock_release_token_pool
        let _constructor_ref =
            object::create_named_object(owner, b"lock_release_token_pool");

        // Create object for @ccip_token_pool and transfer ownership
        let constructor_ref = object::create_named_object(owner, b"ccip_token_pool");
        let ccip_token_pool_obj =
            object::object_from_constructor_ref<ObjectCore>(&constructor_ref);
        object::transfer(owner, ccip_token_pool_obj, @lock_release_token_pool);
    }

    fun create_test_token(owner: &signer): Object<Metadata> {
        let token_constructor_ref =
            object::create_named_object(owner, b"LockReleaseToken");

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &token_constructor_ref,
            option::some(1000000000), // max supply
            utf8(b"Test Token"),
            utf8(b"TEST"),
            8, // decimals
            utf8(b""),
            utf8(b"")
        );

        let token_metadata =
            object::object_from_constructor_ref<Metadata>(&token_constructor_ref);
        let token_signer = &object::generate_signer(&token_constructor_ref);
        let mint_ref = fungible_asset::generate_mint_ref(&token_constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&token_constructor_ref);

        move_to(
            token_signer,
            TestRefs {
                mint_ref,
                transfer_ref: option::some(transfer_ref)
            }
        );

        token_metadata
    }

    fun initialize_modules(
        ccip: &signer, owner: &signer, lock_release_token_pool: &signer
    ) {
        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        token_admin_registry::init_module_for_testing(ccip);
        lock_release_token_pool::test_init_module(lock_release_token_pool);
    }

    fun mint_tokens_to_address(
        token_metadata: Object<Metadata>, to: address, amount: u64
    ) acquires TestRefs {
        let refs = borrow_global<TestRefs>(object::object_address(&token_metadata));
        let tokens = fungible_asset::mint(&refs.mint_ref, amount);
        let store =
            primary_fungible_store::ensure_primary_store_exists(to, token_metadata);
        fungible_asset::deposit(store, tokens);
    }

    fun initialize_pool_with_rebalancer(
        owner: &signer, rebalancer_addr: address
    ) {
        lock_release_token_pool::initialize(owner, option::none(), rebalancer_addr);
    }

    fun setup_pool_with_liquidity(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        liquidity_amount: u64
    ): Object<Metadata> acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        initialize_pool_with_rebalancer(owner, rebalancer_addr);
        mint_tokens_to_address(token_metadata, rebalancer_addr, liquidity_amount);
        lock_release_token_pool::provide_liquidity(rebalancer, liquidity_amount);

        token_metadata
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_provide_liquidity_success(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        initialize_pool_with_rebalancer(owner, rebalancer_addr);
        mint_tokens_to_address(token_metadata, rebalancer_addr, INITIAL_LIQUIDITY * 2);
        lock_release_token_pool::provide_liquidity(rebalancer, INITIAL_LIQUIDITY);

        assert!(lock_release_token_pool::balance() == INITIAL_LIQUIDITY);

        let rebalancer_store =
            primary_fungible_store::primary_store(rebalancer_addr, token_metadata);
        assert!(fungible_asset::balance(rebalancer_store) == INITIAL_LIQUIDITY);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            user = @0x456
        )
    ]
    #[
        expected_failure(
            abort_code = E_UNAUTHORIZED,
            location = lock_release_token_pool::lock_release_token_pool
        )
    ]
    fun test_provide_liquidity_unauthorized(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        user: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);
        let user_addr = signer::address_of(user);

        initialize_pool_with_rebalancer(owner, rebalancer_addr);
        mint_tokens_to_address(token_metadata, user_addr, INITIAL_LIQUIDITY);

        lock_release_token_pool::provide_liquidity(user, INITIAL_LIQUIDITY);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_withdraw_liquidity_success(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        let token_metadata =
            setup_pool_with_liquidity(
                owner,
                ccip,
                lock_release_token_pool,
                rebalancer,
                INITIAL_LIQUIDITY * 2
            );
        let rebalancer_addr = signer::address_of(rebalancer);

        lock_release_token_pool::withdraw_liquidity(rebalancer, WITHDRAW_AMOUNT);

        assert!(
            lock_release_token_pool::balance()
                == INITIAL_LIQUIDITY * 2 - WITHDRAW_AMOUNT
        );

        let rebalancer_store =
            primary_fungible_store::primary_store(rebalancer_addr, token_metadata);
        let expected_balance = WITHDRAW_AMOUNT; // Withdrew amount back to rebalancer
        assert!(fungible_asset::balance(rebalancer_store) == expected_balance);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            user = @0x456
        )
    ]
    #[
        expected_failure(
            abort_code = E_UNAUTHORIZED,
            location = lock_release_token_pool::lock_release_token_pool
        )
    ]
    fun test_withdraw_liquidity_unauthorized(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        user: &signer
    ) acquires TestRefs {
        setup_pool_with_liquidity(
            owner,
            ccip,
            lock_release_token_pool,
            rebalancer,
            INITIAL_LIQUIDITY
        );

        lock_release_token_pool::withdraw_liquidity(user, WITHDRAW_AMOUNT);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    #[
        expected_failure(
            abort_code = E_INSUFFICIENT_LIQUIDITY,
            location = lock_release_token_pool::lock_release_token_pool
        )
    ]
    fun test_withdraw_liquidity_insufficient_balance(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        setup_pool_with_liquidity(
            owner,
            ccip,
            lock_release_token_pool,
            rebalancer,
            SMALL_AMOUNT
        );

        lock_release_token_pool::withdraw_liquidity(rebalancer, LARGE_AMOUNT);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            new_rebalancer = @0x789
        )
    ]
    fun test_set_rebalancer_success(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        new_rebalancer: &signer
    ) {
        setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);
        let new_rebalancer_addr = signer::address_of(new_rebalancer);

        initialize_pool_with_rebalancer(owner, rebalancer_addr);
        assert!(lock_release_token_pool::get_rebalancer() == rebalancer_addr);

        lock_release_token_pool::set_rebalancer(owner, new_rebalancer_addr);
        assert!(lock_release_token_pool::get_rebalancer() == new_rebalancer_addr);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_set_rebalancer_to_zero_address(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) {
        setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        initialize_pool_with_rebalancer(owner, rebalancer_addr);
        lock_release_token_pool::set_rebalancer(owner, @0x0);

        assert!(lock_release_token_pool::get_rebalancer() == @0x0);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            user = @0x456
        )
    ]
    fun test_rebalancer_operations_after_change(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        user: &signer
    ) acquires TestRefs {
        let _token_metadata =
            setup_pool_with_liquidity(
                owner,
                ccip,
                lock_release_token_pool,
                rebalancer,
                INITIAL_LIQUIDITY
            );
        let user_addr = signer::address_of(user);

        lock_release_token_pool::set_rebalancer(owner, user_addr);
        lock_release_token_pool::withdraw_liquidity(user, WITHDRAW_AMOUNT);

        assert!(
            lock_release_token_pool::balance() == INITIAL_LIQUIDITY - WITHDRAW_AMOUNT
        );
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_liquidity_operations_with_disabled_rebalancer(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        setup_pool_with_liquidity(
            owner,
            ccip,
            lock_release_token_pool,
            rebalancer,
            INITIAL_LIQUIDITY
        );

        lock_release_token_pool::set_rebalancer(owner, @0x0);

        assert!(lock_release_token_pool::balance() == INITIAL_LIQUIDITY);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            user = @0x456
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip_token_pool::ownable)]
    fun test_set_rebalancer_to_zero_address_unauthorized(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        user: &signer
    ) {
        setup_test_environment(owner, ccip, lock_release_token_pool);
        let user_addr = signer::address_of(user);

        initialize_pool_with_rebalancer(owner, user_addr);

        // Error E_ONLY_CALLABLE_BY_OWNER
        lock_release_token_pool::set_rebalancer(user, @0x0);
    }

    fun extract_transfer_ref(
        token_metadata: Object<Metadata>
    ): fungible_asset::TransferRef acquires TestRefs {
        let refs = borrow_global_mut<TestRefs>(object::object_address(&token_metadata));
        option::extract(&mut refs.transfer_ref)
    }

    // ============ Migrate Transfer Ref Tests ============
    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_migrate_transfer_ref_success(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        let transfer_ref = extract_transfer_ref(token_metadata);
        // Initialize pool with the transfer ref
        lock_release_token_pool::initialize(
            owner, option::some(transfer_ref), rebalancer_addr
        );

        // Verify the pool was initialized with transfer ref
        // We can test this indirectly by checking that liquidity operations work
        mint_tokens_to_address(token_metadata, rebalancer_addr, INITIAL_LIQUIDITY);
        lock_release_token_pool::provide_liquidity(rebalancer, INITIAL_LIQUIDITY);

        assert!(lock_release_token_pool::balance() == INITIAL_LIQUIDITY);

        // Now migrate (extract) the transfer ref
        let extracted_transfer_ref = lock_release_token_pool::migrate_transfer_ref(owner);

        // Verify the transfer ref was extracted by checking we can still use it
        // The extracted transfer ref should still be valid for operations
        let store1 =
            primary_fungible_store::ensure_primary_store_exists(
                rebalancer_addr, token_metadata
            );
        // Fund store1 with tokens
        let transfer_amount = 100;
        let mint_ref =
            &borrow_global<TestRefs>(object::object_address(&token_metadata)).mint_ref;
        let tokens = fungible_asset::mint(mint_ref, transfer_amount);
        fungible_asset::deposit(store1, tokens);

        let store2 =
            primary_fungible_store::ensure_primary_store_exists(@0x999, token_metadata);

        // This should work with the extracted transfer ref
        fungible_asset::transfer_with_ref(
            &extracted_transfer_ref,
            store1,
            store2,
            transfer_amount
        );
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    #[expected_failure(
        abort_code = 10, location = lock_release_token_pool::lock_release_token_pool
    )]
    fun test_migrate_transfer_ref_not_set(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) {
        let _token_metadata = setup_test_environment(
            owner, ccip, lock_release_token_pool
        );
        let rebalancer_addr = signer::address_of(rebalancer);

        // Initialize pool without transfer ref
        lock_release_token_pool::initialize(
            owner, option::none(), // No transfer ref
            rebalancer_addr
        );

        // This should fail with E_TRANSFER_REF_NOT_SET
        lock_release_token_pool::migrate_transfer_ref(owner);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            user = @0x456
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip_token_pool::ownable)]
    fun test_migrate_transfer_ref_unauthorized(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        user: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        // Create a transfer ref for the token
        let transfer_ref = extract_transfer_ref(token_metadata);

        // Initialize pool with the transfer ref
        lock_release_token_pool::initialize(
            owner, option::some(transfer_ref), rebalancer_addr
        );

        // Try to migrate as non-owner (should fail with E_ONLY_CALLABLE_BY_OWNER)
        lock_release_token_pool::migrate_transfer_ref(user);
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_pool_operations_after_transfer_ref_migration(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        // Create a transfer ref for the token
        let transfer_ref = extract_transfer_ref(token_metadata);

        // Initialize pool with the transfer ref
        lock_release_token_pool::initialize(
            owner, option::some(transfer_ref), rebalancer_addr
        );

        // Add some liquidity first
        mint_tokens_to_address(token_metadata, rebalancer_addr, INITIAL_LIQUIDITY);
        lock_release_token_pool::provide_liquidity(rebalancer, INITIAL_LIQUIDITY);

        let extracted_transfer_ref = lock_release_token_pool::migrate_transfer_ref(owner);

        // After migration, the pool should still function but without transfer ref capabilities
        // Liquidity operations should still work (they'll fall back to regular transfers)
        lock_release_token_pool::withdraw_liquidity(rebalancer, WITHDRAW_AMOUNT);

        assert!(
            lock_release_token_pool::balance() == INITIAL_LIQUIDITY - WITHDRAW_AMOUNT
        );

        assert!(
            fungible_asset::transfer_ref_metadata(&extracted_transfer_ref)
                == token_metadata
        );
    }

    // ================================================================
    // |                  Allowlist Tests                             |
    // ================================================================
    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123
        )
    ]
    fun test_set_allowlist_enabled(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        // Create a transfer ref for the token
        let transfer_ref = extract_transfer_ref(token_metadata);

        // Initialize pool with no initial allowlist (disabled by default)
        lock_release_token_pool::initialize(
            owner, option::some(transfer_ref), rebalancer_addr
        );

        // Allowlist should be disabled initially
        assert!(!lock_release_token_pool::get_allowlist_enabled());

        // Enable the allowlist
        lock_release_token_pool::set_allowlist_enabled(owner, true);
        assert!(lock_release_token_pool::get_allowlist_enabled());

        // Disable the allowlist again
        lock_release_token_pool::set_allowlist_enabled(owner, false);
        assert!(!lock_release_token_pool::get_allowlist_enabled());
    }

    #[
        test(
            owner = @0x100,
            ccip = @ccip,
            lock_release_token_pool = @lock_release_token_pool,
            rebalancer = @0x123,
            unauthorized = @0x456
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip_token_pool::ownable)]
    fun test_set_allowlist_enabled_unauthorized(
        owner: &signer,
        ccip: &signer,
        lock_release_token_pool: &signer,
        rebalancer: &signer,
        unauthorized: &signer
    ) acquires TestRefs {
        let token_metadata = setup_test_environment(owner, ccip, lock_release_token_pool);
        let rebalancer_addr = signer::address_of(rebalancer);

        // Create a transfer ref for the token
        let transfer_ref = extract_transfer_ref(token_metadata);

        // Initialize pool
        lock_release_token_pool::initialize(
            owner, option::some(transfer_ref), rebalancer_addr
        );

        // Try to enable allowlist as non-owner (should fail with E_ONLY_CALLABLE_BY_OWNER)
        lock_release_token_pool::set_allowlist_enabled(unauthorized, true);
    }
}
