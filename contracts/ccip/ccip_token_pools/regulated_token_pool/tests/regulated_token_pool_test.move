#[test_only]
module regulated_token_pool::regulated_token_pool_test {
    use std::signer;
    use std::account;
    use std::object;
    use std::string;
    use std::timestamp;
    use std::option;

    use ccip::state_object;
    use ccip::auth;
    use ccip::token_admin_registry;

    use regulated_token::regulated_token;
    use regulated_token_pool::regulated_token_pool;

    const ADMIN: address = @0x100;
    const POOL_OWNER: address = @0x200;
    const USER1: address = @0x300;
    const TIMESTAMP: u64 = 1744315405;

    fun setup(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        // Create accounts
        account::create_account_for_test(signer::address_of(admin));
        account::create_account_for_test(signer::address_of(regulated_token_pool));
        account::create_account_for_test(USER1);

        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(admin, b"ccip");
        account::create_account_for_test(
            object::address_from_constructor_ref(&_constructor_ref)
        );

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        token_admin_registry::init_module_for_testing(ccip);

        // Create an object at @regulated_token for the ownable functionality
        let regulated_token_pool_constructor_ref =
            object::create_named_object(admin, b"regulated_token_pool");
        account::create_account_for_test(
            object::address_from_constructor_ref(&regulated_token_pool_constructor_ref)
        );

        // Setup regulated token first (use admin as the object creator)
        let regulated_token_constructor_ref =
            object::create_named_object(admin, b"regulated_token");
        account::create_account_for_test(
            object::address_from_constructor_ref(&regulated_token_constructor_ref)
        );

        regulated_token::init_module_for_testing(regulated_token);
        regulated_token::initialize(
            admin,
            option::none(),
            string::utf8(b"Regulated Token"),
            string::utf8(b"RT"),
            6,
            string::utf8(
                b"https://regulatedtoken.com/images/pic.png"
            ),
            string::utf8(b"https://regulatedtoken.com")
        );

        regulated_token_pool::test_init_module(regulated_token_pool);
    }

    // ================================================================
    // |                    Basic Pool Tests                         |
    // ================================================================
    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_pool_initialization(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        // Check that pool was initialized correctly
        let token_address = regulated_token_pool::get_token();
        assert!(token_address == regulated_token::token_address());

        // Check type and version
        let type_version = regulated_token_pool::type_and_version();
        assert!(type_version == string::utf8(b"RegulatedTokenPool 1.6.0"));

        // Check initial ownership
        let owner = regulated_token_pool::owner();
        assert!(owner == signer::address_of(admin));

        // Check allowlist is disabled by default
        assert!(!regulated_token_pool::get_allowlist_enabled());
        assert!(regulated_token_pool::get_allowlist().length() == 0);
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_pool_token_integration(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        // Verify the pool is properly integrated with regulated token
        let token_address = regulated_token_pool::get_token();
        let regulated_token_address = regulated_token::token_address();
        assert!(token_address == regulated_token_address);

        // Check token decimals (regulated token uses 6 decimals)
        let pool_decimals = regulated_token_pool::get_token_decimals();
        assert!(pool_decimals == 6);
    }

    // ================================================================
    // |                    Ownership Tests                          |
    // ================================================================
    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_pool_ownership_transfer(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let initial_owner = regulated_token_pool::owner();
        assert!(initial_owner == signer::address_of(admin));

        // Start ownership transfer
        regulated_token_pool::transfer_ownership(admin, USER1);

        // Should still be original owner until accepted
        assert!(regulated_token_pool::owner() == initial_owner);
        assert!(regulated_token_pool::has_pending_transfer());
        assert!(regulated_token_pool::pending_transfer_to().contains(&USER1));

        // Accept ownership
        let new_owner_signer = account::create_signer_for_test(USER1);
        regulated_token_pool::accept_ownership(&new_owner_signer);

        // Execute transfer
        regulated_token_pool::execute_ownership_transfer(admin, USER1);

        // Now ownership should be transferred
        assert!(regulated_token_pool::owner() == USER1);
        assert!(!regulated_token_pool::has_pending_transfer());
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_chain_management(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        assert!(regulated_token_pool::get_supported_chains().length() == 0);

        let remote_chain_selector = 1000;
        let remote_pool_address = b"remote_pool_address";
        let remote_token_address = x"abcdef";

        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            vector[remote_chain_selector],
            vector[vector[]], // no pools initially
            vector[remote_token_address]
        );

        regulated_token_pool::add_remote_pool(
            admin, remote_chain_selector, remote_pool_address
        );

        assert!(regulated_token_pool::is_supported_chain(remote_chain_selector));
        let supported_chains = regulated_token_pool::get_supported_chains();
        assert!(supported_chains.length() == 1);
        assert!(supported_chains[0] == remote_chain_selector);

        assert!(
            regulated_token_pool::is_remote_pool(
                remote_chain_selector, remote_pool_address
            )
        );

        let remote_pools = regulated_token_pool::get_remote_pools(remote_chain_selector);
        assert!(remote_pools.length() == 1);
        assert!(remote_pools[0] == remote_pool_address);
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure(abort_code = 196609, location = ccip::allowlist)]
    // E_ALLOWLIST_NOT_ENABLED
    fun test_allowlist_updates_fail_when_disabled(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        // Verify allowlist is disabled
        assert!(!regulated_token_pool::get_allowlist_enabled());

        // This should fail because allowlist is disabled
        regulated_token_pool::apply_allowlist_updates(
            admin,
            vector[],
            vector[USER1, ADMIN]
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure]
    fun test_unauthorized_chain_management_fails(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let unauthorized_signer = account::create_signer_for_test(USER1);

        // Non-owner tries to add remote pool - should fail
        regulated_token_pool::add_remote_pool(
            &unauthorized_signer, 1000u64, b"remote_pool"
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure]
    fun test_unauthorized_allowlist_management_fails(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let unauthorized_signer = account::create_signer_for_test(USER1);

        // Non-owner tries to update allowlist - should fail
        regulated_token_pool::apply_allowlist_updates(
            &unauthorized_signer, vector[], vector[USER1]
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure]
    fun test_unauthorized_ownership_transfer_fails(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let unauthorized_signer = account::create_signer_for_test(USER1);

        // Non-owner tries to transfer ownership - should fail
        regulated_token_pool::transfer_ownership(&unauthorized_signer, USER1);
    }

    // ================================================================
    // |                 CCIP Dynamic Dispatch Tests                 |
    // ================================================================
    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_get_store_address_function(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let store_address = regulated_token_pool::get_store_address();

        // Store address should be a valid resource account address
        assert!(store_address != @0x0);
        assert!(store_address != @regulated_token_pool);

        let router_address = regulated_token_pool::get_router();

        assert!(router_address == @ccip);
    }

    // ================================================================
    // |                 Remote Pool Management Tests                |
    // ================================================================
    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_remove_remote_pool_success(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let remote_chain_selector = 1000u64;
        let remote_pool_address = b"remote_pool_address";
        let remote_token_address = x"abcdef";

        // First add a chain and remote pool
        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            vector[remote_chain_selector],
            vector[vector[]], // no pools initially
            vector[remote_token_address]
        );

        regulated_token_pool::add_remote_pool(
            admin, remote_chain_selector, remote_pool_address
        );

        // Verify it was added
        assert!(
            regulated_token_pool::is_remote_pool(
                remote_chain_selector, remote_pool_address
            )
        );

        // Now remove the remote pool
        regulated_token_pool::remove_remote_pool(
            admin, remote_chain_selector, remote_pool_address
        );

        // Verify it was removed
        assert!(
            !regulated_token_pool::is_remote_pool(
                remote_chain_selector, remote_pool_address
            )
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip_token_pool::ownable)]
    fun test_remove_remote_pool_unauthorized_fails(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let unauthorized_signer = account::create_signer_for_test(USER1);

        // Non-owner tries to remove remote pool - should fail
        regulated_token_pool::remove_remote_pool(
            &unauthorized_signer, 1000u64, b"remote_pool"
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_get_remote_token_function(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let remote_chain_selector = 1000u64;
        let remote_token_address = x"abcdef123456";

        // Add a chain with remote token
        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            vector[remote_chain_selector],
            vector[vector[]], // no pools initially
            vector[remote_token_address]
        );

        // Test get_remote_token function
        let retrieved_token =
            regulated_token_pool::get_remote_token(remote_chain_selector);
        assert!(retrieved_token == remote_token_address);
    }

    // ================================================================
    // |                    Rate Limiting Tests                      |
    // ================================================================
    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_rate_limiter_single_config(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let remote_chain_selector = 1000u64;
        let outbound_capacity = 1000000u64;
        let outbound_rate = 10000u64;
        let inbound_capacity = 500000u64;
        let inbound_rate = 5000u64;

        // First add the chain
        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            vector[remote_chain_selector],
            vector[vector[]], // no pools initially
            vector[x"abcd"] // dummy token address
        );

        // Set rate limiter configuration
        regulated_token_pool::set_chain_rate_limiter_config(
            admin,
            remote_chain_selector,
            true, // outbound enabled
            outbound_capacity,
            outbound_rate,
            true, // inbound enabled
            inbound_capacity,
            inbound_rate
        );

        // Test getting rate limiter states - verify functions execute successfully
        let _ =
            regulated_token_pool::get_current_outbound_rate_limiter_state(
                remote_chain_selector
            );
        let _ =
            regulated_token_pool::get_current_inbound_rate_limiter_state(
                remote_chain_selector
            );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_rate_limiter_batch_config(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let chain1 = 1000u64;
        let chain2 = 2000u64;
        let remote_chain_selectors = vector[chain1, chain2];

        // Add both chains first
        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            remote_chain_selectors,
            vector[vector[], vector[]], // no pools initially
            vector[x"abcd", x"ef12"] // dummy token addresses
        );

        // Set batch rate limiter configuration
        regulated_token_pool::set_chain_rate_limiter_configs(
            admin,
            remote_chain_selectors,
            vector[true, false], // outbound enabled flags
            vector[1000000, 2000000], // outbound capacities
            vector[10000, 20000], // outbound rates
            vector[true, true], // inbound enabled flags
            vector[500000, 1000000], // inbound capacities
            vector[5000, 10000] // inbound rates
        );

        // Verify batch configuration executed successfully
        let _ = regulated_token_pool::get_current_outbound_rate_limiter_state(chain1);
        let _ = regulated_token_pool::get_current_outbound_rate_limiter_state(chain2);
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip_token_pool::ownable)]
    fun test_rate_limiter_unauthorized_fails(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        let unauthorized_signer = account::create_signer_for_test(USER1);

        // Non-owner tries to set rate limiter config - should fail
        regulated_token_pool::set_chain_rate_limiter_config(
            &unauthorized_signer,
            1000u64,
            true,
            1000000,
            10000,
            true,
            500000,
            5000
        );
    }

    #[
        test(
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool,
            framework = @aptos_framework,
            ccip = @ccip
        )
    ]
    fun test_pending_transfer_getters(
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer,
        framework: &signer,
        ccip: &signer
    ) {
        setup(
            admin,
            regulated_token,
            regulated_token_pool,
            framework,
            ccip
        );

        // Initially no pending transfer
        assert!(!regulated_token_pool::has_pending_transfer());
        assert!(regulated_token_pool::pending_transfer_from().is_none());
        assert!(regulated_token_pool::pending_transfer_to().is_none());
        assert!(regulated_token_pool::pending_transfer_accepted().is_none());

        // Start ownership transfer
        regulated_token_pool::transfer_ownership(admin, USER1);

        // Now should have pending transfer
        assert!(regulated_token_pool::has_pending_transfer());
        assert!(
            regulated_token_pool::pending_transfer_from().contains(
                &signer::address_of(admin)
            )
        );
        assert!(regulated_token_pool::pending_transfer_to().contains(&USER1));
        assert!(regulated_token_pool::pending_transfer_accepted().contains(&false));

        // Accept the transfer
        let new_owner_signer = account::create_signer_for_test(USER1);
        regulated_token_pool::accept_ownership(&new_owner_signer);

        // Should show accepted
        assert!(regulated_token_pool::pending_transfer_accepted().contains(&true));

        // Execute transfer
        regulated_token_pool::execute_ownership_transfer(admin, USER1);

        // Now should have no pending transfer
        assert!(!regulated_token_pool::has_pending_transfer());
        assert!(regulated_token_pool::pending_transfer_from().is_none());
        assert!(regulated_token_pool::pending_transfer_to().is_none());
        assert!(regulated_token_pool::pending_transfer_accepted().is_none());
    }
}
