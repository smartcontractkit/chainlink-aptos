#[test_only]
module usdc_token_pool::usdc_token_pool_test {
    use std::account;
    use std::object;
    use std::option;
    use std::string;
    use std::timestamp;
    use std::primary_fungible_store;

    use ccip::auth;
    use ccip::state_object;
    use ccip::token_admin_registry;

    use usdc_token_pool::usdc_token_pool;

    use message_transmitter::message_transmitter;
    use token_messenger_minter::token_messenger_minter;

    const TIMESTAMP: u64 = 1744315405;

    inline fun setup(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        create_usdc_token(owner);

        let _constructor_ref = object::create_named_object(owner, b"usdc_token_pool");

        token_admin_registry::init_module_for_testing(ccip);

        initialize_circle_cctp_components(deployer);

        usdc_token_pool::test_init_module(usdc_token_pool);
    }

    inline fun initialize_circle_cctp_components(deployer: &signer) {
        // Initialize Message Transmitter
        message_transmitter::initialize_test_message_transmitter(deployer);

        // Initialize Token Messenger Minter
        token_messenger_minter::initialize_test_token_messenger_minter(
            1, // message_body_version
            std::signer::address_of(deployer) // token_controller
        );
    }

    inline fun create_usdc_token(creator: &signer) {
        let metadata_constructor_ref = &object::create_named_object(
            creator, b"MockUSDC"
        );

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            metadata_constructor_ref,
            option::none(), // max supply
            string::utf8(b"Mock USDC"),
            string::utf8(b"USDC"),
            6, // decimals
            string::utf8(b"https://example.com/icon.png"),
            string::utf8(b"https://example.com")
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_type_and_version(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );

        let expected = string::utf8(b"USDCTokenPool 1.6.0");
        let actual = usdc_token_pool::type_and_version();
        assert!(actual == expected);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_get_store_address(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );

        let store_addr = usdc_token_pool::get_store_address();
        // Store address should be deterministic based on seed
        assert!(store_addr != @0x0);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_domain_management(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Set up domains
        let remote_chain_selectors = vector[1, 2, 3];
        let remote_domain_identifiers = vector[1001, 1002, 1003];
        let allowed_remote_callers = vector[
            x"0102030405060708090a0b0c0d0e0f1011121314",
            x"0203040506070809101112131415161718192021",
            x"030405060708091011121314151617181920212223"
        ];
        let enableds = vector[true, true, false];

        usdc_token_pool::set_domains(
            owner,
            remote_chain_selectors,
            remote_domain_identifiers,
            allowed_remote_callers,
            enableds
        );

        // Test getting domain for enabled chain
        let domain = usdc_token_pool::get_domain(remote_chain_selectors[0]);
        assert!(
            usdc_token_pool::domain_domain_identifier(&domain)
                == remote_domain_identifiers[0]
        );
        assert!(
            usdc_token_pool::domain_allowed_caller(&domain)
                == allowed_remote_callers[0]
        );
        assert!(usdc_token_pool::domain_enabled(&domain) == enableds[0]);

        // Test getting domain for disabled chain
        let domain = usdc_token_pool::get_domain(remote_chain_selectors[2]);
        assert!(
            usdc_token_pool::domain_domain_identifier(&domain)
                == remote_domain_identifiers[2]
        );
        assert!(
            usdc_token_pool::domain_allowed_caller(&domain)
                == allowed_remote_callers[2]
        );
        assert!(usdc_token_pool::domain_enabled(&domain) == enableds[2]);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_chain_support_management(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Test adding chains
        let remote_chain_selectors_to_add = vector[100, 200];
        let remote_pool_addresses_to_add = vector[vector[x"010203"], vector[x"040506"]];
        let remote_token_addresses_to_add = vector[x"0a0b0c", x"0d0e0f"];

        usdc_token_pool::apply_chain_updates(
            owner,
            vector[], // no chains to remove
            remote_chain_selectors_to_add,
            remote_pool_addresses_to_add,
            remote_token_addresses_to_add
        );

        // Test is supported chain
        assert!(usdc_token_pool::is_supported_chain(remote_chain_selectors_to_add[0]));
        assert!(usdc_token_pool::is_supported_chain(remote_chain_selectors_to_add[1]));

        // Test get supported chains
        let supported_chains = usdc_token_pool::get_supported_chains();
        assert!(supported_chains.contains(&remote_chain_selectors_to_add[0]));
        assert!(supported_chains.contains(&remote_chain_selectors_to_add[1]));

        // Test get remote pools
        let remote_pools =
            usdc_token_pool::get_remote_pools(remote_chain_selectors_to_add[0]);
        assert!(
            remote_pools.contains(&remote_pool_addresses_to_add[0][0])
        );

        // Test is remote pool
        assert!(
            usdc_token_pool::is_remote_pool(
                remote_chain_selectors_to_add[0],
                remote_pool_addresses_to_add[0][0]
            )
        );

        // Test get remote token
        let remote_token =
            usdc_token_pool::get_remote_token(remote_chain_selectors_to_add[0]);
        assert!(remote_token == remote_token_addresses_to_add[0]);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_remote_pool_management(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // First add a chain
        let remote_chain_selector = 999;
        let remote_token_address = x"abcdef";

        usdc_token_pool::apply_chain_updates(
            owner,
            vector[], // no chains to remove
            vector[remote_chain_selector],
            vector[vector[]], // no pools initially
            vector[remote_token_address]
        );

        // Test adding remote pool
        let remote_pool_address = x"123456";
        usdc_token_pool::add_remote_pool(
            owner, remote_chain_selector, remote_pool_address
        );

        // Verify pool was added
        assert!(
            usdc_token_pool::is_remote_pool(remote_chain_selector, remote_pool_address)
        );

        // Test removing remote pool
        usdc_token_pool::remove_remote_pool(
            owner, remote_chain_selector, remote_pool_address
        );

        // Verify pool was removed
        assert!(
            !usdc_token_pool::is_remote_pool(remote_chain_selector, remote_pool_address)
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_allowlist_disabled_by_default(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Verify allowlist is disabled by default (initialized with empty vector)
        assert!(!usdc_token_pool::get_allowlist_enabled());
        assert!(usdc_token_pool::get_allowlist().is_empty());
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        ),
        expected_failure(abort_code = 196609, location = ccip::allowlist) // E_ALLOWLIST_NOT_ENABLED
    ]
    fun test_allowlist_updates_fail_when_disabled(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // This should fail because allowlist is disabled by default
        // and there's no way to enable it after initialization // E_ALLOWLIST_NOT_ENABLED
        let addresses_to_add = vector[@0x123, @0x456];
        usdc_token_pool::apply_allowlist_updates(
            owner, vector[], // no removes
            addresses_to_add
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_rate_limiting(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let remote_chain_selector = 1;
        let outbound_is_enabled = true;
        let outbound_capacity = 1000000;
        let outbound_rate = 1000;
        let inbound_is_enabled = true;
        let inbound_capacity = 2000000;
        let inbound_rate = 2000;

        usdc_token_pool::set_chain_rate_limiter_config(
            owner,
            remote_chain_selector,
            outbound_is_enabled,
            outbound_capacity,
            outbound_rate,
            inbound_is_enabled,
            inbound_capacity,
            inbound_rate
        );
        let _outbound_state =
            usdc_token_pool::get_current_outbound_rate_limiter_state(
                remote_chain_selector
            );
        let _inbound_state =
            usdc_token_pool::get_current_inbound_rate_limiter_state(remote_chain_selector);

        let remote_chain_selectors = vector[2, 3];
        let outbound_is_enableds = vector[true, false];
        let outbound_capacities = vector[500000, 750000];
        let outbound_rates = vector[500, 750];
        let inbound_is_enableds = vector[false, true];
        let inbound_capacities = vector[1500000, 1750000];
        let inbound_rates = vector[1500, 1750];

        usdc_token_pool::set_chain_rate_limiter_configs(
            owner,
            remote_chain_selectors,
            outbound_is_enableds,
            outbound_capacities,
            outbound_rates,
            inbound_is_enableds,
            inbound_capacities,
            inbound_rates
        );

        for (i in 0..remote_chain_selectors.length()) {
            let chain_selector = remote_chain_selectors[i];

            let _outbound_state =
                usdc_token_pool::get_current_outbound_rate_limiter_state(chain_selector);
            let _inbound_state =
                usdc_token_pool::get_current_inbound_rate_limiter_state(chain_selector);
        };
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_ownership_management(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let new_owner = @0x999;
        usdc_token_pool::transfer_ownership(owner, new_owner);

        // Check pending transfer
        assert!(usdc_token_pool::has_pending_transfer());

        let pending_transfer_to = usdc_token_pool::pending_transfer_to();
        assert!(option::is_some(&pending_transfer_to));
        assert!(*option::borrow(&pending_transfer_to) == new_owner);

        // Create signer for new owner and accept ownership
        let new_owner_signer = &account::create_signer_for_test(new_owner);
        usdc_token_pool::accept_ownership(new_owner_signer);

        // execute ownership transfer
        usdc_token_pool::execute_ownership_transfer(owner, new_owner);

        // Verify ownership changed
        assert!(usdc_token_pool::owner() == new_owner);

        // Verify no pending transfer
        assert!(!usdc_token_pool::has_pending_transfer());
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_token_decimals(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Test get token decimals
        let decimals = usdc_token_pool::get_token_decimals();
        assert!(decimals == 6); // USDC typically has 6 decimals
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65538, location = usdc_token_pool::usdc_token_pool)]
    fun test_double_initialization_fails(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );

        // First initialization should succeed
        usdc_token_pool::initialize(owner);

        // Second initialization should fail E_ALREADY_INITIALIZED
        usdc_token_pool::initialize(owner);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65548, location = usdc_token_pool::usdc_token_pool)]
    fun test_set_domains_zero_chain_selector_fails(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // E_ZERO_CHAIN_SELECTOR
        usdc_token_pool::set_domains(
            owner,
            vector[0], // zero chain selector
            vector[1001],
            vector[x"0102030405060708090a0b0c0d0e0f1011121314"],
            vector[true]
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65540, location = usdc_token_pool::usdc_token_pool)]
    fun test_set_domains_invalid_arguments_fails(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // E_INVALID_ARGUMENTS
        usdc_token_pool::set_domains(
            owner,
            vector[1, 2], // 2 elements
            vector[1001], // 1 element - mismatch!
            vector[x"0102030405060708090a0b0c0d0e0f1011121314"],
            vector[true]
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_domain_enabled_disabled_states(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Set up a domain as disabled
        let chain_selector = 1;
        usdc_token_pool::set_domains(
            owner,
            vector[chain_selector],
            vector[1001],
            vector[x"0102030405060708090a0b0c0d0e0f1011121314"],
            vector[false] // disabled
        );

        let domain = usdc_token_pool::get_domain(chain_selector);
        assert!(!usdc_token_pool::domain_enabled(&domain));

        // Re-enable the domain
        usdc_token_pool::set_domains(
            owner,
            vector[chain_selector],
            vector[1001],
            vector[x"0102030405060708090a0b0c0d0e0f1011121314"],
            vector[true] // enabled
        );

        let domain = usdc_token_pool::get_domain(chain_selector);
        assert!(usdc_token_pool::domain_enabled(&domain));
    }

    // ================================================================
    // |                    Additional Tests                          |
    // ================================================================
    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 1, location = ccip::address)]
    // E_ZERO_ADDRESS_NOT_ALLOWED
    fun test_set_domains_empty_allowed_caller_fails(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Should fail with empty allowed caller
        usdc_token_pool::set_domains(
            owner,
            vector[1],
            vector[1001],
            vector[vector[]], // empty allowed caller
            vector[true]
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_get_token_address(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let token_address = usdc_token_pool::get_token();
        assert!(token_address == @local_token);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_get_router_address(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let router_address = usdc_token_pool::get_router();
        // Router should be set to a valid address (not zero)
        assert!(router_address != @0x0);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327681, location = usdc_token_pool::usdc_token_pool)]
    // E_NOT_PUBLISHER
    fun test_unauthorized_initialization_fails(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );

        // Try to initialize with unauthorized signer
        let unauthorized = &account::create_signer_for_test(@0x999);
        usdc_token_pool::initialize(unauthorized);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_domain_update_overwrites_existing(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let chain_selector = 1;

        // Set initial domain
        usdc_token_pool::set_domains(
            owner,
            vector[chain_selector],
            vector[1001],
            vector[x"0102030405060708090a0b0c0d0e0f1011121314"],
            vector[true]
        );

        let domain = usdc_token_pool::get_domain(chain_selector);
        assert!(usdc_token_pool::domain_domain_identifier(&domain) == 1001);
        assert!(usdc_token_pool::domain_enabled(&domain));

        // Update the same domain with different values
        usdc_token_pool::set_domains(
            owner,
            vector[chain_selector],
            vector[2002], // different domain identifier
            vector[x"1112131415161718191a1b1c1d1e1f2021222324"], // different caller
            vector[false] // disabled
        );

        let updated_domain = usdc_token_pool::get_domain(chain_selector);
        assert!(usdc_token_pool::domain_domain_identifier(&updated_domain) == 2002);
        assert!(!usdc_token_pool::domain_enabled(&updated_domain));
        assert!(
            usdc_token_pool::domain_allowed_caller(&updated_domain)
                == x"1112131415161718191a1b1c1d1e1f2021222324"
        );
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_multiple_domains_management(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Set up multiple domains at once
        let chain_selectors = vector[10, 20, 30, 40];
        let domain_identifiers = vector[1010, 2020, 3030, 4040];
        let allowed_callers = vector[
            x"1010101010101010101010101010101010101010",
            x"2020202020202020202020202020202020202020",
            x"3030303030303030303030303030303030303030",
            x"4040404040404040404040404040404040404040"
        ];
        let enableds = vector[true, false, true, false];

        usdc_token_pool::set_domains(
            owner,
            chain_selectors,
            domain_identifiers,
            allowed_callers,
            enableds
        );

        // Verify each domain was set correctly
        for (i in 0..chain_selectors.length()) {
            let domain = usdc_token_pool::get_domain(chain_selectors[i]);
            assert!(
                usdc_token_pool::domain_domain_identifier(&domain)
                    == domain_identifiers[i]
            );
            assert!(
                usdc_token_pool::domain_allowed_caller(&domain) == allowed_callers[i]
            );
            assert!(usdc_token_pool::domain_enabled(&domain) == enableds[i]);
        };
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_rate_limiter_edge_cases(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let chain_selector = 1;

        // Test with zero capacity and rate (disabled rate limiting)
        usdc_token_pool::set_chain_rate_limiter_config(
            owner,
            chain_selector, // remote_chain_selector
            false, // outbound_is_enabled
            0, // outbound_capacity
            0, // outbound_rate
            false, // inbound_is_enabled
            0, // inbound_capacity
            0 // inbound_rate
        );

        let outbound_state =
            usdc_token_pool::get_current_outbound_rate_limiter_state(chain_selector);
        let inbound_state =
            usdc_token_pool::get_current_inbound_rate_limiter_state(chain_selector);

        // Should be able to get states even with zero values (no assertion on internal fields)
        let _outbound_state = outbound_state;
        let _inbound_state = inbound_state;

        // Test with maximum values
        usdc_token_pool::set_chain_rate_limiter_config(
            owner,
            chain_selector,
            true,
            18446744073709551615, // max u64
            18446744073709551615, // max u64
            true,
            18446744073709551615, // max u64
            18446744073709551615 // max u64
        );

        let outbound_state =
            usdc_token_pool::get_current_outbound_rate_limiter_state(chain_selector);
        let inbound_state =
            usdc_token_pool::get_current_inbound_rate_limiter_state(chain_selector);

        // Should be able to get states with maximum values (no assertion on internal fields)
        let _outbound_state = outbound_state;
        let _inbound_state = inbound_state;
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_ownership_transfer_edge_cases(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        let original_owner = std::signer::address_of(owner);
        let new_owner_addr = @0x999;

        // Test that the current owner is correct initially
        assert!(usdc_token_pool::owner() == original_owner);
        assert!(!usdc_token_pool::has_pending_transfer());

        // Test legitimate transfer
        usdc_token_pool::transfer_ownership(owner, new_owner_addr);
        assert!(usdc_token_pool::has_pending_transfer());

        let pending_to = usdc_token_pool::pending_transfer_to();
        assert!(option::is_some(&pending_to));
        assert!(*option::borrow(&pending_to) == new_owner_addr);

        let pending_from = usdc_token_pool::pending_transfer_from();
        assert!(option::is_some(&pending_from));
        assert!(*option::borrow(&pending_from) == original_owner);

        // Before acceptance, pending_transfer_accepted should be option false
        let pending_accepted = usdc_token_pool::pending_transfer_accepted();
        assert!(option::is_some(&pending_accepted));
        assert!(*option::borrow(&pending_accepted) == false);
    }

    #[
        test(
            ccip = @ccip,
            owner = @mcms,
            usdc_token_pool = @usdc_token_pool,
            deployer = @deployer,
            framework = @aptos_framework
        )
    ]
    fun test_chain_updates_comprehensive(
        ccip: &signer,
        owner: &signer,
        usdc_token_pool: &signer,
        deployer: &signer,
        framework: &signer
    ) {
        setup(
            ccip,
            owner,
            usdc_token_pool,
            deployer,
            framework
        );
        usdc_token_pool::initialize(owner);

        // Add initial chains
        let initial_chains = vector[100, 200, 300];
        let initial_pools = vector[
            vector[x"100a", x"100b"],
            vector[x"200a"],
            vector[x"300a", x"300b", x"300c"]
        ];
        let initial_tokens = vector[x"1100", x"2200", x"3300"];

        usdc_token_pool::apply_chain_updates(
            owner,
            vector[], // no chains to remove
            initial_chains,
            initial_pools,
            initial_tokens
        );

        // Verify all chains were added
        for (i in 0..initial_chains.length()) {
            assert!(usdc_token_pool::is_supported_chain(initial_chains[i]));
            assert!(
                usdc_token_pool::get_remote_token(initial_chains[i])
                    == initial_tokens[i]
            );

            // Verify all pools for this chain
            let pools = usdc_token_pool::get_remote_pools(initial_chains[i]);
            assert!(pools.length() == initial_pools[i].length());
        };

        // Remove some chains and add new ones
        let chains_to_remove = vector[200]; // Remove chain 200
        let chains_to_add = vector[400, 500]; // Add chains 400, 500
        let pools_to_add = vector[vector[x"400a"], vector[x"500a", x"500b"]];
        let tokens_to_add = vector[x"4400", x"5500"];

        usdc_token_pool::apply_chain_updates(
            owner,
            chains_to_remove,
            chains_to_add,
            pools_to_add,
            tokens_to_add
        );

        // Verify chain 200 was removed
        assert!(!usdc_token_pool::is_supported_chain(200));

        // Verify new chains were added
        assert!(usdc_token_pool::is_supported_chain(400));
        assert!(usdc_token_pool::is_supported_chain(500));

        // Verify original chains 100 and 300 still exist
        assert!(usdc_token_pool::is_supported_chain(100));
        assert!(usdc_token_pool::is_supported_chain(300));
    }
}
