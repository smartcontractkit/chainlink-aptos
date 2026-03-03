#[test_only]
module regulated_token_pool::regulated_token_pool_ccip_test {
    use std::account;
    use std::fungible_asset::{Self, FungibleAsset, Metadata};
    use std::object;
    use std::primary_fungible_store;
    use std::signer;
    use std::string;
    use std::option;
    use std::timestamp;

    use ccip::auth;
    use ccip::rmn_remote;
    use ccip::state_object;
    use ccip::token_admin_registry;
    use ccip::token_admin_dispatcher;

    use regulated_token::regulated_token;
    use regulated_token_pool::regulated_token_pool;

    // Test constants
    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const TOKEN_AMOUNT: u64 = 100; // Use smaller amount for testing
    const TIMESTAMP: u64 = 1744315405;

    const OUTBOUND_CAPACITY: u64 = 10000000; // Increase capacity significantly
    const OUTBOUND_RATE: u64 = 100000;
    const INBOUND_CAPACITY: u64 = 5000000;
    const INBOUND_RATE: u64 = 50000;

    const MOCK_EVM_ADDRESS: vector<u8> = x"1234567890123456789012345678901234567890";

    // Test addresses
    const ADMIN: address = @0x100;
    const SENDER: address = @0x500;
    const RECIPIENT: address = @0x600;

    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;

    // ================================================================
    // |                    Setup Functions                          |
    // ================================================================
    fun setup_ccip_dispatch_environment(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        // Initialize timestamp
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);

        // Create accounts for all signers
        account::create_account_for_test(signer::address_of(admin));
        account::create_account_for_test(signer::address_of(ccip));
        account::create_account_for_test(signer::address_of(regulated_token));
        account::create_account_for_test(signer::address_of(regulated_token_pool));
        account::create_account_for_test(SENDER);
        account::create_account_for_test(RECIPIENT);

        // Create ccip object for state management
        let ccip_constructor_ref = object::create_named_object(admin, b"ccip");
        account::create_account_for_test(
            object::address_from_constructor_ref(&ccip_constructor_ref)
        );

        // Initialize core CCIP infrastructure
        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        token_admin_registry::init_module_for_testing(ccip);

        // Initialize RMN remote with the current chain selector
        setup_rmn_remote(admin);

        // Create regulated token object
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

        // Grant admin the BRIDGE_MINTER_OR_BURNER role for token operations
        setup_regulated_token_roles(admin);

        // Create regulated token pool object
        let regulated_token_pool_constructor_ref =
            object::create_named_object(admin, b"regulated_token_pool");
        account::create_account_for_test(
            object::address_from_constructor_ref(&regulated_token_pool_constructor_ref)
        );

        // Initialize regulated token pool (this will auto-register with token admin registry)
        regulated_token_pool::test_init_module(regulated_token_pool);

        // Grant the pool's store signer the BRIDGE_MINTER_OR_BURNER role so it can mint tokens for release_or_mint
        let pool_store_address = regulated_token_pool::get_store_address();
        regulated_token::grant_role(
            admin, BRIDGE_MINTER_OR_BURNER_ROLE, pool_store_address
        );

        // Complete the token admin registry setup
        setup_token_admin_registry(admin);

        // Set up CCIP authorization for admin to act as onramp/offramp
        setup_ccip_authorization(admin);

        // Configure chains and rate limits
        setup_chain_configurations(admin);
    }

    fun setup_rmn_remote(admin: &signer) {
        // Initialize RMN remote with a test chain selector
        rmn_remote::initialize(admin, DEST_CHAIN_SELECTOR);
    }

    fun setup_regulated_token_roles(admin: &signer) {
        // Grant admin the BRIDGE_MINTER_OR_BURNER role (role 6) so they can mint/burn tokens for testing
        regulated_token::grant_role(
            admin, BRIDGE_MINTER_OR_BURNER_ROLE, signer::address_of(admin)
        );
    }

    fun setup_ccip_authorization(admin: &signer) {
        // Allow admin to act as onramp and offramp for dispatch operations
        auth::apply_allowed_onramp_updates(
            admin,
            vector[], // onramps_to_remove
            vector[signer::address_of(admin)] // onramps_to_add
        );

        auth::apply_allowed_offramp_updates(
            admin,
            vector[], // offramps_to_remove
            vector[signer::address_of(admin)] // offramps_to_add
        );
    }

    fun setup_token_admin_registry(admin: &signer) {
        let regulated_token_address = regulated_token::token_address();

        // Propose admin as the administrator for the regulated token
        token_admin_registry::propose_administrator(
            admin, regulated_token_address, signer::address_of(admin)
        );

        // Accept the admin role
        token_admin_registry::accept_admin_role(admin, regulated_token_address);

        // Set the pool for the token to complete registration
        token_admin_registry::set_pool(
            admin, regulated_token_address, @regulated_token_pool
        );
    }

    fun setup_chain_configurations(admin: &signer) {
        // Configure supported chains in regulated token pool
        let remote_token_address = MOCK_EVM_ADDRESS;

        regulated_token_pool::apply_chain_updates(
            admin,
            vector[], // no chains to remove
            vector[DEST_CHAIN_SELECTOR], // chains to add
            vector[vector[MOCK_EVM_ADDRESS]], // Add MOCK_EVM_ADDRESS as remote pool
            vector[remote_token_address] // remote token addresses
        );

        // Set rate limiter configuration
        regulated_token_pool::set_chain_rate_limiter_config(
            admin,
            DEST_CHAIN_SELECTOR,
            true, // outbound enabled
            OUTBOUND_CAPACITY,
            OUTBOUND_RATE,
            true, // inbound enabled
            INBOUND_CAPACITY,
            INBOUND_RATE
        );

        // Advance time to allow rate limiter buckets to fill
        // Need enough time for buckets to accumulate at least TOKEN_AMOUNT tokens
        // outbound_rate = 100000 tokens/second, inbound_rate = 50000 tokens/second
        // For 100 tokens, we need at least 1 second for outbound, 1 second for inbound
        timestamp::update_global_time_for_test_secs(TIMESTAMP + 2);
    }

    // ================================================================
    // |                  CCIP Dispatch Flow Tests                   |
    // ================================================================
    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool
        )
    ]
    fun test_dispatch_lock_or_burn_flow(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        setup_ccip_dispatch_environment(
            aptos_framework,
            ccip,
            admin,
            regulated_token,
            regulated_token_pool
        );

        let regulated_token_address = regulated_token::token_address();
        let metadata = object::address_to_object<Metadata>(regulated_token_address);

        // Set up test token state
        let _ =
            primary_fungible_store::ensure_primary_store_exists(
                signer::address_of(admin), metadata
            );

        // Mint some tokens to admin for testing (mint extra to ensure sufficient balance)
        regulated_token::mint(admin, signer::address_of(admin), TOKEN_AMOUNT * 2);

        // Verify admin has tokens
        let admin_balance =
            primary_fungible_store::balance(signer::address_of(admin), metadata);
        assert!(admin_balance >= TOKEN_AMOUNT);

        // Get initial token supply for comparison
        let total_supply_before = fungible_asset::supply(metadata);

        // Prepare dispatch parameters for lock_or_burn
        let sender_address = SENDER;
        let receiver_bytes = MOCK_EVM_ADDRESS;

        // Create a FungibleStore for SENDER so we can burn from it
        // This will call `regulated_token::bridge_burn` which attempts to check the sender's store
        // to make sure it's not frozen.
        let _sender_store =
            primary_fungible_store::ensure_primary_store_exists(SENDER, metadata);

        // Create a fungible asset to be locked/burned
        // Try using primary fungible store withdraw instead
        let fa_to_burn = primary_fungible_store::withdraw(admin, metadata, TOKEN_AMOUNT);

        // Use token_admin_dispatcher to trigger lock_or_burn via dynamic dispatch
        // This should call regulated_token_pool::lock_or_burn via dynamic dispatch
        let (dest_token_address, dest_pool_data) =
            token_admin_dispatcher::dispatch_lock_or_burn(
                admin, // caller with authorization
                @regulated_token_pool,
                fa_to_burn,
                sender_address,
                DEST_CHAIN_SELECTOR,
                receiver_bytes
            );

        // Verify the operation completed successfully
        assert!(dest_token_address == MOCK_EVM_ADDRESS);
        assert!(dest_pool_data.length() > 0);

        // Verify tokens were burned from supply
        let total_supply_after = fungible_asset::supply(metadata);
        if (total_supply_before.is_some() && total_supply_after.is_some()) {
            let supply_before = *total_supply_before.borrow();
            let supply_after = *total_supply_after.borrow();
            assert!(supply_after < supply_before);
        };
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool
        )
    ]
    fun test_dispatch_release_or_mint_flow(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        // Set up CCIP dispatch environment
        setup_ccip_dispatch_environment(
            aptos_framework,
            ccip,
            admin,
            regulated_token,
            regulated_token_pool
        );

        let regulated_token_address = regulated_token::token_address();
        let metadata = object::address_to_object<Metadata>(regulated_token_address);

        // Get initial token supply for comparison
        let total_supply_before = fungible_asset::supply(metadata);

        // Prepare dispatch parameters for release_or_mint
        let sender_bytes = MOCK_EVM_ADDRESS;
        let receiver_address = RECIPIENT;
        let source_amount: u256 = (TOKEN_AMOUNT as u256);
        let source_pool_address = MOCK_EVM_ADDRESS;
        let source_pool_data = vector[];
        let offchain_token_data = vector[];

        // Use token_admin_dispatcher to trigger release_or_mint via dynamic dispatch
        // This should call regulated_token_pool::release_or_mint via dynamic dispatch
        let (fa_minted, destination_amount) =
            token_admin_dispatcher::dispatch_release_or_mint(
                admin, // caller with authorization
                @regulated_token_pool,
                sender_bytes,
                receiver_address,
                source_amount,
                regulated_token_address,
                DEST_CHAIN_SELECTOR,
                source_pool_address,
                source_pool_data,
                offchain_token_data
            );

        // Verify the operation completed successfully
        assert!(destination_amount == TOKEN_AMOUNT);
        assert!(fungible_asset::amount(&fa_minted) == TOKEN_AMOUNT);

        // Verify tokens were minted to supply
        let total_supply_after = fungible_asset::supply(metadata);
        if (total_supply_before.is_some() && total_supply_after.is_some()) {
            let supply_before = *total_supply_before.borrow();
            let supply_after = *total_supply_after.borrow();
            assert!(supply_after > supply_before);
        };

        // Dispose of the minted FA
        burn_fa(admin, fa_minted);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool
        )
    ]
    fun test_token_admin_registry_integration(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        // Set up CCIP dispatch environment
        setup_ccip_dispatch_environment(
            aptos_framework,
            ccip,
            admin,
            regulated_token,
            regulated_token_pool
        );

        let regulated_token_address = regulated_token::token_address();

        // Verify that the regulated token pool is properly registered
        let pool_address = token_admin_registry::get_pool(regulated_token_address);
        assert!(pool_address == @regulated_token_pool);

        // Verify the token configuration
        let (registered_pool, administrator, pending_admin) =
            token_admin_registry::get_token_config(regulated_token_address);
        assert!(registered_pool == @regulated_token_pool);
        // Administrator should be set during pool initialization
        assert!(administrator != @0x0);
        assert!(pending_admin == @0x0);

        // Verify pool local token matches (using V2 since pools now only register with V2)
        let local_token =
            token_admin_registry::get_pool_local_token_v2(@regulated_token_pool);
        assert!(local_token == regulated_token_address);

        // Test the basic registry functions work
        let pools = token_admin_registry::get_pools(vector[regulated_token_address]);
        assert!(pools.length() == 1);
        assert!(pools[0] == @regulated_token_pool);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool
        )
    ]
    fun test_regulated_token_pool_component_setup(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        // Set up CCIP dispatch environment
        setup_ccip_dispatch_environment(
            aptos_framework,
            ccip,
            admin,
            regulated_token,
            regulated_token_pool
        );

        // Verify the regulated token pool was initialized correctly
        let token_address = regulated_token_pool::get_token();
        assert!(token_address == regulated_token::token_address());

        // Verify type and version
        let type_version = regulated_token_pool::type_and_version();
        assert!(type_version == string::utf8(b"RegulatedTokenPool 1.6.0"));

        // Verify store address is set up correctly
        let store_address = regulated_token_pool::get_store_address();
        assert!(store_address != @0x0);
        assert!(store_address != @regulated_token_pool);

        // Verify token decimals
        let decimals = regulated_token_pool::get_token_decimals();
        assert!(decimals == 6); // Regulated token uses 6 decimals

        // Verify router configuration
        let router_address = regulated_token_pool::get_router();
        assert!(router_address == @ccip);

        // Verify ownership is set correctly
        let owner = regulated_token_pool::owner();
        assert!(owner != @0x0);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            admin = @admin,
            regulated_token = @regulated_token,
            regulated_token_pool = @regulated_token_pool
        )
    ]
    fun test_ccip_rate_limiting_integration(
        aptos_framework: &signer,
        ccip: &signer,
        admin: &signer,
        regulated_token: &signer,
        regulated_token_pool: &signer
    ) {
        // Set up CCIP dispatch environment
        setup_ccip_dispatch_environment(
            aptos_framework,
            ccip,
            admin,
            regulated_token,
            regulated_token_pool
        );

        // Verify rate limiting is properly configured
        assert!(regulated_token_pool::is_supported_chain(DEST_CHAIN_SELECTOR));

        // Test rate limiter state can be retrieved
        let _ =
            regulated_token_pool::get_current_outbound_rate_limiter_state(
                DEST_CHAIN_SELECTOR
            );
        let _ =
            regulated_token_pool::get_current_inbound_rate_limiter_state(
                DEST_CHAIN_SELECTOR
            );

        // Verify chain configuration
        let supported_chains = regulated_token_pool::get_supported_chains();
        assert!(supported_chains.length() == 1);
        assert!(supported_chains[0] == DEST_CHAIN_SELECTOR);

        // Verify remote token configuration
        let remote_token = regulated_token_pool::get_remote_token(DEST_CHAIN_SELECTOR);
        assert!(remote_token == MOCK_EVM_ADDRESS);
    }

    fun burn_fa(admin: &signer, fa: FungibleAsset) {
        let metadata = fungible_asset::metadata_from_asset(&fa);
        // Create a FungibleStore for SENDER so we can burn from it
        // This will call `regulated_token::bridge_burn` which attempts to check the sender's store
        // to make sure it's not frozen.
        let _store = primary_fungible_store::ensure_primary_store_exists(
            SENDER, metadata
        );
        regulated_token::bridge_burn(admin, SENDER, fa);
    }
}
