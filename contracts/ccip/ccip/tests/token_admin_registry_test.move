#[test_only]
module ccip::token_admin_registry_test {
    use std::signer;
    use std::string;
    use std::option;
    use std::object::{Self, Object, ExtendRef, ObjectCore};
    use std::fungible_asset::{
        Self,
        Metadata,
        MintRef,
        BurnRef,
        TransferRef,
        FungibleAsset
    };
    use std::account;
    use std::primary_fungible_store;
    use ccip::token_admin_registry::{Self};
    use ccip::state_object;
    use ccip::auth;

    use 0x662d86e29929eb0637ba20d8926e91ffc74f59580cf18874b366b3150300561f::mock_pool;

    const OWNER: address = @0x100;
    const ADMIN: address = @0x200;
    const POOL_1: address = @0x300;
    const POOL_2: address = @0x400;

    const TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME: vector<u8> = b"token_admin_registry_test";

    struct TestToken has key {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    struct TestProof has drop {}

    fun setup(ccip: &signer, owner: &signer): (signer, signer, Object<Metadata>) {
        account::create_account_for_test(signer::address_of(ccip));

        // Create object for @ccip
        let constructor_ref = object::create_named_object(owner, b"ccip");
        let ccip_obj_signer = object::generate_signer(&constructor_ref);

        // Create object for mock token pool
        let constructor_ref = object::create_named_object(owner, b"mock");
        let mock_obj_signer = object::generate_signer(&constructor_ref);

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        let (token_obj, _token_addr) = create_test_token(owner, b"test_token");

        token_admin_registry::init_module_for_testing(ccip);

        (ccip_obj_signer, mock_obj_signer, token_obj)
    }

    fun create_test_token(owner: &signer, seed: vector<u8>): (Object<Metadata>, address) {
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
        let token_addr = object::object_address(&metadata);

        // =========== Create token refs ==================

        let obj_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
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

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_unregister_and_reregister_token(
        ccip: &signer, owner: &signer
    ) {
        let (ccip_obj_signer, mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);
        let initial_administrator = signer::address_of(owner);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );

        // Verify the pool is registered
        let ccip_pool_addr = signer::address_of(&ccip_obj_signer);
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == ccip_pool_addr);

        // Get the token config to verify admin
        let (_, admin, _) = token_admin_registry::get_token_config(token_addr);
        assert!(admin == initial_administrator);

        // Unregister token
        token_admin_registry::unregister_pool(owner, token_addr);

        // Verify the token is unregistered (pool address should be @0x0)
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == @0x0);

        let (token_pool_address, admin, pending_admin) =
            token_admin_registry::get_token_config(token_addr);
        assert!(token_pool_address == @0x0);
        assert!(admin == @0x0);
        assert!(pending_admin == @0x0);
        assert!(token_admin_registry::get_token_unregistered_events().length() == 1);

        let new_administrator = signer::address_of(owner);
        mock_pool::register_and_set_pool(owner, &mock_obj_signer, token_addr);

        // Verify the pool has been updated
        let mock_pool_addr = signer::address_of(&mock_obj_signer);
        let new_pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(new_pool_addr == mock_pool_addr);

        // Verify admin has been updated (should be the new pool address)
        let (_, new_admin, _) = token_admin_registry::get_token_config(token_addr);
        assert!(new_admin == new_administrator);
    }

    // This tests if create_sticky_object() works properly and allows re-registration
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_unregister_and_reregister_same_pool_address(
        ccip: &signer, owner: &signer
    ) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);
        let ccip_pool_addr = signer::address_of(&ccip_obj_signer);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(owner, token_addr, ccip_pool_addr);

        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == ccip_pool_addr);

        token_admin_registry::unregister_pool(owner, token_addr);

        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == @0x0);

        // Now try to register the SAME pool address again
        // This should work if create_sticky_object() handles conflicts properly
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(owner, token_addr, ccip_pool_addr);

        // Verify re-registration worked
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == ccip_pool_addr);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 65562, location = ccip::token_admin_registry)]
    fun test_wrong_token_for_pool(ccip: &signer, owner: &signer) {
        let (ccip_obj_signer, mock_obj_signer, token1_obj) = setup(ccip, owner);
        let token1_addr = object::object_address(&token1_obj);
        let (_token2_obj, token2_addr) = create_test_token(owner, b"test_token_2");

        // Register token1 with ccip pool
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token1_addr,
            TestProof {}
        );

        set_admin(owner, token1_addr);

        token_admin_registry::set_pool(
            owner, token1_addr, signer::address_of(&ccip_obj_signer)
        );

        mock_pool::register_pool(&mock_obj_signer, token2_addr);

        // Point Mock Pool to Token1 - Fails with E_INVALID_TOKEN_FOR_POOL
        token_admin_registry::set_pool(
            owner, token1_addr, signer::address_of(&mock_obj_signer)
        );
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_register_pool(ccip: &signer, owner: &signer) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);
        let initial_administrator = signer::address_of(owner);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );
        // Verify the pool is registered
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == signer::address_of(&ccip_obj_signer));

        // Verify the token config
        let (pool_address, admin, pending_admin) =
            token_admin_registry::get_token_config(token_addr);
        assert!(pool_address == signer::address_of(&ccip_obj_signer));
        assert!(admin == initial_administrator); // Initial admin is pool address
        assert!(pending_admin == @0x0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_set_pool(ccip: &signer, owner: &signer) {
        let (ccip_obj_signer, mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );

        // Register another pool (for a different token)
        let (_token2, token2_addr) = create_test_token(owner, b"test_token_2");

        mock_pool::register_and_set_pool(owner, &mock_obj_signer, token2_addr);

        // Now change the pool for token1 to the mock pool
        let mock_pool_addr = signer::address_of(&mock_obj_signer);
        token_admin_registry::set_pool(owner, token2_addr, mock_pool_addr);

        // Verify the pool was updated
        let pool_addr = token_admin_registry::get_pool(token2_addr);
        assert!(pool_addr == mock_pool_addr);
    }

    #[test(ccip = @ccip, owner = @mcms, not_owner = @0x300)]
    #[expected_failure(abort_code = 327703, location = ccip::token_admin_registry)]
    fun test_not_token_owner(
        ccip: &signer, owner: &signer, not_owner: &signer
    ) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // First register the token pool
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        // E_NOT_ADMINISTRATOR
        token_admin_registry::set_pool(
            not_owner, token_addr, signer::address_of(&ccip_obj_signer)
        );
    }

    #[test(ccip = @ccip, owner = @mcms, not_admin = @0x300)]
    #[expected_failure(abort_code = 327703, location = ccip::token_admin_registry)]
    fun test_unregister_pool_not_admin(
        ccip: &signer, owner: &signer, not_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(not_admin));

        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );

        // Try to unregister the token with a non-admin signer
        // Should fail with E_NOT_ADMINISTRATOR
        token_admin_registry::unregister_pool(not_admin, token_addr);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 65558, location = ccip::token_admin_registry)]
    fun test_unregister_pool_not_registered(
        ccip: &signer, owner: &signer
    ) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Try to unregister a token that is not registered
        // Should fail with E_FUNGIBLE_ASSET_NOT_REGISTERED
        token_admin_registry::unregister_pool(&ccip_obj_signer, token_addr);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 65540, location = ccip::token_admin_registry)]
    fun test_duplicate_register_pool(ccip: &signer, owner: &signer) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );

        // Try to register the same token pool again
        // Should fail with E_ALREADY_REGISTERED
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );
    }

    #[test(ccip = @ccip, owner = @mcms, admin = @0x200)]
    fun test_transfer_admin_role(
        ccip: &signer, owner: &signer, admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(admin));

        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            TestProof {}
        );

        set_admin(owner, token_addr);

        token_admin_registry::set_pool(
            owner, token_addr, signer::address_of(&ccip_obj_signer)
        );

        // Request transfer of admin role
        let admin_addr = signer::address_of(admin);
        token_admin_registry::transfer_admin_role(
            owner, // Current admin
            token_addr, admin_addr
        );

        // Verify pending admin
        let (_, _, pending_admin) = token_admin_registry::get_token_config(token_addr);
        assert!(pending_admin == admin_addr);

        // Accept admin role
        token_admin_registry::accept_admin_role(admin, token_addr);

        // Verify new admin
        let (_, current_admin, pending_admin) =
            token_admin_registry::get_token_config(token_addr);
        assert!(current_admin == admin_addr);
        assert!(pending_admin == @0x0);

        // Verify is_administrator function
        assert!(token_admin_registry::is_administrator(token_addr, admin_addr));
        assert!(
            !token_admin_registry::is_administrator(
                token_addr, signer::address_of(&ccip_obj_signer)
            )
        );
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_all_configured_tokens(ccip: &signer, owner: &signer) {
        let (ccip_obj_signer, mock_obj_signer, token1_obj) = setup(ccip, owner);
        let token1_addr = object::object_address(&token1_obj);

        let (_token2, token2_addr) = create_test_token(owner, b"test_token_2");

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token1_addr,
            TestProof {}
        );

        set_admin(owner, token1_addr);

        token_admin_registry::set_pool(
            owner, token1_addr, signer::address_of(&ccip_obj_signer)
        );

        mock_pool::register_and_set_pool(owner, &mock_obj_signer, token2_addr);

        // Get all tokens with pagination
        let (tokens, _next_key, has_more) =
            token_admin_registry::get_all_configured_tokens(@0x0, 2);
        assert!(tokens.length() == 2);
        assert!(!has_more);
    }

    #[test(
        ccip = @ccip, owner = @mcms, token_owner = @0x123, new_admin = @0x456
    )]
    fun test_propose_administrator_by_token_owner(
        ccip: &signer, owner: &signer, token_owner: &signer, new_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));
        account::create_account_for_test(signer::address_of(new_admin));

        let (ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_owner");

        // Register a pool first
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_address,
            TestProof {}
        );

        token_admin_registry::propose_administrator(
            token_owner, token_address, signer::address_of(new_admin)
        );

        let (_, _, pending_admin) = token_admin_registry::get_token_config(token_address);
        assert!(pending_admin == signer::address_of(new_admin));
    }

    #[test(
        ccip = @ccip,
        owner = @mcms,
        new_ccip_owner = @0x555,
        token_owner = @0x123,
        new_admin = @0x456
    )]
    fun test_propose_administrator_by_ccip_owner(
        ccip: &signer,
        owner: &signer,
        new_ccip_owner: &signer,
        token_owner: &signer,
        new_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));
        account::create_account_for_test(signer::address_of(new_admin));
        account::create_account_for_test(signer::address_of(new_ccip_owner));

        let (ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_ccip");

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_address,
            TestProof {}
        );

        let ccip_object =
            object::address_to_object<ObjectCore>(signer::address_of(&ccip_obj_signer));

        object::transfer(owner, ccip_object, signer::address_of(new_ccip_owner));

        // New CCIP owner should be able to propose administrator
        token_admin_registry::propose_administrator(
            new_ccip_owner, token_address, signer::address_of(new_admin)
        );

        let (_, _, pending_admin) = token_admin_registry::get_token_config(token_address);
        assert!(pending_admin == signer::address_of(new_admin));
    }

    #[test(
        ccip = @ccip,
        owner = @mcms,
        token_owner = @0x123,
        unauthorized = @0x789,
        new_admin = @0x456
    )]
    #[expected_failure(abort_code = 327705, location = ccip::token_admin_registry)]
    fun test_propose_administrator_unauthorized(
        ccip: &signer,
        owner: &signer,
        token_owner: &signer,
        unauthorized: &signer,
        new_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));
        account::create_account_for_test(signer::address_of(unauthorized));
        account::create_account_for_test(signer::address_of(new_admin));

        let (ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_unauth");

        // Register a pool first
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_address,
            TestProof {}
        );

        set_admin(token_owner, token_address);

        token_admin_registry::set_pool(
            token_owner, // Token owner sets the pool
            token_address,
            signer::address_of(&ccip_obj_signer)
        );

        // Unauthorized user should not be able to propose administrator
        // Should fail with E_NOT_AUTHORIZED (327705)
        token_admin_registry::propose_administrator(
            unauthorized, token_address, signer::address_of(new_admin)
        );
    }

    inline fun set_admin(owner: &signer, token_address: address) {
        let admin = signer::address_of(owner);
        token_admin_registry::propose_administrator(owner, token_address, admin);
        token_admin_registry::accept_admin_role(owner, token_address);
    }

    #[test(ccip = @ccip, owner = @mcms, token_owner = @0x123)]
    #[expected_failure(abort_code = 65563, location = ccip::token_admin_registry)]
    fun test_set_pool_without_admin_set(
        ccip: &signer, owner: &signer, token_owner: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));

        let (ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_no_admin");

        // Register a pool first
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_address,
            TestProof {}
        );

        // Try to set pool without setting admin first
        // Should fail with E_ADMIN_NOT_SET_FOR_TOKEN (65563)
        token_admin_registry::set_pool(
            token_owner, token_address, signer::address_of(&ccip_obj_signer)
        );
    }

    #[test(
        ccip = @ccip,
        owner = @mcms,
        token_owner = @0x123,
        first_admin = @0x456,
        second_admin = @0x789
    )]
    fun test_propose_administrator_second_time_if_first_admin_incorrect(
        ccip: &signer,
        owner: &signer,
        token_owner: &signer,
        first_admin: &signer,
        second_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));
        account::create_account_for_test(signer::address_of(first_admin));
        account::create_account_for_test(signer::address_of(second_admin));

        let (_ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_double_admin");

        // Set admin for the first time
        token_admin_registry::propose_administrator(
            token_owner, token_address, signer::address_of(first_admin)
        );

        token_admin_registry::propose_administrator(
            token_owner, token_address, signer::address_of(second_admin)
        );

        let (_, _, pending_admin) = token_admin_registry::get_token_config(token_address);
        assert!(pending_admin == signer::address_of(second_admin));
    }

    #[test(ccip = @ccip, owner = @mcms, token_owner = @0x123)]
    #[expected_failure(abort_code = 65565, location = ccip::token_admin_registry)]
    fun test_propose_administrator_zero_address(
        ccip: &signer, owner: &signer, token_owner: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));

        let (_ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_zero_admin");

        // Try to propose zero address as administrator
        // Should fail with E_ZERO_ADDRESS (65565)
        token_admin_registry::propose_administrator(token_owner, token_address, @0x0);
    }

    #[test(
        ccip = @ccip, owner = @mcms, token_owner = @0x123, admin = @0x456
    )]
    fun test_complete_flow_propose_accept_set_pool(
        ccip: &signer, owner: &signer, token_owner: &signer, admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(token_owner));
        account::create_account_for_test(signer::address_of(admin));

        let (ccip_obj_signer, _mock_obj_signer, _token_obj) = setup(ccip, owner);

        // Create a token owned by token_owner
        let (_token_metadata, token_address) =
            create_test_token(token_owner, b"test_token_complete_flow");

        // Register a pool first
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_address,
            TestProof {}
        );

        // Step 1: Propose administrator
        token_admin_registry::propose_administrator(
            token_owner, token_address, signer::address_of(admin)
        );

        // Verify pending admin is set
        let (pool_addr, current_admin, pending_admin) =
            token_admin_registry::get_token_config(token_address);
        assert!(pool_addr == @0x0); // No pool set yet
        assert!(current_admin == @0x0); // No current admin yet
        assert!(pending_admin == signer::address_of(admin));

        // Step 2: Accept admin role
        token_admin_registry::accept_admin_role(admin, token_address);

        // Verify admin is now set
        let (pool_addr, current_admin, pending_admin) =
            token_admin_registry::get_token_config(token_address);
        assert!(pool_addr == @0x0); // Still no pool set
        assert!(current_admin == signer::address_of(admin));
        assert!(pending_admin == @0x0); // No pending admin

        // Step 3: Set pool (only admin can do this)
        token_admin_registry::set_pool(
            admin, // Admin sets the pool
            token_address,
            signer::address_of(&ccip_obj_signer)
        );

        let (pool_addr, current_admin, pending_admin) =
            token_admin_registry::get_token_config(token_address);
        assert!(pool_addr == signer::address_of(&ccip_obj_signer));
        assert!(current_admin == signer::address_of(admin));
        assert!(pending_admin == @0x0);

        let retrieved_pool = token_admin_registry::get_pool(token_address);
        assert!(retrieved_pool == signer::address_of(&ccip_obj_signer));
    }

    // =========================== Mock Pool Implementation ===========================
    public fun lock_or_burn<T: key>(
        store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
    ) {
        fungible_asset::deposit(store, fa);
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, _amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        let metadata = fungible_asset::transfer_ref_metadata(transfer_ref);
        fungible_asset::zero(metadata)
    }
}
