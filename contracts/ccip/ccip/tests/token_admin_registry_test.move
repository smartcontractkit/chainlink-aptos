#[test_only]
module ccip::token_admin_registry_test {
    use std::signer;
    use std::string;
    use std::option;
    use std::object::{Self, Object, ExtendRef};
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
    use std::event;
    use ccip::token_admin_registry::{Self, TokenUnregistered};
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
        auth::test_init_module(owner);

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
            TestToken { metadata, extend_ref, mint_ref, burn_ref, transfer_ref }
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
            initial_administrator,
            TestProof {}
        );

        // Verify the pool is registered
        let ccip_pool_addr = signer::address_of(&ccip_obj_signer);
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == ccip_pool_addr);

        // Get the token config to verify admin
        let (_, admin, _) = token_admin_registry::get_token_config(token_addr);
        assert!(admin == initial_administrator);

        // Unregister token
        token_admin_registry::unregister_token(owner, token_addr);

        // Verify the token is unregistered (pool address should be @0x0)
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == @0x0);

        let (token_pool_address, admin, pending_admin) =
            token_admin_registry::get_token_config(token_addr);
        assert!(token_pool_address == @0x0);
        assert!(admin == @0x0);
        assert!(pending_admin == @0x0);
        assert!(
            event::emitted_events<TokenUnregistered>().length() == 1
        );

        let new_administrator = signer::address_of(owner);
        mock_pool::register_pool(&mock_obj_signer, token_addr, new_administrator);

        // Verify the pool has been updated
        let mock_pool_addr = signer::address_of(&mock_obj_signer);
        let new_pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(new_pool_addr == mock_pool_addr);

        // Verify admin has been updated (should be the new pool address)
        let (_, new_admin, _) = token_admin_registry::get_token_config(token_addr);
        assert!(new_admin == new_administrator);
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
            initial_administrator,
            TestProof {}
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
            signer::address_of(owner),
            TestProof {}
        );

        // Register another pool (for a different token)
        let (_token2, token2_addr) = create_test_token(owner, b"test_token_2");

        mock_pool::register_pool(
            &mock_obj_signer, token2_addr, signer::address_of(owner)
        );

        // Now change the pool for token1 to the mock pool
        let mock_pool_addr = signer::address_of(&mock_obj_signer);
        token_admin_registry::set_pool(owner, token_addr, mock_pool_addr);

        // Verify the pool was updated
        let pool_addr = token_admin_registry::get_pool(token_addr);
        assert!(pool_addr == mock_pool_addr);
    }

    #[test(ccip = @ccip, owner = @mcms, not_owner = @0x300)]
    #[expected_failure(abort_code = 327682, location = ccip::token_admin_registry)]
    fun test_not_fungible_asset_owner(
        ccip: &signer, owner: &signer, not_owner: &signer
    ) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // First register the token pool
        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            signer::address_of(owner),
            TestProof {}
        );

        // Create mock pool with not_owner
        let constructor_ref = object::create_named_object(not_owner, b"not_owner");
        let not_owner_signer = object::generate_signer(&constructor_ref);

        // Try to register the token pool again with a different owner
        // E_NOT_FUNGIBLE_ASSET_OWNER
        token_admin_registry::register_pool<TestProof>(
            &not_owner_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            signer::address_of(owner),
            TestProof {}
        );
    }

    #[test(ccip = @ccip, owner = @mcms, not_admin = @0x300)]
    #[expected_failure(abort_code = 327703, location = ccip::token_admin_registry)]
    fun test_unregister_token_not_admin(
        ccip: &signer, owner: &signer, not_admin: &signer
    ) {
        account::create_account_for_test(signer::address_of(not_admin));

        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            signer::address_of(owner),
            TestProof {}
        );

        // Try to unregister the token with a non-admin signer
        // Should fail with E_NOT_ADMINISTRATOR
        token_admin_registry::unregister_token(not_admin, token_addr);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 65558, location = ccip::token_admin_registry)]
    fun test_unregister_token_not_registered(
        ccip: &signer, owner: &signer
    ) {
        let (ccip_obj_signer, _mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Try to unregister a token that is not registered
        // Should fail with E_FUNGIBLE_ASSET_NOT_REGISTERED
        token_admin_registry::unregister_token(&ccip_obj_signer, token_addr);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 65557, location = ccip::token_admin_registry)]
    fun test_register_token_already_registered(
        ccip: &signer, owner: &signer
    ) {
        let (ccip_obj_signer, mock_obj_signer, token_obj) = setup(ccip, owner);
        let token_addr = object::object_address(&token_obj);

        token_admin_registry::register_pool<TestProof>(
            &ccip_obj_signer,
            TOKEN_ADMIN_REGISTRY_TEST_MODULE_NAME,
            token_addr,
            signer::address_of(owner),
            TestProof {}
        );

        // Try to register the token pool again
        // Should fail with E_FUNGIBLE_ASSET_ALREADY_REGISTERED
        mock_pool::register_pool(
            &mock_obj_signer, token_addr, signer::address_of(owner)
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
            signer::address_of(owner),
            TestProof {}
        );

        // Request transfer of admin role
        let admin_addr = signer::address_of(admin);
        token_admin_registry::transfer_admin_role(
            owner, // Current admin
            token_addr,
            admin_addr
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
            signer::address_of(owner),
            TestProof {}
        );

        mock_pool::register_pool(
            &mock_obj_signer, token2_addr, signer::address_of(owner)
        );

        // Get all tokens with pagination
        let (tokens, _next_key, has_more) =
            token_admin_registry::get_all_configured_tokens(@0x0, 2);
        assert!(tokens.length() == 2);
        assert!(!has_more);
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
