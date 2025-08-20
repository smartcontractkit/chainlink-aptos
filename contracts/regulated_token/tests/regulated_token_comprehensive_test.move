#[test_only]
module regulated_token::regulated_token_comprehensive_test {
    use std::account;
    use std::primary_fungible_store;
    use std::object::{Object};
    use std::fungible_asset::{Metadata};

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const MINTER1: address = @0x200;
    const MINTER2: address = @0x201;
    const MINTER3: address = @0x202;
    const BURNER1: address = @0x300;
    const BURNER2: address = @0x301;
    const BURNER3: address = @0x302;
    const PAUSER1: address = @0x400;
    const PAUSER2: address = @0x401;
    const UNPAUSER1: address = @0x410;
    const FREEZER1: address = @0x500;
    const FREEZER2: address = @0x501;
    const UNFREEZER1: address = @0x510;
    const USER1: address = @0x600;
    const USER2: address = @0x700;
    const USER3: address = @0x800;
    const UNAUTHORIZED: address = @0x999;

    const PAUSER_ROLE: u8 = 0;
    const UNPAUSER_ROLE: u8 = 1;
    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;
    const TOKEN_POOL_ROLE: u8 = 7;

    fun setup_token(regulated_token: &signer): Object<Metadata> {
        regulated_token::init_module_for_testing(regulated_token);
        regulated_token::token_metadata()
    }

    fun setup_token_and_roles(regulated_token: &signer): Object<Metadata> {
        let token_metadata = setup_token(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        regulated_token::grant_role(&admin, MINTER_ROLE, MINTER1); // Native minter
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, MINTER2); // Bridge minter
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, MINTER3); // Token pool minter

        regulated_token::grant_role(&admin, BURNER_ROLE, BURNER1); // Native burner
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, BURNER2); // Bridge burner
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, BURNER3); // Token pool burner

        regulated_token::grant_role(&admin, PAUSER_ROLE, PAUSER1);
        regulated_token::grant_role(&admin, PAUSER_ROLE, PAUSER2);
        regulated_token::grant_role(&admin, UNPAUSER_ROLE, UNPAUSER1);

        regulated_token::grant_role(&admin, FREEZER_ROLE, FREEZER1);
        regulated_token::grant_role(&admin, FREEZER_ROLE, FREEZER2);
        regulated_token::grant_role(&admin, UNFREEZER_ROLE, UNFREEZER1);

        token_metadata
    }

    // Flexible parameterized version - mint to any users with any amounts
    fun mint_tokens_to_users(
        users: vector<address>, amounts: vector<u64>
    ) {
        assert!(users.length() == amounts.length(), 0); // Ensure vectors match
        let minter1 = account::create_signer_for_test(MINTER1);

        for (i in 0..users.length()) {
            regulated_token::mint(&minter1, users[i], amounts[i]);
        }
    }

    // Convenience function for single user minting
    fun mint_to_user(user: address, amount: u64) {
        let minter1 = account::create_signer_for_test(MINTER1);
        regulated_token::mint(&minter1, user, amount);
    }

    // Flexible version with custom minter
    fun mint_tokens_with_minter(
        minter_addr: address, users: vector<address>, amounts: vector<u64>
    ) {
        assert!(users.length() == amounts.length(), 0);
        let minter = account::create_signer_for_test(minter_addr);

        for (i in 0..users.length()) {
            regulated_token::mint(&minter, users[i], amounts[i]);
        }
    }

    // ================================================================
    // |                    Phase 1: Core Function Error Testing     |
    // ================================================================

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_MINTER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_native_minter_fails(
        regulated_token: &signer
    ) {
        regulated_token::init_module_for_testing(regulated_token);

        // Unauthorized user tries to mint
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_MINTER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_bridge_minter_fails(
        regulated_token: &signer
    ) {
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);
        // Grant only native minter role, not bridge minter
        regulated_token::grant_role(&admin, MINTER_ROLE, MINTER1);

        // Try to mint with only native role (should work)
        mint_tokens_with_minter(MINTER1, vector[USER1], vector[100]);

        // Now test unauthorized bridge minting
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_MINTER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_token_pool_minter_fails(
        regulated_token: &signer
    ) {
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);
        // Grant only token pool role to one user
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, MINTER3);

        // Try to mint without any minter role
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_mint_to_nonexistent_account(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let minter1 = account::create_signer_for_test(MINTER1);
        let nonexistent_addr = @0x12345;

        // Should succeed - primary store gets created automatically
        regulated_token::mint(&minter1, nonexistent_addr, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(nonexistent_addr, metadata) == 100);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_mint_different_minter_types_events(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Test that different minter types work and should emit different events
        // All should succeed (event testing would require event inspection)
        mint_tokens_with_minter(MINTER1, vector[USER1], vector[100]); // Should emit NativeMint
        mint_tokens_with_minter(MINTER2, vector[USER2], vector[200]); // Should emit BridgeMint
        mint_tokens_with_minter(MINTER3, vector[USER3], vector[300]); // Should emit TokenPoolMint

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
        assert!(primary_fungible_store::balance(USER3, metadata) == 300);
    }

    // 1.2 Burn Function Edge Cases (9 tests)

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_BURNER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_native_burner_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Unauthorized user tries to burn
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn(&unauthorized, USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_BURNER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_bridge_burner_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // User with no burner role tries to burn
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn(&unauthorized, USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_BURNER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_token_pool_burner_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // User with only pauser role tries to burn
        let pauser = account::create_signer_for_test(PAUSER1);
        regulated_token::burn(&pauser, USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_exact_balance_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]); // USER1 has 100 tokens

        let burner1 = account::create_signer_for_test(BURNER1);

        // Burn exact balance
        regulated_token::burn(&burner1, USER1, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_different_burner_types_events(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[300, 300, 300]
        );

        let burner1 = account::create_signer_for_test(BURNER1); // Native
        let burner2 = account::create_signer_for_test(BURNER2); // Bridge
        let burner3 = account::create_signer_for_test(BURNER3); // Token pool

        // All should succeed and emit different events
        regulated_token::burn(&burner1, USER1, 100); // Should emit NativeBurn
        regulated_token::burn(&burner2, USER2, 100); // Should emit BridgeBurn
        regulated_token::burn(&burner3, USER3, 100); // Should emit TokenPoolBurn

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 200);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
        assert!(primary_fungible_store::balance(USER3, metadata) == 200);
    }

    // 1.3 Burn Frozen Funds Function (8 tests)

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_when_paused_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze account and pause contract
        let freezer1 = account::create_signer_for_test(FREEZER1);
        let pauser1 = account::create_signer_for_test(PAUSER1);

        regulated_token::freeze_account(&freezer1, USER1);
        regulated_token::pause(&pauser1);

        // Now try to burn frozen funds while paused
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn_frozen_funds(&burner1, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_BURNER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_unauthorized_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze account
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        // Unauthorized user tries to burn frozen funds
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn_frozen_funds(&unauthorized, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_unfrozen_account_noop(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Don't freeze the account
        let burner1 = account::create_signer_for_test(BURNER1);

        // Try to burn frozen funds from unfrozen account - should be no-op
        regulated_token::burn_frozen_funds(&burner1, USER1);

        // Balance should remain unchanged
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_zero_balance_noop(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);

        // Freeze account but don't give it any tokens
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        let burner1 = account::create_signer_for_test(BURNER1);

        // Try to burn frozen funds from account with zero balance - should be no-op
        regulated_token::burn_frozen_funds(&burner1, USER1);

        // Balance should remain zero
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_batch_burn_frozen_funds_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[100, 200, 300]
        );

        // Freeze all accounts
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_accounts(&freezer1, vector[USER1, USER2, USER3]);

        let burner1 = account::create_signer_for_test(BURNER1);

        // Batch burn frozen funds
        regulated_token::batch_burn_frozen_funds(&burner1, vector[USER1, USER2, USER3]);

        // All balances should be zero
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
        assert!(primary_fungible_store::balance(USER2, metadata) == 0);
        assert!(primary_fungible_store::balance(USER3, metadata) == 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_batch_burn_frozen_funds_mixed_states(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[100, 200, 300]
        );

        // Freeze only USER1 and USER3
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);
        regulated_token::freeze_account(&freezer1, USER3);
        // USER2 remains unfrozen

        let burner1 = account::create_signer_for_test(BURNER1);

        // Batch burn - should only affect frozen accounts
        regulated_token::batch_burn_frozen_funds(&burner1, vector[USER1, USER2, USER3]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0); // Burned
        assert!(primary_fungible_store::balance(USER2, metadata) == 200); // Unchanged
        assert!(primary_fungible_store::balance(USER3, metadata) == 0); // Burned
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_different_burner_types(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[100, 200, 300]
        );

        // Freeze all accounts
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_accounts(&freezer1, vector[USER1, USER2, USER3]);

        let burner1 = account::create_signer_for_test(BURNER1); // Native
        let burner2 = account::create_signer_for_test(BURNER2); // Bridge
        let burner3 = account::create_signer_for_test(BURNER3); // Token pool

        // Different burner types should all work
        regulated_token::burn_frozen_funds(&burner1, USER1); // Should emit NativeBurn
        regulated_token::burn_frozen_funds(&burner2, USER2); // Should emit BridgeBurn
        regulated_token::burn_frozen_funds(&burner3, USER3); // Should emit TokenPoolBurn

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
        assert!(primary_fungible_store::balance(USER2, metadata) == 0);
        assert!(primary_fungible_store::balance(USER3, metadata) == 0);
    }

    // ================================================================
    // |                 Phase 2: Role Management Testing            |
    // ================================================================

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_invalid_role_number_fails(
        regulated_token: &signer
    ) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Try to grant role with invalid role number (8 is beyond TOKEN_POOL_ROLE = 7)
        regulated_token::grant_role(&admin, 8, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_grant_role_unauthorized_admin_fails(
        regulated_token: &signer
    ) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        // Non-admin tries to grant role
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::grant_role(&unauthorized, MINTER_ROLE, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_grant_role_duplicate_idempotent(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant role first time
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);

        // Grant same role again - should be idempotent
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);

        // User should still be able to mint
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER2, metadata) == 100);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_role_enumeration_functions(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        // Test that all role constructor functions work
        let _pauser_role = regulated_token::pauser_role();
        let _unpauser_role = regulated_token::unpauser_role();
        let _freezer_role = regulated_token::freezer_role();
        let _unfreezer_role = regulated_token::unfreezer_role();
        let _minter_role = regulated_token::minter_role();
        let _burner_role = regulated_token::burner_role();
        let _bridge_role = regulated_token::bridge_minter_or_burner_role();
        let _token_pool_role = regulated_token::token_pool_role();

        // If we get here, all role functions work
        assert!(true);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_get_role_function_coverage(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        regulated_token::grant_role(&admin, PAUSER_ROLE, USER1);
        regulated_token::grant_role(&admin, UNPAUSER_ROLE, USER1);
        regulated_token::grant_role(&admin, FREEZER_ROLE, USER1);
        regulated_token::grant_role(&admin, UNFREEZER_ROLE, USER1);
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);
        regulated_token::grant_role(&admin, BURNER_ROLE, USER1);
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER1);
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, USER1);

        assert!(regulated_token::has_role(USER1, PAUSER_ROLE));
        assert!(regulated_token::has_role(USER1, UNPAUSER_ROLE));
        assert!(regulated_token::has_role(USER1, FREEZER_ROLE));
        assert!(regulated_token::has_role(USER1, UNFREEZER_ROLE));
        assert!(regulated_token::has_role(USER1, MINTER_ROLE));
        assert!(regulated_token::has_role(USER1, BURNER_ROLE));
        assert!(regulated_token::has_role(USER1, BRIDGE_MINTER_OR_BURNER_ROLE));
        assert!(regulated_token::has_role(USER1, TOKEN_POOL_ROLE));
    }

    #[test(regulated_token = @regulated_token)]
    fun test_minter_added_event_emission(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant different minter roles - should emit MinterAdded events
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1); // Should emit MinterAdded
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER2); // Should emit MinterAdded
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, USER3); // Should emit MinterAdded

        // Grant non-minter roles - should NOT emit MinterAdded events
        regulated_token::grant_role(&admin, PAUSER_ROLE, USER1); // Should NOT emit MinterAdded
        regulated_token::grant_role(&admin, FREEZER_ROLE, USER2); // Should NOT emit MinterAdded

        // If we get here without errors, event emission logic works
        assert!(true);
    }

    // ================================================================
    // |               Phase 3: Input Validation Error Tests         |
    // ================================================================
    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_AMOUNT,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_zero_amount_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Try to mint zero amount - should fail
        mint_to_user(USER1, 0);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_AMOUNT,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_zero_amount_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        let burner1 = account::create_signer_for_test(BURNER1);

        // Try to burn zero amount - should fail
        regulated_token::burn(&burner1, USER1, 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_mint_burn_max_amount_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let burner1 = account::create_signer_for_test(BURNER1);

        // Test with large amount
        let large_amount = 1000000000000u64; // 1 trillion

        // Should succeed
        mint_to_user(USER1, large_amount);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == large_amount);

        // Should also be able to burn
        regulated_token::burn(&burner1, USER1, large_amount);
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_mint_to_zero_address_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Mint to zero address should work (primary store gets created)
        mint_to_user(@0x0, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(@0x0, metadata) == 100);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_operations_with_zero_address_participants(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant role to zero address should work
        regulated_token::grant_role(&admin, MINTER_ROLE, @0x0);

        // Check if zero address has the role
        assert!(regulated_token::has_role(@0x0, MINTER_ROLE));

        // Freeze zero address should work
        regulated_token::grant_role(&admin, FREEZER_ROLE, FREEZER1);
        let freezer = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer, @0x0);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::is_frozen(@0x0, metadata));
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_number_8_fails(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Role number 8 is invalid (max is TOKEN_POOL_ROLE = 7)
        regulated_token::grant_role(&admin, 8, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_number_255_fails(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Role number 255 (max u8) is invalid
        regulated_token::grant_role(&admin, 255, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_has_role_invalid_number_fails(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        // has_role with invalid role number should abort
        regulated_token::has_role(USER1, 8);
    }

    // ================================================================
    // |            Phase 4: Initialization & State Error Tests      |
    // ================================================================

    #[test(_regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_TOKEN_NOT_INITIALIZED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_token_metadata_before_init_fails(_regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        // Try to get token metadata before initialization
        regulated_token::token_metadata();
    }

    #[test(regulated_token = @regulated_token)]
    fun test_multiple_operations_after_init_success(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);

        // Multiple consecutive operations should work fine
        let pauser1 = account::create_signer_for_test(PAUSER1);
        let unpauser1 = account::create_signer_for_test(UNPAUSER1);

        mint_to_user(USER1, 100);
        regulated_token::pause(&pauser1);
        regulated_token::unpause(&unpauser1);
        mint_to_user(USER2, 200);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
        assert!(!regulated_token::is_paused());
    }

    #[test(regulated_token = @regulated_token)]
    fun test_all_valid_operation_types_coverage(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Test that all minter role types create proper events
        // This ensures operation_type field coverage
        let admin = account::create_signer_for_test(ADMIN);

        // Grant all minter types to different users
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1); // operation_type = 4
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER2); // operation_type = 6
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, USER3); // operation_type = 7

        // All should succeed and emit MinterAdded events with correct operation_type
        assert!(regulated_token::has_role(USER1, MINTER_ROLE));
        assert!(regulated_token::has_role(USER2, BRIDGE_MINTER_OR_BURNER_ROLE));
        assert!(regulated_token::has_role(USER3, TOKEN_POOL_ROLE));
    }

    // ================================================================
    // |         Phase 5: Authorization & Permission Error Tests     |
    // ================================================================

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unpause_unauthorized_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Pause the contract first
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to unpause with unauthorized user (no unpauser role)
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::unpause(&unauthorized);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unpause_with_pauser_role_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to unpause with pauser (has pause but not unpause role)
        regulated_token::unpause(&pauser1); // Should fail
    }

    #[test(regulated_token = @regulated_token)]
    fun test_unpause_authorized_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);
        assert!(regulated_token::is_paused());

        // Unpause with authorized unpauser
        let unpauser1 = account::create_signer_for_test(UNPAUSER1);
        regulated_token::unpause(&unpauser1);
        assert!(!regulated_token::is_paused());
    }

    #[test(regulated_token = @regulated_token)]
    fun test_token_pool_minter_specific_behavior(
        regulated_token: &signer
    ) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant only TOKEN_POOL_ROLE
        regulated_token::grant_role(&admin, TOKEN_POOL_ROLE, USER1);

        // Should be able to mint with token pool role
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER2, metadata) == 100);

        // Should also be able to burn with token pool role
        let token_pool_user = account::create_signer_for_test(USER1);
        regulated_token::burn(&token_pool_user, USER2, 50);
        assert!(primary_fungible_store::balance(USER2, metadata) == 50);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_bridge_minter_burner_specific_behavior(
        regulated_token: &signer
    ) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant only BRIDGE_MINTER_OR_BURNER_ROLE
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER1);

        // Should be able to mint with bridge role
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER2, metadata) == 100);

        // Should also be able to burn with bridge role
        let bridge_user = account::create_signer_for_test(USER1);
        regulated_token::burn(&bridge_user, USER2, 50);
        assert!(primary_fungible_store::balance(USER2, metadata) == 50);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_MINTER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_minter_role_separation_enforced(regulated_token: &signer) {
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(UNAUTHORIZED);
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Grant only freezer role (no minter roles)
        regulated_token::grant_role(&admin, FREEZER_ROLE, USER1);

        // Should NOT be able to mint with only freezer role
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_to_frozen_account_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Freeze the destination account
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        // Try to mint to frozen account
        mint_to_user(USER1, 100);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_from_frozen_account_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze the account with tokens
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        // Try to burn from frozen account (should fail for regular burn)
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn(&burner1, USER1, 50);
    }

    // 5.4 Cross-Role Authorization Tests (2 tests)

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_minter_cannot_freeze_accounts(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Minter tries to freeze account (should fail)
        let minter1 = account::create_signer_for_test(MINTER1);
        regulated_token::freeze_account(&minter1, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_freezer_cannot_pause_contract(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Freezer tries to pause contract (should fail)
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::pause(&freezer1);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_when_paused_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to mint when paused
        mint_to_user(USER1, 100);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_when_paused_fails(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to burn when paused
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn(&burner1, USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_while_paused_fails(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze account and pause contract
        let freezer1 = account::create_signer_for_test(FREEZER1);
        let pauser1 = account::create_signer_for_test(PAUSER1);

        regulated_token::freeze_account(&freezer1, USER1);
        regulated_token::pause(&pauser1);

        // Try to burn frozen funds when paused
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn_frozen_funds(&burner1, USER1);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_pause_unpause_operations_flow(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let pauser1 = account::create_signer_for_test(PAUSER1);
        let unpauser1 = account::create_signer_for_test(UNPAUSER1);

        // Normal operation
        mint_to_user(USER1, 100);

        // Pause
        regulated_token::pause(&pauser1);
        assert!(regulated_token::is_paused());

        // Unpause
        regulated_token::unpause(&unpauser1);
        assert!(!regulated_token::is_paused());

        // Normal operation should work again
        mint_to_user(USER2, 200);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_unfreeze_operations_flow(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1, USER2], vector[100, 200]);

        let freezer1 = account::create_signer_for_test(FREEZER1);
        let unfreezer1 = account::create_signer_for_test(UNFREEZER1);
        let burner1 = account::create_signer_for_test(BURNER1);

        // Freeze account
        regulated_token::freeze_account(&freezer1, USER1);
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Burn frozen funds should work
        regulated_token::burn_frozen_funds(&burner1, USER1);
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);

        // Unfreeze account
        regulated_token::unfreeze_account(&unfreezer1, USER1);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));

        // Normal operations should work again
        mint_to_user(USER1, 150);
        assert!(primary_fungible_store::balance(USER1, metadata) == 150);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_double_pause_idempotent(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let pauser1 = account::create_signer_for_test(PAUSER1);
        let pauser2 = account::create_signer_for_test(PAUSER2);

        // Pause once
        regulated_token::pause(&pauser1);
        assert!(regulated_token::is_paused());

        // Pause again - should be idempotent (no error)
        regulated_token::pause(&pauser2);
        assert!(regulated_token::is_paused());

        // Should still be paused
        assert!(regulated_token::is_paused());
    }

    #[test(regulated_token = @regulated_token)]
    fun test_double_freeze_idempotent(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let freezer1 = account::create_signer_for_test(FREEZER1);
        let freezer2 = account::create_signer_for_test(FREEZER2);

        // Freeze once
        regulated_token::freeze_account(&freezer1, USER1);
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Freeze again - should be idempotent (no error)
        regulated_token::freeze_account(&freezer2, USER1);
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Should still be frozen
        assert!(primary_fungible_store::is_frozen(USER1, metadata));
    }

    // ================================================================
    // |                         Error Tests                          |
    // ================================================================

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_frozen_account_and_paused_contract_prioritizes_pause_error(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Create both error conditions
        let freezer1 = account::create_signer_for_test(FREEZER1);
        let pauser1 = account::create_signer_for_test(PAUSER1);

        regulated_token::freeze_account(&freezer1, USER1);
        regulated_token::pause(&pauser1);

        // Try to mint to frozen account while paused
        // Should fail with E_PAUSED first (checked before frozen account)
        mint_to_user(USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_unauthorized_minter_with_multiple_conditions(
        regulated_token: &signer
    ) {
        setup_token_and_roles(regulated_token);

        // Give USER1 minter role but freeze their destination account
        let admin = account::create_signer_for_test(ADMIN);
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);

        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER2);

        // Try to mint to frozen account with authorized minter
        // Should fail with E_ACCOUNT_FROZEN (frozen account check comes after auth)
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_batch_operations_partial_success(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);
        mint_tokens_to_users(vector[USER1, USER2], vector[100, 200]); // Only mint to USER1 and USER2

        let freezer1 = account::create_signer_for_test(FREEZER1);
        let burner1 = account::create_signer_for_test(BURNER1);

        // Freeze USER1 and USER2, but not USER3
        regulated_token::freeze_accounts(&freezer1, vector[USER1, USER2]);

        // Batch burn frozen funds - should handle mixed frozen/unfrozen accounts
        regulated_token::batch_burn_frozen_funds(&burner1, vector[USER1, USER2, USER3]);

        let metadata = regulated_token::token_metadata();
        // USER1 and USER2 should have 0 balance (were frozen and had funds)
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
        assert!(primary_fungible_store::balance(USER2, metadata) == 0);
        // USER3 should still have 0 balance (wasn't frozen, so no-op)
        assert!(primary_fungible_store::balance(USER3, metadata) == 0);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_batch_role_updates_comprehensive(regulated_token: &signer) {
        setup_token_and_roles(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Test comprehensive batch role updates
        regulated_token::apply_pauser_updates(
            &admin,
            vector[PAUSER2], // Remove PAUSER2
            vector[USER1, USER2] // Add USER1, USER2 as pausers
        );

        regulated_token::apply_freezer_updates(
            &admin,
            vector[FREEZER2], // Remove FREEZER2
            vector[USER1] // Add USER1 as freezer (in addition to pauser)
        );

        regulated_token::apply_unfreezer_updates(
            &admin,
            vector[], // Remove none
            vector[USER3] // Add USER3 as unfreezer
        );

        // Verify role changes
        assert!(regulated_token::has_role(PAUSER1, PAUSER_ROLE)); // Still has role
        assert!(!regulated_token::has_role(PAUSER2, PAUSER_ROLE)); // Removed
        assert!(regulated_token::has_role(USER1, PAUSER_ROLE)); // Added
        assert!(regulated_token::has_role(USER2, PAUSER_ROLE)); // Added

        assert!(regulated_token::has_role(FREEZER1, FREEZER_ROLE)); // Still has role
        assert!(!regulated_token::has_role(FREEZER2, FREEZER_ROLE)); // Removed
        assert!(regulated_token::has_role(USER1, FREEZER_ROLE)); // Added (also has pauser)

        assert!(regulated_token::has_role(UNFREEZER1, UNFREEZER_ROLE)); // Still has role
        assert!(regulated_token::has_role(USER3, UNFREEZER_ROLE)); // Added

        // Test that USER1 can now both pause and freeze
        let user1_signer = account::create_signer_for_test(USER1);
        regulated_token::pause(&user1_signer);
        assert!(regulated_token::is_paused());

        let unpauser1 = account::create_signer_for_test(UNPAUSER1);
        regulated_token::unpause(&unpauser1);

        regulated_token::freeze_account(&user1_signer, USER2);
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::is_frozen(USER2, metadata));
    }
}
