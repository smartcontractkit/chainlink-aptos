#[test_only]
module regulated_token::freeze_test {
    use std::account;
    use std::primary_fungible_store;
    use std::object;

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const FREEZER: address = @0x100;
    const USER1: address = @0x200;
    const USER2: address = @0x300;

    fun setup(owner: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(owner, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);
        regulated_token::grant_role(&admin, 2, FREEZER); // FREEZER_ROLE = 2
        regulated_token::grant_role(&admin, 3, FREEZER); // UNFREEZER_ROLE = 3
        regulated_token::grant_role(&admin, 4, FREEZER); // MINTER_ROLE = 4 (for testing mints)
        regulated_token::grant_role(&admin, 5, FREEZER); // BURNER_ROLE = 5 (for testing burns)
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_single_account(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Initially not frozen
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 1);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Now should be frozen
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 2);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unfreeze_single_account(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Freeze first
        regulated_token::freeze_accounts(&freezer, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 1);

        // Then unfreeze
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 2);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_multiple_accounts(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Initially not frozen
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 1);
        assert!(!primary_fungible_store::is_frozen(USER2, metadata), 2);

        // Freeze both accounts
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);

        // Both should be frozen
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 3);
        assert!(primary_fungible_store::is_frozen(USER2, metadata), 4);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unfreeze_multiple_accounts(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Freeze both first
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 1);
        assert!(primary_fungible_store::is_frozen(USER2, metadata), 2);

        // Unfreeze both
        regulated_token::unfreeze_accounts(&freezer, vector[USER1, USER2]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 3);
        assert!(!primary_fungible_store::is_frozen(USER2, metadata), 4);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_selective_unfreeze(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Freeze both
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 1);
        assert!(primary_fungible_store::is_frozen(USER2, metadata), 2);

        // Unfreeze only USER1
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 3);
        assert!(primary_fungible_store::is_frozen(USER2, metadata), 4); // USER2 still frozen
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_to_frozen_account_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Try to mint to frozen account (should fail)
        regulated_token::mint(&freezer, USER1, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_from_frozen_account_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Mint tokens first
        regulated_token::mint(&freezer, USER1, 100);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Try to burn from frozen account (should fail)
        regulated_token::burn(&freezer, USER1, 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant burner role to admin for burn_frozen_funds
        regulated_token::grant_role(&admin, 5, ADMIN); // BURNER_ROLE = 5

        // Mint tokens first
        regulated_token::mint(&freezer, USER1, 100);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        let metadata = regulated_token::token_metadata();
        let initial_balance = primary_fungible_store::balance(USER1, metadata);
        assert!(initial_balance == 100, 1);

        // Admin can burn frozen funds
        regulated_token::burn_frozen_funds(&admin, USER1);

        // Balance should be 0 now
        let final_balance = primary_fungible_store::balance(USER1, metadata);
        assert!(final_balance == 0, 2);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_freeze(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let unauthorized_user = account::create_signer_for_test(USER1);

        // User without freezer role tries to freeze (should fail)
        regulated_token::freeze_accounts(&unauthorized_user, vector[USER1]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_unfreeze(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let unauthorized_user = account::create_signer_for_test(USER1);

        // Freeze account first
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // User without unfreezer role tries to unfreeze (should fail)
        regulated_token::unfreeze_accounts(&unauthorized_user, vector[USER1]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_unfreeze_cycle(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Multiple freeze/unfreeze cycles
        for (i in 0..3) {
            // Start unfrozen
            assert!(!primary_fungible_store::is_frozen(USER1, metadata), i * 2);

            // Freeze
            regulated_token::freeze_accounts(&freezer, vector[USER1]);
            assert!(
                primary_fungible_store::is_frozen(USER1, metadata),
                i * 2 + 1
            );

            // Unfreeze
            regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        };

        // Should end unfrozen
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 6);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_empty_list(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        let freezer = account::create_signer_for_test(FREEZER);

        // Freezing empty list should not crash
        regulated_token::freeze_accounts(&freezer, vector[]);
        regulated_token::unfreeze_accounts(&freezer, vector[]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_idempotent(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let metadata = regulated_token::token_metadata();

        // Freeze once
        regulated_token::freeze_accounts(&freezer, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 1);

        // Freeze again (should be idempotent)
        regulated_token::freeze_accounts(&freezer, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 2);

        // Unfreeze once
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 3);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_is_frozen_function(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);

        // Initially not frozen
        assert!(!regulated_token::is_frozen(USER1), 1);
        assert!(!regulated_token::is_frozen(USER2), 2);

        // Freeze USER1
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Check is_frozen function
        assert!(regulated_token::is_frozen(USER1), 3);
        assert!(!regulated_token::is_frozen(USER2), 4); // USER2 still not frozen

        // Freeze USER2 as well
        regulated_token::freeze_accounts(&freezer, vector[USER2]);
        assert!(regulated_token::is_frozen(USER1), 5);
        assert!(regulated_token::is_frozen(USER2), 6);

        // Unfreeze USER1
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!regulated_token::is_frozen(USER1), 7);
        assert!(regulated_token::is_frozen(USER2), 8); // USER2 still frozen
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_empty(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // No accounts frozen initially
        let (accounts, next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts.length() == 0, 1);
        assert!(next_key == @0x0, 2);
        assert!(!has_more, 3);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_single(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze one account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Get all frozen accounts
        let (accounts, next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts.length() == 1, 1);
        assert!(accounts[0] == USER1, 2);
        assert!(next_key == USER1, 3); // Last key returned
        assert!(!has_more, 4); // No more accounts
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_multiple(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze multiple accounts
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);

        // Get all frozen accounts
        let (accounts, _next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts.length() == 2, 1);
        assert!(accounts.contains(&USER1), 2);
        assert!(accounts.contains(&USER2), 3);
        assert!(!has_more, 4); // No more accounts

        // Test pagination with limit 1
        let (accounts_page1, next_key_page1, has_more_page1) =
            regulated_token::get_all_frozen_accounts(@0x0, 1);
        assert!(accounts_page1.length() == 1, 5);
        assert!(has_more_page1, 6); // Should have more since we only got 1 of 2

        // Get second page
        let (accounts_page2, _next_key_page2, has_more_page2) =
            regulated_token::get_all_frozen_accounts(next_key_page1, 1);
        assert!(accounts_page2.length() == 1, 7);
        assert!(!has_more_page2, 8); // No more after getting the second account

        // Combined pages should have both accounts
        let all_paginated_accounts = accounts_page1;
        all_paginated_accounts.append(accounts_page2);
        assert!(all_paginated_accounts.contains(&USER1), 9);
        assert!(all_paginated_accounts.contains(&USER2), 10);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_after_unfreeze(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze both accounts
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);

        // Verify both are in frozen list
        let (accounts_before, _next_key, _has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts_before.length() == 2, 1);

        // Unfreeze one account
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);

        // Verify only one remains in frozen list
        let (accounts_after, _next_key, _has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts_after.length() == 1, 2);
        assert!(accounts_after[0] == USER2, 3);
        assert!(!accounts_after.contains(&USER1), 4); // USER1 should not be in frozen list
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_zero_limit(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Test with zero limit
        let (accounts, next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 0);
        assert!(accounts.length() == 0, 1);
        assert!(next_key == @0x0, 2); // Should return start key unchanged
        assert!(has_more, 3); // Should indicate there are accounts available
    }
}
