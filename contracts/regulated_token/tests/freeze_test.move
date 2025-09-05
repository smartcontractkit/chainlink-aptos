#[test_only]
module regulated_token::freeze_test {
    use std::account;
    use std::option;
    use std::primary_fungible_store;
    use std::object;
    use std::string;

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const FREEZER: address = @0x100;
    const USER1: address = @0x200;
    const USER2: address = @0x300;

    fun setup(admin: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );
        regulated_token::init_module_for_testing(regulated_token);

        regulated_token::initialize(
            admin,
            option::none(), // max_supply
            string::utf8(b"Regulated Token"), // name
            string::utf8(b"RT"), // symbol
            6, // decimals
            string::utf8(
                b"https://regulatedtoken.com/images/pic.png"
            ), // icon
            string::utf8(b"https://regulatedtoken.com") // project
        );

        regulated_token::grant_role(admin, 2, FREEZER); // FREEZER_ROLE = 2
        regulated_token::grant_role(admin, 3, FREEZER); // UNFREEZER_ROLE = 3
        regulated_token::grant_role(admin, 4, FREEZER); // MINTER_ROLE = 4 (for testing mints)
        regulated_token::grant_role(admin, 5, FREEZER); // BURNER_ROLE = 5 (for testing burns)
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
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Now should be frozen
        assert!(primary_fungible_store::is_frozen(USER1, metadata));
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
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Then unfreeze
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
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
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
        assert!(!primary_fungible_store::is_frozen(USER2, metadata));

        // Freeze both accounts
        regulated_token::freeze_accounts(&freezer, vector[USER1, USER2]);

        // Both should be frozen
        assert!(primary_fungible_store::is_frozen(USER1, metadata));
        assert!(primary_fungible_store::is_frozen(USER2, metadata));
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
        assert!(primary_fungible_store::is_frozen(USER1, metadata));
        assert!(primary_fungible_store::is_frozen(USER2, metadata));

        // Unfreeze both
        regulated_token::unfreeze_accounts(&freezer, vector[USER1, USER2]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
        assert!(!primary_fungible_store::is_frozen(USER2, metadata));
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
        assert!(primary_fungible_store::is_frozen(USER1, metadata));
        assert!(primary_fungible_store::is_frozen(USER2, metadata));

        // Unfreeze only USER1
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
        assert!(primary_fungible_store::is_frozen(USER2, metadata)); // USER2 still frozen
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
        assert!(initial_balance == 100);

        // Admin can burn frozen funds
        regulated_token::burn_frozen_funds(&admin, USER1);

        // Balance should be 0 now
        let final_balance = primary_fungible_store::balance(USER1, metadata);
        assert!(final_balance == 0);
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
            assert!(!primary_fungible_store::is_frozen(USER1, metadata));

            // Freeze
            regulated_token::freeze_accounts(&freezer, vector[USER1]);
            assert!(primary_fungible_store::is_frozen(USER1, metadata));

            // Unfreeze
            regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        };

        // Should end unfrozen
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
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
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Freeze again (should be idempotent)
        regulated_token::freeze_accounts(&freezer, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Unfreeze once
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata));
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_is_frozen_function(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        let freezer = account::create_signer_for_test(FREEZER);

        // Initially not frozen
        assert!(!regulated_token::is_frozen(USER1));
        assert!(!regulated_token::is_frozen(USER2));

        // Freeze USER1
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Check is_frozen function
        assert!(regulated_token::is_frozen(USER1));
        assert!(!regulated_token::is_frozen(USER2)); // USER2 still not frozen

        // Freeze USER2 as well
        regulated_token::freeze_accounts(&freezer, vector[USER2]);
        assert!(regulated_token::is_frozen(USER1));
        assert!(regulated_token::is_frozen(USER2));

        // Unfreeze USER1
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);
        assert!(!regulated_token::is_frozen(USER1));
        assert!(regulated_token::is_frozen(USER2)); // USER2 still frozen
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_empty(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // No accounts frozen initially
        let (accounts, next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts.length() == 0);
        assert!(next_key == @0x0);
        assert!(!has_more);
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
        assert!(accounts.length() == 1);
        assert!(accounts[0] == USER1);
        assert!(next_key == USER1); // Last key returned
        assert!(!has_more); // No more accounts
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
        assert!(accounts.length() == 2);
        assert!(accounts.contains(&USER1));
        assert!(accounts.contains(&USER2));
        assert!(!has_more); // No more accounts

        // Test pagination with limit 1
        let (accounts_page1, next_key_page1, has_more_page1) =
            regulated_token::get_all_frozen_accounts(@0x0, 1);
        assert!(accounts_page1.length() == 1);
        assert!(has_more_page1); // Should have more since we only got 1 of 2

        // Get second page
        let (accounts_page2, _next_key_page2, has_more_page2) =
            regulated_token::get_all_frozen_accounts(next_key_page1, 1);
        assert!(accounts_page2.length() == 1);
        assert!(!has_more_page2); // No more after getting the second account

        // Combined pages should have both accounts
        let all_paginated_accounts = accounts_page1;
        all_paginated_accounts.append(accounts_page2);
        assert!(all_paginated_accounts.contains(&USER1));
        assert!(all_paginated_accounts.contains(&USER2));
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
        assert!(accounts_before.length() == 2);

        // Unfreeze one account
        regulated_token::unfreeze_accounts(&freezer, vector[USER1]);

        // Verify only one remains in frozen list
        let (accounts_after, _next_key, _has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(accounts_after.length() == 1);
        assert!(accounts_after[0] == USER2);
        assert!(!accounts_after.contains(&USER1)); // USER1 should not be in frozen list
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
        assert!(accounts.length() == 0);
        assert!(next_key == @0x0); // Should return start key unchanged
        assert!(has_more); // Should indicate there are accounts available
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_frozen_funds_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let frozen_user = USER1;
        let recovery_recipient = @0x600;
        let initial_amount = 1000u64;

        account::create_account_for_test(frozen_user);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery role to recovery_manager
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7

        let metadata = regulated_token::token_metadata();

        // Mint tokens to frozen user
        regulated_token::mint(&freezer, frozen_user, initial_amount);
        assert!(primary_fungible_store::balance(frozen_user, metadata) == initial_amount);

        // Freeze the user's account
        regulated_token::freeze_accounts(&freezer, vector[frozen_user]);
        assert!(primary_fungible_store::is_frozen(frozen_user, metadata));

        // Recover frozen funds
        regulated_token::recover_frozen_funds(
            &recovery_signer, frozen_user, recovery_recipient
        );

        // Verify funds were transferred
        assert!(primary_fungible_store::balance(frozen_user, metadata) == 0);
        assert!(
            primary_fungible_store::balance(recovery_recipient, metadata)
                == initial_amount
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_batch_recover_frozen_funds_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let frozen_user1 = USER1;
        let frozen_user2 = USER2;
        let recovery_recipient = @0x600;
        let amount1 = 1000u64;
        let amount2 = 2000u64;

        account::create_account_for_test(frozen_user1);
        account::create_account_for_test(frozen_user2);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery role to recovery_manager
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7

        let metadata = regulated_token::token_metadata();

        // Mint tokens to both users
        regulated_token::mint(&freezer, frozen_user1, amount1);
        regulated_token::mint(&freezer, frozen_user2, amount2);

        // Freeze both accounts
        regulated_token::freeze_accounts(&freezer, vector[frozen_user1, frozen_user2]);
        assert!(primary_fungible_store::is_frozen(frozen_user1, metadata));
        assert!(primary_fungible_store::is_frozen(frozen_user2, metadata));

        // Batch recover frozen funds
        regulated_token::batch_recover_frozen_funds(
            &recovery_signer,
            vector[frozen_user1, frozen_user2],
            recovery_recipient
        );

        // Verify all funds were transferred
        assert!(primary_fungible_store::balance(frozen_user1, metadata) == 0);
        assert!(primary_fungible_store::balance(frozen_user2, metadata) == 0);
        assert!(
            primary_fungible_store::balance(recovery_recipient, metadata)
                == amount1 + amount2
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_recover_frozen_funds_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let unauthorized_user = @0x500;
        let frozen_user = USER1;
        let recovery_recipient = @0x600;

        account::create_account_for_test(frozen_user);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(unauthorized_user);

        let freezer = account::create_signer_for_test(FREEZER);
        let unauthorized_signer = account::create_signer_for_test(unauthorized_user);

        regulated_token::mint(&freezer, frozen_user, 1000);
        regulated_token::freeze_accounts(&freezer, vector[frozen_user]);

        // Should fail because unauthorized_user doesn't have RECOVERY_ROLE
        regulated_token::recover_frozen_funds(
            &unauthorized_signer, frozen_user, recovery_recipient
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_ACCOUNT_MUST_BE_FROZEN_FOR_RECOVERY,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_frozen_funds_from_unfrozen_account_reverts(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let unfrozen_user = USER1;
        let recovery_recipient = @0x600;
        let initial_amount = 1000u64;

        account::create_account_for_test(unfrozen_user);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery role to recovery_manager
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7

        // Mint tokens to unfrozen user (don't freeze)
        regulated_token::mint(&freezer, unfrozen_user, initial_amount);

        // Try to recover from unfrozen account - should revert
        regulated_token::recover_frozen_funds(
            &recovery_signer, unfrozen_user, recovery_recipient
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_frozen_funds_zero_balance_no_op(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let frozen_user = USER1;
        let recovery_recipient = @0x600;

        account::create_account_for_test(frozen_user);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery role to recovery_manager
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7

        let metadata = regulated_token::token_metadata();

        // Freeze the user's account (but no tokens minted)
        regulated_token::freeze_accounts(&freezer, vector[frozen_user]);
        assert!(primary_fungible_store::is_frozen(frozen_user, metadata));
        assert!(primary_fungible_store::balance(frozen_user, metadata) == 0);

        // Try to recover from frozen account with zero balance - should be no-op
        regulated_token::recover_frozen_funds(
            &recovery_signer, frozen_user, recovery_recipient
        );

        // Verify no funds were transferred (zero balance)
        assert!(primary_fungible_store::balance(frozen_user, metadata) == 0);
        assert!(primary_fungible_store::balance(recovery_recipient, metadata) == 0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_ZERO_ADDRESS_NOT_ALLOWED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_frozen_funds_zero_address(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let frozen_user = USER1;

        account::create_account_for_test(frozen_user);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery role to recovery_manager
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7

        // Mint and freeze
        regulated_token::mint(&freezer, frozen_user, 1000);
        regulated_token::freeze_accounts(&freezer, vector[frozen_user]);

        // Should fail because recipient is zero address
        regulated_token::recover_frozen_funds(&recovery_signer, frozen_user, @0x0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_frozen_funds_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recovery_manager = @0x500;
        let frozen_user = USER1;
        let recovery_recipient = @0x600;

        account::create_account_for_test(frozen_user);
        account::create_account_for_test(recovery_recipient);
        account::create_account_for_test(recovery_manager);

        let admin_signer = account::create_signer_for_test(ADMIN);
        let freezer = account::create_signer_for_test(FREEZER);
        let recovery_signer = account::create_signer_for_test(recovery_manager);

        // Grant recovery and pauser roles
        regulated_token::grant_role(&admin_signer, 7, recovery_manager); // RECOVERY_ROLE = 7
        regulated_token::grant_role(&admin_signer, 0, ADMIN); // PAUSER_ROLE = 0

        // Mint and freeze
        regulated_token::mint(&freezer, frozen_user, 1000);
        regulated_token::freeze_accounts(&freezer, vector[frozen_user]);

        regulated_token::pause(&admin_signer);

        // Should fail because contract is paused
        regulated_token::recover_frozen_funds(
            &recovery_signer, frozen_user, recovery_recipient
        );
    }
}
