#[test_only]
module regulated_token::freeze_test {
    use std::account;
    use std::primary_fungible_store;
    use std::signer;

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const FREEZER: address = @0x100;
    const USER1: address = @0x200;
    const USER2: address = @0x300;

    fun setup(regulated_token: &signer) {
        account::create_account_for_test(signer::address_of(regulated_token));
        regulated_token::init_module_for_testing(regulated_token);

        let admin = account::create_signer_for_test(ADMIN);
        regulated_token::grant_role(&admin, 2, FREEZER); // FREEZER_ROLE = 2
        regulated_token::grant_role(&admin, 3, FREEZER); // UNFREEZER_ROLE = 3
        regulated_token::grant_role(&admin, 4, FREEZER); // MINTER_ROLE = 4 (for testing mints)
        regulated_token::grant_role(&admin, 5, FREEZER); // BURNER_ROLE = 5 (for testing burns)
    }

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_single_account(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    fun test_unfreeze_single_account(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_multiple_accounts(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    fun test_unfreeze_multiple_accounts(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    fun test_selective_unfreeze(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_to_frozen_account_fails(regulated_token: &signer) {
        setup(regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Try to mint to frozen account (should fail)
        regulated_token::mint(&freezer, USER1, 100);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_from_frozen_account_fails(regulated_token: &signer) {
        setup(regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);

        // Mint tokens first
        regulated_token::mint(&freezer, USER1, 100);

        // Freeze the account
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // Try to burn from frozen account (should fail)
        regulated_token::burn(&freezer, USER1, 50);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_success(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_freeze(regulated_token: &signer) {
        setup(regulated_token);

        account::create_account_for_test(USER1);
        let unauthorized_user = account::create_signer_for_test(USER1);

        // User without freezer role tries to freeze (should fail)
        regulated_token::freeze_accounts(&unauthorized_user, vector[USER1]);
    }

    #[test(regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_unfreeze(regulated_token: &signer) {
        setup(regulated_token);

        account::create_account_for_test(USER1);
        let freezer = account::create_signer_for_test(FREEZER);
        let unauthorized_user = account::create_signer_for_test(USER1);

        // Freeze account first
        regulated_token::freeze_accounts(&freezer, vector[USER1]);

        // User without unfreezer role tries to unfreeze (should fail)
        regulated_token::unfreeze_accounts(&unauthorized_user, vector[USER1]);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_unfreeze_cycle(regulated_token: &signer) {
        setup(regulated_token);

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

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_empty_list(regulated_token: &signer) {
        setup(regulated_token);

        let freezer = account::create_signer_for_test(FREEZER);

        // Freezing empty list should not crash
        regulated_token::freeze_accounts(&freezer, vector[]);
        regulated_token::unfreeze_accounts(&freezer, vector[]);
    }

    #[test(regulated_token = @regulated_token)]
    fun test_freeze_idempotent(regulated_token: &signer) {
        setup(regulated_token);

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
}
