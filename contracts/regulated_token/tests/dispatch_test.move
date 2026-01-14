#[test_only]
module regulated_token::dispatch_test {
    use std::account;
    use std::primary_fungible_store;
    use std::signer;
    use std::object;
    use std::string;
    use std::option;
    use std::fungible_asset::{Self, Metadata};

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const USER1: address = @0x200;
    const USER2: address = @0x300;

    fun setup(admin: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );

        regulated_token::init_module_for_testing(regulated_token);

        // Initialize the token with default parameters - use the admin signer
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
    }

    fun setup_roles(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        // Grant all roles to admin for testing
        regulated_token::grant_role(admin, 0, admin_addr); // PAUSER_ROLE
        regulated_token::grant_role(admin, 1, admin_addr); // UNPAUSER_ROLE
        regulated_token::grant_role(admin, 2, admin_addr); // FREEZER_ROLE
        regulated_token::grant_role(admin, 3, admin_addr); // UNFREEZER_ROLE
        regulated_token::grant_role(admin, 4, admin_addr); // MINTER_ROLE
        regulated_token::grant_role(admin, 5, admin_addr); // BURNER_ROLE
    }

    // Flexible function to mint to any users with specified amounts
    fun mint_tokens_to_users(
        admin: &signer, users: vector<address>, amounts: vector<u64>
    ) {
        assert!(users.length() == amounts.length(), 0); // Ensure vectors match

        // Create accounts if they don't exist
        for (i in 0..users.length()) {
            account::create_account_for_test(users[i]);
            regulated_token::mint(admin, users[i], amounts[i]);
        }
    }

    // Convenience function for single user setup
    fun setup_user_with_tokens(admin: &signer, user: address, amount: u64) {
        account::create_account_for_test(user);
        regulated_token::mint(admin, user, amount);
    }

    // Backward compatibility wrapper - sets up USER1 and USER2 with same amount
    fun setup_accounts_with_tokens(admin: &signer, amount: u64) {
        mint_tokens_to_users(
            admin,
            vector[USER1, USER2],
            vector[amount, amount]
        );
    }

    // ================================================================
    // |                Dynamic Dispatch Trigger Tests               |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_transfer_triggers_dispatch_hooks(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        assert!(primary_fungible_store::balance(USER1, metadata) == 1000);
        assert!(primary_fungible_store::balance(USER2, metadata) == 1000);

        // Transfer should work normally (hooks allow it)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);

        // Verify transfer worked (proves hooks were called and allowed transfer)
        assert!(primary_fungible_store::balance(USER1, metadata) == 900);
        assert!(primary_fungible_store::balance(USER2, metadata) == 1100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_deposit_withdraw_trigger_hooks(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();
        let user1_signer = account::create_signer_for_test(USER1);

        // Withdraw tokens (should trigger our withdraw hook)
        let fa = primary_fungible_store::withdraw(&user1_signer, metadata, 100);
        assert!(primary_fungible_store::balance(USER1, metadata) == 900);

        // Deposit tokens back (should trigger our deposit hook)
        primary_fungible_store::deposit(USER2, fa);
        assert!(primary_fungible_store::balance(USER2, metadata) == 1100);
    }

    // ================================================================
    // |                 Pause Enforcement Tests                     |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_transfer_blocked_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Pause the contract
        regulated_token::pause(admin);
        assert!(regulated_token::is_paused());

        // Transfer should fail due to pause (via our dispatch hooks)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_withdraw_blocked_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Pause the contract
        regulated_token::pause(admin);

        // Withdraw should fail due to pause (via our dispatch hooks)
        let user1_signer = account::create_signer_for_test(USER1);
        let fa = primary_fungible_store::withdraw(&user1_signer, metadata, 100);

        // Clean up fungible asset to avoid drop error
        primary_fungible_store::deposit(USER1, fa);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_deposit_blocked_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();
        let user1_signer = account::create_signer_for_test(USER1);

        // Withdraw first (before pause)
        let fa = primary_fungible_store::withdraw(&user1_signer, metadata, 100);

        // Pause the contract
        regulated_token::pause(admin);

        // Deposit should fail due to pause (via our dispatch hooks)
        primary_fungible_store::deposit(USER2, fa);
    }

    // ================================================================
    // |                 Freeze Enforcement Tests                    |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = std::fungible_asset)]
    fun test_transfer_from_frozen_account_blocked(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Freeze USER1's account
        regulated_token::freeze_accounts(admin, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata));

        // Transfer from frozen account should fail (via our dispatch hooks)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = std::fungible_asset)]
    fun test_transfer_to_frozen_account_blocked(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Freeze USER2's account
        regulated_token::freeze_accounts(admin, vector[USER2]);
        assert!(primary_fungible_store::is_frozen(USER2, metadata), 1);

        // Transfer to frozen account should fail (via our dispatch hooks)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = std::fungible_asset)]
    fun test_withdraw_from_frozen_account_blocked(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Freeze USER1's account
        regulated_token::freeze_accounts(admin, vector[USER1]);

        // Withdraw from frozen account should fail (via our dispatch hooks)
        let user1_signer = account::create_signer_for_test(USER1);
        let fa = primary_fungible_store::withdraw(&user1_signer, metadata, 100);

        // Clean up fungible asset to avoid drop error
        primary_fungible_store::deposit(USER1, fa);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = std::fungible_asset)]
    fun test_deposit_to_frozen_account_blocked(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();
        let user1_signer = account::create_signer_for_test(USER1);

        // Withdraw first (before freezing)
        let fa = primary_fungible_store::withdraw(&user1_signer, metadata, 100);

        // Freeze USER2's account
        regulated_token::freeze_accounts(admin, vector[USER2]);

        // Deposit to frozen account should fail (via our dispatch hooks)
        primary_fungible_store::deposit(USER2, fa);
    }

    // ================================================================
    // |                    Hook Security Tests                      |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unfreeze_allows_transfers(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Freeze and then unfreeze USER1's account
        regulated_token::freeze_accounts(admin, vector[USER1]);
        assert!(primary_fungible_store::is_frozen(USER1, metadata), 1);

        regulated_token::unfreeze_accounts(admin, vector[USER1]);
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 2);

        // Transfer should now work (hooks allow unfrozen accounts)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);

        // Verify transfer worked
        assert!(primary_fungible_store::balance(USER1, metadata) == 900, 3);
        assert!(primary_fungible_store::balance(USER2, metadata) == 1100, 4);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unpause_allows_transfers(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Pause and then unpause
        regulated_token::pause(admin);
        assert!(regulated_token::is_paused(), 1);

        regulated_token::unpause(admin);
        assert!(!regulated_token::is_paused(), 2);

        // Transfer should now work (hooks allow unpaused state)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);

        // Verify transfer worked
        assert!(primary_fungible_store::balance(USER1, metadata) == 900, 3);
        assert!(primary_fungible_store::balance(USER2, metadata) == 1100, 4);
    }

    // ================================================================
    // |                 Combined Scenarios Tests                    |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_paused_overrides_unfrozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Ensure accounts are unfrozen but pause the contract
        assert!(!primary_fungible_store::is_frozen(USER1, metadata), 1);
        regulated_token::pause(admin);

        // Transfer should fail due to pause (even though not frozen)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = std::fungible_asset)]
    fun test_frozen_blocks_even_when_unpaused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        let metadata = regulated_token::token_metadata();

        // Ensure contract is unpaused but freeze account
        assert!(!regulated_token::is_paused(), 1);
        regulated_token::freeze_accounts(admin, vector[USER1]);

        // Transfer should fail due to freeze (even though not paused)
        let user1_signer = account::create_signer_for_test(USER1);
        primary_fungible_store::transfer(&user1_signer, metadata, USER2, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = regulated_token::regulated_token::E_INVALID_ASSET)]
    fun test_dispatch_with_wrong_transfer_ref(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);

        // Create a second fungible asset to get a different TransferRef
        let constructor_ref_2 = &object::create_named_object(admin, b"wrong_token");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref_2,
            option::none(),
            string::utf8(b"Wrong Token"),
            string::utf8(b"WRONG"),
            6,
            string::utf8(b"https://wrong.com"),
            string::utf8(b"https://wrong.com")
        );
        let wrong_transfer_ref = fungible_asset::generate_transfer_ref(constructor_ref_2);

        // Try to use wrong TransferRef with our regulated token store
        let metadata = regulated_token::token_metadata();
        let user_store =
            primary_fungible_store::ensure_primary_store_exists(USER1, metadata);

        // This should fail in assert_correct_asset() check
        let fa = fungible_asset::zero(metadata);
        regulated_token::deposit(user_store, fa, &wrong_transfer_ref);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = regulated_token::regulated_token::E_INVALID_ASSET)]
    fun test_dispatch_with_invalid_store(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(admin);
        setup_accounts_with_tokens(admin, 1000);

        // Create a store for a different token
        let constructor_ref_2 = &object::create_named_object(admin, b"other_token");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref_2,
            option::none(),
            string::utf8(b"Other Token"),
            string::utf8(b"OTHER"),
            6,
            string::utf8(b"https://other.com"),
            string::utf8(b"https://other.com")
        );
        let other_metadata =
            object::object_from_constructor_ref<Metadata>(constructor_ref_2);
        let other_store =
            primary_fungible_store::ensure_primary_store_exists(USER1, other_metadata);
        let transfer_ref = fungible_asset::generate_transfer_ref(constructor_ref_2);

        // Try to use our regulated token metadata with other token's store
        // This should fail in assert_correct_asset() check with E_INVALID_ASSET
        let fa = regulated_token::withdraw(other_store, 100, &transfer_ref);
        primary_fungible_store::deposit(USER1, fa);
    }
}
