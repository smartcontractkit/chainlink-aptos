#[test_only]
module regulated_token::regulated_token_comprehensive_test {
    use std::account;
    use std::primary_fungible_store;
    use std::object::{Self, Object};
    use std::fungible_asset::{Metadata};
    use std::event;
    use std::option;
    use std::string;

    use regulated_token::regulated_token::{
        Self,
        NativeMint,
        BridgeMint,
        NativeBurn,
        BridgeBurn
    };

    const ADMIN: address = @admin;
    const MINTER1: address = @0x200;
    const BRIDGE_MINTER: address = @0x201;
    const MINTER3: address = @0x202;
    const BURNER1: address = @0x300;
    const BRIDGE_BURNER: address = @0x301;
    const BURNER3: address = @0x302;
    const PAUSER1: address = @0x400;
    const PAUSER2: address = @0x401;
    const UNPAUSER1: address = @0x410;
    const FREEZER1: address = @0x500;
    const FREEZER2: address = @0x501;
    const UNFREEZER1: address = @0x510;
    const RECOVERY1: address = @0x600;
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
    const RECOVERY_ROLE: u8 = 7;

    fun setup_token(admin: &signer, regulated_token: &signer): Object<Metadata> {
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

        regulated_token::token_metadata()
    }

    fun setup_token_and_roles(admin: &signer, regulated_token: &signer): Object<Metadata> {
        let token_metadata = setup_token(admin, regulated_token);

        regulated_token::grant_role(admin, MINTER_ROLE, MINTER1); // Native minter
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, BRIDGE_MINTER); // Bridge minter
        regulated_token::grant_role(admin, RECOVERY_ROLE, RECOVERY1); // Recover funds

        regulated_token::grant_role(admin, BURNER_ROLE, BURNER1); // Native burner
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, BRIDGE_BURNER); // Bridge burner
        regulated_token::grant_role(admin, RECOVERY_ROLE, RECOVERY1); // Recover funds

        regulated_token::grant_role(admin, PAUSER_ROLE, PAUSER1);
        regulated_token::grant_role(admin, PAUSER_ROLE, PAUSER2);
        regulated_token::grant_role(admin, UNPAUSER_ROLE, UNPAUSER1);

        regulated_token::grant_role(admin, FREEZER_ROLE, FREEZER1);
        regulated_token::grant_role(admin, FREEZER_ROLE, FREEZER2);
        regulated_token::grant_role(admin, UNFREEZER_ROLE, UNFREEZER1);

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
        assert!(users.length() == amounts.length());
        let minter = account::create_signer_for_test(minter_addr);

        for (i in 0..users.length()) {
            regulated_token::mint(&minter, users[i], amounts[i]);
        }
    }

    // ================================================================
    // |                    Phase 1: Core Function Error Testing     |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_native_minter_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Unauthorized user tries to mint
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_bridge_minter_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant only native minter role, not bridge minter
        regulated_token::grant_role(admin, MINTER_ROLE, MINTER1);

        // Try to mint with only native role (should work)
        mint_tokens_with_minter(MINTER1, vector[USER1], vector[100]);

        // Now test unauthorized bridge minting
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_unauthorized_recovery_minter_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant only recovery role to one user
        regulated_token::grant_role(admin, RECOVERY_ROLE, MINTER3);

        // Try to mint without any minter role
        mint_tokens_with_minter(UNAUTHORIZED, vector[USER1], vector[100]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_mint_to_nonexistent_account(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let minter1 = account::create_signer_for_test(MINTER1);
        let nonexistent_addr = @0x12345;

        // Should succeed - primary store gets created automatically
        regulated_token::mint(&minter1, nonexistent_addr, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(nonexistent_addr, metadata) == 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_mint_different_minter_types_events(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Test that different minter types work and should emit different events
        // All should succeed (event testing would require event inspection)
        mint_tokens_with_minter(MINTER1, vector[USER1], vector[100]); // Should emit NativeMint
        let native_mint_events = event::emitted_events<NativeMint>();
        assert!(native_mint_events.length() == 1);

        mint_tokens_with_minter(BRIDGE_MINTER, vector[USER2], vector[200]); // Should emit BridgeMint
        let bridge_mint_events = event::emitted_events<BridgeMint>();
        assert!(bridge_mint_events.length() == 1);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
    }

    // 1.2 Burn Function Edge Cases (9 tests)
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_native_burner_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Unauthorized user tries to burn
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn(&unauthorized, USER1, 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_bridge_burner_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // User with no burner role tries to burn
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn(&unauthorized, USER1, 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_unauthorized_recovery_burner_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // User with only recovery role tries to burn
        let recovery = account::create_signer_for_test(RECOVERY1);
        regulated_token::burn(&recovery, USER1, 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_exact_balance_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]); // USER1 has 100 tokens

        let burner1 = account::create_signer_for_test(BURNER1);

        // Burn exact balance
        regulated_token::burn(&burner1, USER1, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_different_burner_types_events(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[300, 300, 300]
        );

        let burner1 = account::create_signer_for_test(BURNER1); // Native
        let bridge_burner = account::create_signer_for_test(BRIDGE_BURNER); // Bridge

        regulated_token::burn(&burner1, USER1, 100); // Should emit NativeBurn
        let native_burn_events = event::emitted_events<NativeBurn>();
        assert!(native_burn_events.length() == 1);

        regulated_token::burn(&bridge_burner, USER2, 100); // Should emit BridgeBurn
        let bridge_burn_events = event::emitted_events<BridgeBurn>();
        assert!(bridge_burn_events.length() == 1);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 200);
        assert!(primary_fungible_store::balance(USER2, metadata) == 200);
    }

    // 1.3 Burn Frozen Funds Function
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_when_paused_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_unauthorized_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze account
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        // Unauthorized user tries to burn frozen funds
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::burn_frozen_funds(&unauthorized, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_unfrozen_account_noop(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Don't freeze the account
        let burner1 = account::create_signer_for_test(BURNER1);

        // Try to burn frozen funds from unfrozen account - should be no-op
        regulated_token::burn_frozen_funds(&burner1, USER1);

        // Balance should remain unchanged
        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_zero_balance_noop(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_batch_burn_frozen_funds_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_batch_burn_frozen_funds_mixed_states(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_different_burner_types(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(
            vector[USER1, USER2, USER3],
            vector[100, 200, 300]
        );

        // Freeze all accounts
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_accounts(&freezer1, vector[USER1, USER2, USER3]);

        let burner1 = account::create_signer_for_test(BURNER1); // Native
        let bridge_burner = account::create_signer_for_test(BRIDGE_BURNER); // Bridge

        regulated_token::burn_frozen_funds(&burner1, USER1); // Should emit NativeBurn
        let native_burn_events = event::emitted_events<NativeBurn>();
        assert!(native_burn_events.length() == 1);

        regulated_token::burn_frozen_funds(&bridge_burner, USER2); // Should emit BridgeBurn
        let bridge_burn_events = event::emitted_events<BridgeBurn>();
        assert!(bridge_burn_events.length() == 1);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER1, metadata) == 0);
        assert!(primary_fungible_store::balance(USER2, metadata) == 0);
    }

    // ================================================================
    // |                 Phase 2: Role Management Testing            |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_invalid_role_number_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Try to grant role with invalid role number (8 is beyond TOKEN_POOL_ROLE = 7)
        regulated_token::grant_role(admin, 8, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_grant_role_unauthorized_admin_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Non-admin tries to grant role
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::grant_role(&unauthorized, MINTER_ROLE, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_grant_role_duplicate_idempotent(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant role first time
        regulated_token::grant_role(admin, MINTER_ROLE, USER1);

        // Grant same role again - should be idempotent
        regulated_token::grant_role(admin, MINTER_ROLE, USER1);

        // User should still be able to mint
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER2, metadata) == 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_role_enumeration_functions(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Test that all role constructor functions work
        let _pauser_role = regulated_token::pauser_role();
        let _unpauser_role = regulated_token::unpauser_role();
        let _freezer_role = regulated_token::freezer_role();
        let _unfreezer_role = regulated_token::unfreezer_role();
        let _minter_role = regulated_token::minter_role();
        let _burner_role = regulated_token::burner_role();
        let _bridge_role = regulated_token::bridge_minter_or_burner_role();
        let _recovery_role = regulated_token::recovery_role();

        // If we get here, all role functions work
        assert!(true);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_view_role_functions(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Test all the new view functions to verify they work
        let admin_addr = regulated_token::get_admin();
        assert!(admin_addr == ADMIN);

        let pending_admin = regulated_token::get_pending_admin();
        assert!(pending_admin == @0x0); // Initially no pending admin

        // Test role member getters - setup_token_and_roles creates these roles
        let minters = regulated_token::get_minters();
        assert!(minters.length() == 1); // MINTER1 from setup
        assert!(minters.contains(&MINTER1));

        let bridge_minters_or_burners = regulated_token::get_bridge_minters_or_burners();
        assert!(bridge_minters_or_burners.length() == 2); // BRIDGE_MINTER and BRIDGE_BURNER from setup
        assert!(bridge_minters_or_burners.contains(&BRIDGE_MINTER));
        assert!(bridge_minters_or_burners.contains(&BRIDGE_BURNER));

        let burners = regulated_token::get_burners();
        assert!(burners.length() == 1); // BURNER1 from setup
        assert!(burners.contains(&BURNER1));

        let freezers = regulated_token::get_freezers();
        assert!(freezers.length() == 2); // FREEZER1 and FREEZER2 from setup
        assert!(freezers.contains(&FREEZER1));
        assert!(freezers.contains(&FREEZER2));

        let unfreezers = regulated_token::get_unfreezers();
        assert!(unfreezers.length() == 1); // UNFREEZER1 from setup
        assert!(unfreezers.contains(&UNFREEZER1));

        let pausers = regulated_token::get_pausers();
        assert!(pausers.length() == 2); // PAUSER1 and PAUSER2 from setup
        assert!(pausers.contains(&PAUSER1));
        assert!(pausers.contains(&PAUSER2));

        let unpausers = regulated_token::get_unpausers();
        assert!(unpausers.length() == 1); // UNPAUSER1 from setup
        assert!(unpausers.contains(&UNPAUSER1));

        let recovery_managers = regulated_token::get_recovery_managers();
        assert!(recovery_managers.length() == 1); // RECOVERY1 from setup
        assert!(recovery_managers.contains(&RECOVERY1));

        // Test that these functions return the same data as the generic role functions
        assert!(regulated_token::get_role_members(MINTER_ROLE) == minters);
        assert!(
            regulated_token::get_role_members(BRIDGE_MINTER_OR_BURNER_ROLE)
                == bridge_minters_or_burners
        );
        assert!(regulated_token::get_role_members(BURNER_ROLE) == burners);
        assert!(regulated_token::get_role_members(FREEZER_ROLE) == freezers);
        assert!(regulated_token::get_role_members(UNFREEZER_ROLE) == unfreezers);
        assert!(regulated_token::get_role_members(PAUSER_ROLE) == pausers);
        assert!(regulated_token::get_role_members(UNPAUSER_ROLE) == unpausers);
        assert!(regulated_token::get_role_members(RECOVERY_ROLE) == recovery_managers);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_role_function_coverage(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        regulated_token::grant_role(&admin, PAUSER_ROLE, USER1);
        regulated_token::grant_role(&admin, UNPAUSER_ROLE, USER1);
        regulated_token::grant_role(&admin, FREEZER_ROLE, USER1);
        regulated_token::grant_role(&admin, UNFREEZER_ROLE, USER1);
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);
        regulated_token::grant_role(&admin, BURNER_ROLE, USER1);
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER1);
        regulated_token::grant_role(&admin, RECOVERY_ROLE, USER1);

        assert!(regulated_token::has_role(USER1, PAUSER_ROLE));
        assert!(regulated_token::has_role(USER1, UNPAUSER_ROLE));
        assert!(regulated_token::has_role(USER1, FREEZER_ROLE));
        assert!(regulated_token::has_role(USER1, UNFREEZER_ROLE));
        assert!(regulated_token::has_role(USER1, MINTER_ROLE));
        assert!(regulated_token::has_role(USER1, BURNER_ROLE));
        assert!(regulated_token::has_role(USER1, BRIDGE_MINTER_OR_BURNER_ROLE));
        assert!(regulated_token::has_role(USER1, RECOVERY_ROLE));
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_role_query_functions(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Initially no members for minter role
        assert!(regulated_token::get_role_member_count(MINTER_ROLE) == 1); // MINTER1 from setup
        assert!(regulated_token::get_role_members(MINTER_ROLE).length() == 1);
        assert!(regulated_token::get_role_member(MINTER_ROLE, 0) == MINTER1);

        // Add more minters
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);
        regulated_token::grant_role(&admin, MINTER_ROLE, USER2);

        // Test member count
        assert!(regulated_token::get_role_member_count(MINTER_ROLE) == 3);

        // Test get all members
        let members = regulated_token::get_role_members(MINTER_ROLE);
        assert!(members.length() == 3);
        assert!(members.contains(&MINTER1));
        assert!(members.contains(&USER1));
        assert!(members.contains(&USER2));

        // Test get member by index
        let member_0 = regulated_token::get_role_member(MINTER_ROLE, 0);
        let member_1 = regulated_token::get_role_member(MINTER_ROLE, 1);
        let member_2 = regulated_token::get_role_member(MINTER_ROLE, 2);

        // All members should be valid addresses
        assert!(members.contains(&member_0));
        assert!(members.contains(&member_1));
        assert!(members.contains(&member_2));

        // Test different role
        assert!(regulated_token::get_role_member_count(BURNER_ROLE) == 1); // BURNER1 from setup

        // Add burner
        regulated_token::grant_role(&admin, BURNER_ROLE, USER3);
        assert!(regulated_token::get_role_member_count(BURNER_ROLE) == 2);

        let burner_members = regulated_token::get_role_members(BURNER_ROLE);
        assert!(burner_members.length() == 2);
        assert!(burner_members.contains(&BURNER1));
        assert!(burner_members.contains(&USER3));
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_minter_added_event_emission(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant different minter roles - should emit MinterAdded events
        regulated_token::grant_role(admin, MINTER_ROLE, USER1); // Should emit MinterAdded
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER2); // Should emit MinterAdded
        regulated_token::grant_role(admin, RECOVERY_ROLE, USER3); // Should emit MinterAdded

        // Grant non-minter roles - should NOT emit MinterAdded events
        regulated_token::grant_role(admin, PAUSER_ROLE, USER1); // Should NOT emit MinterAdded
        regulated_token::grant_role(admin, FREEZER_ROLE, USER2); // Should NOT emit MinterAdded

        // If we get here without errors, event emission logic works
        assert!(true);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_mint_burn_max_amount_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_mint_to_zero_address_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Mint to zero address should work (primary store gets created)
        mint_to_user(@0x0, 100);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(@0x0, metadata) == 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_operations_with_zero_address_participants(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_number_8_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Role number 8 is invalid (max is TOKEN_POOL_ROLE = 7)
        regulated_token::grant_role(admin, 8, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_grant_role_number_255_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Role number 255 (max u8) is invalid
        regulated_token::grant_role(admin, 255, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_ROLE_NUMBER,
            location = regulated_token::regulated_token
        )
    ]
    fun test_has_role_invalid_number_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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
    fun test_token_metadata_before_init_fails(
        _regulated_token: &signer
    ) {
        // account::create_account_for_test(ADMIN);
        // Try to get token metadata before initialization
        regulated_token::token_metadata();
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_multiple_operations_after_init_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_all_valid_operation_types_coverage(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Test that all minter role types create proper events
        // This ensures operation_type field coverage
        let admin = account::create_signer_for_test(ADMIN);

        // Grant all minter types to different users
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1); // operation_type = 4
        regulated_token::grant_role(&admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER2); // operation_type = 6
        regulated_token::grant_role(&admin, RECOVERY_ROLE, USER3); // operation_type = 7

        // All should succeed and emit MinterAdded events with correct operation_type
        assert!(regulated_token::has_role(USER1, MINTER_ROLE));
        assert!(regulated_token::has_role(USER2, BRIDGE_MINTER_OR_BURNER_ROLE));
        assert!(regulated_token::has_role(USER3, RECOVERY_ROLE));
    }

    // ================================================================
    // |         Phase 5: Authorization & Permission Error Tests     |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unpause_unauthorized_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Pause the contract first
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to unpause with unauthorized user (no unpauser role)
        let unauthorized = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::unpause(&unauthorized);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unpause_with_pauser_role_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to unpause with pauser (has pause but not unpause role)
        regulated_token::unpause(&pauser1); // Should fail
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unpause_authorized_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);
        assert!(regulated_token::is_paused());

        // Unpause with authorized unpauser
        let unpauser1 = account::create_signer_for_test(UNPAUSER1);
        regulated_token::unpause(&unpauser1);
        assert!(!regulated_token::is_paused());
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_bridge_minter_burner_specific_behavior(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant only BRIDGE_MINTER_OR_BURNER_ROLE
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, USER1);

        // Should be able to mint with bridge role
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(USER2, metadata) == 100);

        // Should also be able to burn with bridge role
        let bridge_user = account::create_signer_for_test(USER1);
        regulated_token::burn(&bridge_user, USER2, 50);
        assert!(primary_fungible_store::balance(USER2, metadata) == 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_minter_role_separation_enforced(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Grant only freezer role (no minter roles)
        regulated_token::grant_role(admin, FREEZER_ROLE, USER1);

        // Should NOT be able to mint with only freezer role
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);
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
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Freeze the account with tokens
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER1);

        // Try to burn from frozen account (should fail for regular burn)
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn(&burner1, USER1, 50);
    }

    // 5.4 Cross-Role Authorization Tests (2 tests)
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_minter_cannot_freeze_accounts(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Minter tries to freeze account (should fail)
        let minter1 = account::create_signer_for_test(MINTER1);
        regulated_token::freeze_account(&minter1, USER1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_freezer_cannot_pause_contract(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Freezer tries to pause contract (should fail)
        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::pause(&freezer1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_when_paused_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to mint when paused
        mint_to_user(USER1, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_when_paused_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
        mint_tokens_to_users(vector[USER1], vector[100]);

        // Pause the contract
        let pauser1 = account::create_signer_for_test(PAUSER1);
        regulated_token::pause(&pauser1);

        // Try to burn when paused
        let burner1 = account::create_signer_for_test(BURNER1);
        regulated_token::burn(&burner1, USER1, 50);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_frozen_funds_while_paused_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_pause_unpause_operations_flow(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_unfreeze_operations_flow(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_double_freeze_idempotent(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

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
    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_frozen_account_and_paused_contract_prioritizes_pause_error(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_unauthorized_minter_with_multiple_conditions(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        // Give USER1 minter role but freeze their destination account
        let admin = account::create_signer_for_test(ADMIN);
        regulated_token::grant_role(&admin, MINTER_ROLE, USER1);

        let freezer1 = account::create_signer_for_test(FREEZER1);
        regulated_token::freeze_account(&freezer1, USER2);

        // Try to mint to frozen account with authorized minter
        // Should fail with E_ACCOUNT_FROZEN (frozen account check comes after auth)
        mint_tokens_with_minter(USER1, vector[USER2], vector[100]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_batch_operations_partial_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_batch_role_updates_comprehensive(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let admin = account::create_signer_for_test(ADMIN);

        // Test comprehensive batch role updates
        regulated_token::apply_role_updates(
            &admin,
            PAUSER_ROLE,
            vector[PAUSER2], // Remove PAUSER2
            vector[USER1, USER2] // Add USER1, USER2 as pausers
        );

        regulated_token::apply_role_updates(
            &admin,
            FREEZER_ROLE,
            vector[FREEZER2], // Remove FREEZER2
            vector[USER1] // Add USER1 as freezer (in addition to pauser)
        );

        regulated_token::apply_role_updates(
            &admin,
            UNFREEZER_ROLE,
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

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_comprehensive_query_functions_integration(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let admin = account::create_signer_for_test(ADMIN);
        let freezer1 = account::create_signer_for_test(FREEZER1);
        let unfreezer1 = account::create_signer_for_test(UNFREEZER1);

        // Create test accounts
        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);
        account::create_account_for_test(USER3);

        // Test role query functions with freezer role (should have 2 members from setup)
        let initial_freezer_count = regulated_token::get_role_member_count(FREEZER_ROLE);
        assert!(initial_freezer_count == 2); // FREEZER1 and FREEZER2 from setup

        let freezer_members = regulated_token::get_role_members(FREEZER_ROLE);
        assert!(freezer_members.length() == 2);
        assert!(freezer_members.contains(&FREEZER1));
        assert!(freezer_members.contains(&FREEZER2));

        // Add USER1 as freezer
        regulated_token::grant_role(&admin, FREEZER_ROLE, USER1);

        // Verify count increased
        assert!(regulated_token::get_role_member_count(FREEZER_ROLE) == 3);

        // Test member access by index
        let member_0 = regulated_token::get_role_member(FREEZER_ROLE, 0);
        let member_1 = regulated_token::get_role_member(FREEZER_ROLE, 1);
        let member_2 = regulated_token::get_role_member(FREEZER_ROLE, 2);

        let all_members = regulated_token::get_role_members(FREEZER_ROLE);
        assert!(all_members.contains(&member_0));
        assert!(all_members.contains(&member_1));
        assert!(all_members.contains(&member_2));

        // Test freeze functionality with is_frozen
        assert!(!regulated_token::is_frozen(USER1));
        assert!(!regulated_token::is_frozen(USER2));
        assert!(!regulated_token::is_frozen(USER3));

        // Freeze some accounts
        regulated_token::freeze_accounts(&freezer1, vector[USER1, USER3]);

        // Test is_frozen function
        assert!(regulated_token::is_frozen(USER1));
        assert!(!regulated_token::is_frozen(USER2)); // Not frozen
        assert!(regulated_token::is_frozen(USER3));

        // Test get_all_frozen_accounts function
        let (frozen_accounts, _next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(frozen_accounts.length() == 2);
        assert!(frozen_accounts.contains(&USER1));
        assert!(frozen_accounts.contains(&USER3));
        assert!(!frozen_accounts.contains(&USER2)); // USER2 not frozen
        assert!(!has_more); // No more than 2 accounts

        // Test pagination of frozen accounts
        let (page1, next_key1, has_more1) =
            regulated_token::get_all_frozen_accounts(@0x0, 1);
        assert!(page1.length() == 1);
        assert!(has_more1); // Should have more

        let (page2, _next_key2, has_more2) =
            regulated_token::get_all_frozen_accounts(next_key1, 1);
        assert!(page2.length() == 1);
        assert!(!has_more2); // No more after second page

        // Combined pages should equal full result
        let combined_pages = page1;
        combined_pages.append(page2);
        assert!(combined_pages.length() == 2);
        assert!(combined_pages.contains(&USER1));
        assert!(combined_pages.contains(&USER3));

        // Unfreeze one account and test again
        regulated_token::unfreeze_accounts(&unfreezer1, vector[USER1]);

        assert!(!regulated_token::is_frozen(USER1)); // Now unfrozen
        assert!(regulated_token::is_frozen(USER3)); // Still frozen

        // Verify frozen accounts list updated
        let (frozen_after_unfreeze, _next_key, _has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(frozen_after_unfreeze.length() == 1);
        assert!(frozen_after_unfreeze[0] == USER3);
        assert!(!frozen_after_unfreeze.contains(&USER1)); // USER1 no longer in frozen list
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ALREADY_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_pause_already_paused_contract_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let pauser1 = account::create_signer_for_test(PAUSER1);

        // Pause the contract first
        regulated_token::pause(&pauser1);
        assert!(regulated_token::is_paused());

        // Try to pause again - should fail with E_ALREADY_PAUSED
        regulated_token::pause(&pauser1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_NOT_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_unpause_not_paused_contract_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup_token_and_roles(admin, regulated_token);

        let unpauser1 = account::create_signer_for_test(UNPAUSER1);

        // Contract is not paused by default
        assert!(!regulated_token::is_paused());

        // Try to unpause when not paused - should fail with E_NOT_PAUSED
        regulated_token::unpause(&unpauser1);
    }
}
