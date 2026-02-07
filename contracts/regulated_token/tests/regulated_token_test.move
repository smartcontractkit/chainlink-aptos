#[test_only]
module regulated_token::regulated_token_test {
    use std::fungible_asset::{Self, FungibleAsset};
    use std::option;
    use std::primary_fungible_store;
    use std::signer;
    use std::string;
    use std::object;
    use std::account;
    use std::event;

    use regulated_token::regulated_token::{Self};

    const RECOVERY_USER: address = @0xfeef;
    const RECIPIENT: address = @0xbeef;

    const PAUSER_ROLE: u8 = 0;
    const UNPAUSER_ROLE: u8 = 1;
    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const BRIDGE_MINTER_OR_BURNER_ROLE: u8 = 6;
    const RECOVERY_ROLE: u8 = 7;

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
    }

    fun setup_roles(
        admin: &signer,
        minter_addr: address,
        burner_addr: address,
        freezer_addr: address,
        pauser_addr: address
    ) {
        regulated_token::grant_role(admin, MINTER_ROLE, minter_addr);
        regulated_token::grant_role(admin, BURNER_ROLE, burner_addr);
        regulated_token::grant_role(admin, FREEZER_ROLE, freezer_addr);
        regulated_token::grant_role(admin, UNFREEZER_ROLE, freezer_addr);
        regulated_token::grant_role(admin, PAUSER_ROLE, pauser_addr);
        regulated_token::grant_role(admin, UNPAUSER_ROLE, pauser_addr);
    }

    fun setup_with_recovery_role(
        admin: &signer, regulated_token: &signer
    ): signer {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Grant recovery role to RECOVERY_USER
        account::create_account_for_test(RECOVERY_USER);
        account::create_account_for_test(RECIPIENT);
        regulated_token::grant_role(admin, RECOVERY_ROLE, RECOVERY_USER);

        // Create primary stores to ensure they exist (for recipient, contract address, and token state address)
        let metadata_obj = regulated_token::token_metadata();
        primary_fungible_store::ensure_primary_store_exists(RECIPIENT, metadata_obj);
        primary_fungible_store::ensure_primary_store_exists(
            @regulated_token, metadata_obj
        );
        primary_fungible_store::ensure_primary_store_exists(
            regulated_token::token_address(), metadata_obj
        );

        account::create_signer_for_test(RECOVERY_USER)
    }

    #[test(admin = @admin, recipient = @0xcafe, regulated_token = @regulated_token)]
    fun test_mint_token(
        admin: &signer, recipient: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let recipient_addr = signer::address_of(recipient);
        let minter_addr = signer::address_of(admin);

        setup_roles(
            admin,
            minter_addr,
            minter_addr,
            minter_addr,
            minter_addr
        );

        let mint_amount: u64 = 100;
        regulated_token::mint(admin, recipient_addr, mint_amount);

        let metadata_obj = regulated_token::token_metadata();
        assert!(fungible_asset::supply(metadata_obj)
            == option::some(mint_amount as u128));
        assert!(
            primary_fungible_store::balance(recipient_addr, metadata_obj) == mint_amount
        );
    }

    #[test(admin = @admin, recipient = @0xcafe, regulated_token = @regulated_token)]
    fun test_burn_token(
        admin: &signer, recipient: &signer, regulated_token: &signer
    ) {
        test_mint_token(admin, recipient, regulated_token);

        let recipient_addr = signer::address_of(recipient);
        let burn_amount: u64 = 50;

        regulated_token::burn(admin, recipient_addr, burn_amount);

        let metadata_obj = regulated_token::token_metadata();
        // 100 is the mint amount, 50 is the burn amount
        let mint_amount: u64 = 100;
        assert!(
            primary_fungible_store::balance(recipient_addr, metadata_obj)
                == mint_amount - burn_amount
        );

        // Assert tokens are burned from existing supply
        assert!(
            fungible_asset::supply(metadata_obj)
                == option::some((mint_amount - burn_amount) as u128)
        );
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_unauthorized_mint(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // Attempt unauthorized mint (should fail)
        regulated_token::mint(user, signer::address_of(user), 1000000);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_unauthorized_burn(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // Add owner to minter role
        setup_roles(
            admin,
            signer::address_of(admin),
            signer::address_of(admin),
            signer::address_of(admin),
            signer::address_of(admin)
        );

        // Mint first to initialize the store
        regulated_token::mint(admin, signer::address_of(user), 100);

        // Attempt unauthorized burn (should fail)
        regulated_token::burn(user, signer::address_of(user), 1000000);
    }

    // ================================================================
    // |                      Pausable Tests                          |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_pause_unpause_functionality(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        setup_roles(
            admin,
            signer::address_of(admin),
            signer::address_of(admin),
            signer::address_of(admin),
            signer::address_of(admin)
        );

        // Initially not paused
        assert!(!regulated_token::is_paused());

        // Owner can pause
        regulated_token::pause(admin);
        assert!(regulated_token::is_paused());

        // Owner can unpause
        regulated_token::unpause(admin);
        assert!(!regulated_token::is_paused());
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_pause(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // Non-pauser tries to pause (should fail)
        regulated_token::pause(user);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_when_paused(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Pause the contract
        regulated_token::pause(admin);

        // Try to mint when paused (should fail)
        let user_addr = signer::address_of(user);
        regulated_token::mint(admin, user_addr, 100);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_when_paused(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        let user_addr = signer::address_of(user);
        regulated_token::mint(admin, user_addr, 100);

        // Pause the contract
        regulated_token::pause(admin);

        // Try to burn when paused (should fail)
        regulated_token::burn(admin, user_addr, 50);
    }

    // ================================================================
    // |                      Role Management Tests                   |
    // ================================================================
    #[test(admin = @admin, minter = @0xface, regulated_token = @regulated_token)]
    fun test_role_management(
        admin: &signer, minter: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        let minter_addr = signer::address_of(minter);

        // Grant minter role
        regulated_token::grant_role(admin, MINTER_ROLE, minter_addr);

        // Now minter can mint
        regulated_token::mint(minter, @0x123, 100);

        let metadata_obj = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(@0x123, metadata_obj) == 100);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    fun test_revoke_role_success(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let user_addr = signer::address_of(user);

        // Grant minter role to user
        regulated_token::grant_role(admin, MINTER_ROLE, user_addr);

        // Verify user has the role
        assert!(regulated_token::has_role(user_addr, MINTER_ROLE));

        // User should be able to mint
        regulated_token::mint(user, @0x123, 100);
        let metadata_obj = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(@0x123, metadata_obj) == 100);

        // Revoke the minter role
        regulated_token::revoke_role(admin, MINTER_ROLE, user_addr);

        // Verify user no longer has the role
        assert!(!regulated_token::has_role(user_addr, MINTER_ROLE));
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_MINTER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    fun test_revoke_role_blocks_operations(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let user_addr = signer::address_of(user);

        // Grant minter role to user
        regulated_token::grant_role(admin, MINTER_ROLE, user_addr);

        // Revoke the minter role
        regulated_token::revoke_role(admin, MINTER_ROLE, user_addr);

        // User should no longer be able to mint (should fail)
        regulated_token::mint(user, @0x123, 100);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_revoke_role_unauthorized(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);

        // Grant minter role to admin first
        regulated_token::grant_role(admin, MINTER_ROLE, admin_addr);

        // User (non-admin) tries to revoke admin's role (should fail)
        regulated_token::revoke_role(user, MINTER_ROLE, admin_addr);
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    fun test_revoke_multiple_roles(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let user_addr = signer::address_of(user);

        // Grant multiple roles to user
        regulated_token::grant_role(admin, MINTER_ROLE, user_addr);
        regulated_token::grant_role(admin, BURNER_ROLE, user_addr);
        regulated_token::grant_role(admin, FREEZER_ROLE, user_addr);

        // Verify user has all roles
        assert!(regulated_token::has_role(user_addr, MINTER_ROLE));
        assert!(regulated_token::has_role(user_addr, BURNER_ROLE));
        assert!(regulated_token::has_role(user_addr, FREEZER_ROLE));

        // Revoke minter role only
        regulated_token::revoke_role(admin, MINTER_ROLE, user_addr);

        // Verify only minter role was revoked
        assert!(!regulated_token::has_role(user_addr, MINTER_ROLE));
        assert!(regulated_token::has_role(user_addr, BURNER_ROLE));
        assert!(regulated_token::has_role(user_addr, FREEZER_ROLE));

        // Revoke remaining roles
        regulated_token::revoke_role(admin, BURNER_ROLE, user_addr);
        regulated_token::revoke_role(admin, FREEZER_ROLE, user_addr);

        // Verify all roles are revoked
        assert!(!regulated_token::has_role(user_addr, MINTER_ROLE));
        assert!(!regulated_token::has_role(user_addr, BURNER_ROLE));
        assert!(!regulated_token::has_role(user_addr, FREEZER_ROLE));
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    fun test_revoke_role_idempotent(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let user_addr = signer::address_of(user);

        // Grant minter role to user
        regulated_token::grant_role(admin, MINTER_ROLE, user_addr);
        assert!(regulated_token::has_role(user_addr, MINTER_ROLE));

        // Revoke the role
        regulated_token::revoke_role(admin, MINTER_ROLE, user_addr);
        assert!(!regulated_token::has_role(user_addr, MINTER_ROLE));

        // Revoke the same role again (should not fail)
        regulated_token::revoke_role(admin, MINTER_ROLE, user_addr);
        assert!(!regulated_token::has_role(user_addr, MINTER_ROLE));
    }

    #[test(
        admin = @admin,
        user = @0xface,
        freezer = @0xcafe,
        regulated_token = @regulated_token
    )]
    fun test_revoke_freezer_role_functionality(
        admin: &signer, user: &signer, freezer: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        let user_addr = signer::address_of(user);
        let freezer_addr = signer::address_of(freezer);

        // Setup admin with minter role and freezer with freezer role
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );
        regulated_token::grant_role(admin, FREEZER_ROLE, freezer_addr);
        regulated_token::grant_role(admin, UNFREEZER_ROLE, freezer_addr);

        // Mint tokens to user
        regulated_token::mint(admin, user_addr, 100);

        // Freezer should be able to freeze account
        regulated_token::freeze_account(freezer, user_addr);
        assert!(regulated_token::is_frozen(user_addr));

        // Revoke freezer role
        regulated_token::revoke_role(admin, FREEZER_ROLE, freezer_addr);

        // Freezer should no longer be able to freeze accounts
        // First unfreeze to test freezing again
        regulated_token::unfreeze_account(freezer, user_addr);
        assert!(!regulated_token::is_frozen(user_addr));

        // This should fail because freezer role was revoked, but we can't test the failure
        // in this test due to the expected_failure attribute limitation, so we just verify
        // the role was properly revoked
        assert!(!regulated_token::has_role(freezer_addr, FREEZER_ROLE));
        assert!(regulated_token::has_role(freezer_addr, UNFREEZER_ROLE)); // Unfreezer role should still exist
    }

    // ================================================================
    // |                      Freeze Tests                           |
    // ================================================================
    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    fun test_freeze_functionality(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        let user_addr = signer::address_of(user);

        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Mint some tokens first
        regulated_token::mint(admin, user_addr, 100);

        let metadata_obj = regulated_token::token_metadata();

        // Initially not frozen (test both primary_fungible_store and regulated_token methods)
        assert!(!primary_fungible_store::is_frozen(user_addr, metadata_obj));
        assert!(!regulated_token::is_frozen(user_addr));

        // Freeze the account
        regulated_token::freeze_accounts(admin, vector[user_addr]);

        // Now should be frozen (test both methods)
        assert!(primary_fungible_store::is_frozen(user_addr, metadata_obj));
        assert!(regulated_token::is_frozen(user_addr));

        // Unfreeze the account
        regulated_token::unfreeze_accounts(admin, vector[user_addr]);

        // Should not be frozen anymore (test both methods)
        assert!(!primary_fungible_store::is_frozen(user_addr, metadata_obj));
        assert!(!regulated_token::is_frozen(user_addr));
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_freeze(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let user_addr = signer::address_of(user);

        // Non-freezer tries to freeze (should fail)
        regulated_token::freeze_accounts(user, vector[user_addr]);
    }

    // ================================================================
    // |                      Burn Frozen Funds Tests                   |
    // ================================================================
    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        let user_addr = signer::address_of(user);

        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Mint tokens to user
        regulated_token::mint(admin, user_addr, 100);

        // Freeze the account
        regulated_token::freeze_accounts(admin, vector[user_addr]);

        // Burn frozen funds
        regulated_token::burn_frozen_funds(admin, user_addr);

        let metadata_obj = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(user_addr, metadata_obj) == 0);
    }

    // ================================================================
    // |                      View Function Tests                     |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_view_functions(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Test pausable view functions
        assert!(!regulated_token::is_paused());
        regulated_token::pause(admin);
        assert!(regulated_token::is_paused());
        regulated_token::unpause(admin);
        assert!(!regulated_token::is_paused());

        // Test token metadata
        let metadata_obj = regulated_token::token_metadata();
        assert!(fungible_asset::name(metadata_obj) == string::utf8(b"Regulated Token"));
        assert!(fungible_asset::symbol(metadata_obj) == string::utf8(b"RT"));
    }

    // ================================================================
    // |                      Token Recovery Tests                    |
    // ================================================================
    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_from_contract_address(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint tokens to admin first
        regulated_token::mint(admin, signer::address_of(admin), 1000);

        // Simulate tokens getting stuck in @regulated_token address by minting directly there
        regulated_token::mint(admin, @regulated_token, 500);

        let metadata_obj = regulated_token::token_metadata();

        // Verify tokens are stuck in contract address
        let stuck_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        assert!(stuck_balance == 500);

        // Verify recipient initially has no tokens
        let initial_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);
        assert!(initial_recipient_balance == 0);

        // Recover tokens
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify tokens were recovered
        let final_contract_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let final_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);

        assert!(final_contract_balance == 0); // Contract should have no tokens
        assert!(final_recipient_balance == stuck_balance); // Recipient should have recovered tokens
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_from_token_state_address(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);
        let token_state_address = regulated_token::token_state_address();

        // Mint tokens to admin first, then send some to token state address
        regulated_token::mint(admin, signer::address_of(admin), 1000);

        let metadata_obj = regulated_token::token_metadata();

        // Transfer some tokens to token state address to simulate them getting stuck
        primary_fungible_store::transfer(admin, metadata_obj, token_state_address, 300);

        // Verify tokens are stuck in token state address
        let stuck_balance =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        assert!(stuck_balance == 300);

        // Verify recipient initially has no tokens
        let initial_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);
        assert!(initial_recipient_balance == 0);

        // Recover tokens
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify tokens were recovered
        let final_state_balance =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        let final_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);

        assert!(final_state_balance == 0); // Token state should have no tokens
        assert!(final_recipient_balance == stuck_balance); // Recipient should have recovered tokens
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_recover_tokens_unauthorized_fails(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Mint some tokens to contract address
        regulated_token::mint(admin, @regulated_token, 100);

        // User without recovery role tries to recover tokens (should fail)
        regulated_token::recover_tokens(user, RECIPIENT);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_with_recovery_role_succeeds(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint tokens to both locations that can get stuck
        regulated_token::mint(admin, @regulated_token, 200);

        let token_state_address = regulated_token::token_state_address();
        regulated_token::mint(admin, signer::address_of(admin), 300);
        primary_fungible_store::transfer(
            admin,
            regulated_token::token_metadata(),
            token_state_address,
            150
        );

        let metadata_obj = regulated_token::token_metadata();

        // Verify tokens are stuck in both locations
        let stuck_contract =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let stuck_state =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        assert!(stuck_contract == 200);
        assert!(stuck_state == 150);

        // Recovery role user should be able to recover
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify all tokens were recovered
        let final_contract_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let final_state_balance =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        let final_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);

        assert!(final_contract_balance == 0);
        assert!(final_state_balance == 0);
        assert!(
            final_recipient_balance == stuck_contract + stuck_state
        ); // Should have all recovered tokens
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ZERO_ADDRESS_NOT_ALLOWED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_tokens_to_zero_address_fails(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint some tokens to contract address
        regulated_token::mint(admin, @regulated_token, 100);

        // Try to recover to zero address (should fail)
        regulated_token::recover_tokens(&recovery_signer, @0x0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_CANNOT_TRANSFER_TO_REGULATED_TOKEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_tokens_to_regulated_token_fails(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint some tokens to token state address
        let token_state_address = regulated_token::token_state_address();
        regulated_token::mint(admin, signer::address_of(admin), 200);
        primary_fungible_store::transfer(
            admin,
            regulated_token::token_metadata(),
            token_state_address,
            150
        );

        // Try to recover to @regulated_token address (should fail)
        regulated_token::recover_tokens(&recovery_signer, @regulated_token);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_CANNOT_TRANSFER_TO_REGULATED_TOKEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_tokens_to_token_state_address_fails(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint some tokens to contract address
        regulated_token::mint(admin, @regulated_token, 100);

        let token_state_address = regulated_token::token_state_address();

        // Try to recover to token state address (should fail)
        regulated_token::recover_tokens(&recovery_signer, token_state_address);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_when_no_balance(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        let metadata_obj = regulated_token::token_metadata();

        // Verify no tokens are stuck anywhere
        let contract_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let token_state_balance =
            primary_fungible_store::balance(
                regulated_token::token_state_address(), metadata_obj
            );
        assert!(contract_balance == 0);
        assert!(token_state_balance == 0);

        // Verify recipient has no tokens initially
        let initial_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);
        assert!(initial_recipient_balance == 0);

        // Recovery should work (no-op) when no tokens are stuck
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify nothing changed
        let final_contract_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let final_state_balance =
            primary_fungible_store::balance(
                regulated_token::token_state_address(), metadata_obj
            );
        let final_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);

        assert!(final_contract_balance == 0);
        assert!(final_state_balance == 0);
        assert!(final_recipient_balance == 0); // Still no tokens
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_both_locations(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        // Mint tokens to both problematic locations
        regulated_token::mint(admin, @regulated_token, 750); // Contract address

        let token_state_address = regulated_token::token_state_address();
        regulated_token::mint(admin, signer::address_of(admin), 500);
        primary_fungible_store::transfer(
            admin,
            regulated_token::token_metadata(),
            token_state_address,
            250
        ); // Token state address

        let metadata_obj = regulated_token::token_metadata();

        // Verify tokens are stuck in both locations
        let stuck_contract =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let stuck_state =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        assert!(stuck_contract == 750);
        assert!(stuck_state == 250);

        let total_stuck = stuck_contract + stuck_state;

        // Single recovery call should recover from both locations
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify all tokens were recovered from both locations
        let final_contract_balance =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let final_state_balance =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        let final_recipient_balance =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);

        assert!(final_contract_balance == 0);
        assert!(final_state_balance == 0);
        assert!(final_recipient_balance == total_stuck); // Should have all recovered tokens
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_recover_tokens_fails_if_paused(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        let metadata_obj = regulated_token::token_metadata();

        // Simulate scenario where tokens might get stuck during failed operations
        // 1. Mint some tokens normally
        regulated_token::mint(admin, signer::address_of(admin), 1000);

        // 2. Simulate tokens getting sent to contract (could happen during failed bridge operations)
        regulated_token::mint(admin, @regulated_token, 400);

        // 3. Simulate tokens getting sent to token state address (could happen during internal operations)
        let token_state_address = regulated_token::token_state_address();
        primary_fungible_store::transfer(admin, metadata_obj, token_state_address, 300);

        // 4. Pause the contract to simulate emergency state
        regulated_token::pause(admin);
        assert!(regulated_token::is_paused());

        // Verify tokens are stuck in both problematic locations
        let stuck_contract =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let stuck_state =
            primary_fungible_store::balance(token_state_address, metadata_obj);
        assert!(stuck_contract == 400);
        assert!(stuck_state == 300);

        // Recovery should fail when contract is paused (emergency recovery)
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_state_consistency(
        admin: &signer, regulated_token: &signer
    ) {
        let recovery_signer = setup_with_recovery_role(admin, regulated_token);

        let metadata_obj = regulated_token::token_metadata();

        // Initial setup: mint tokens to various accounts
        regulated_token::mint(admin, signer::address_of(admin), 2000);
        regulated_token::mint(admin, @0xabc, 1500);
        regulated_token::mint(admin, @0xdef, 800);

        // Check initial total supply
        let initial_supply = fungible_asset::supply(metadata_obj);
        assert!(initial_supply.is_some());
        let initial_total = *initial_supply.borrow();
        assert!(initial_total == 4300); // 2000 + 1500 + 800

        // Simulate tokens getting stuck
        regulated_token::mint(admin, @regulated_token, 600); // Contract
        let token_state_address = regulated_token::token_state_address();
        primary_fungible_store::transfer(admin, metadata_obj, token_state_address, 200); // State

        // Check total supply after tokens get stuck
        let supply_with_stuck = fungible_asset::supply(metadata_obj);
        let total_with_stuck = *supply_with_stuck.borrow();
        assert!(total_with_stuck == 4900); // 4300 + 600 = 4900 (transfer doesn't change supply, only mint does)

        // Sum all balances before recovery
        let admin_balance_before =
            primary_fungible_store::balance(signer::address_of(admin), metadata_obj);
        let abc_balance_before = primary_fungible_store::balance(@0xabc, metadata_obj);
        let def_balance_before = primary_fungible_store::balance(@0xdef, metadata_obj);
        let recipient_balance_before =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);
        let contract_balance_before =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let state_balance_before =
            primary_fungible_store::balance(token_state_address, metadata_obj);

        let total_balance_before =
            admin_balance_before + abc_balance_before + def_balance_before
                + recipient_balance_before + contract_balance_before
                + state_balance_before;

        // Recover stuck tokens
        regulated_token::recover_tokens(&recovery_signer, RECIPIENT);

        // Verify total supply is unchanged
        let supply_after_recovery = fungible_asset::supply(metadata_obj);
        let total_after_recovery = *supply_after_recovery.borrow();
        assert!(total_after_recovery == total_with_stuck); // Supply should be unchanged

        // Sum all balances after recovery
        let admin_balance_after =
            primary_fungible_store::balance(signer::address_of(admin), metadata_obj);
        let abc_balance_after = primary_fungible_store::balance(@0xabc, metadata_obj);
        let def_balance_after = primary_fungible_store::balance(@0xdef, metadata_obj);
        let recipient_balance_after =
            primary_fungible_store::balance(RECIPIENT, metadata_obj);
        let contract_balance_after =
            primary_fungible_store::balance(@regulated_token, metadata_obj);
        let state_balance_after =
            primary_fungible_store::balance(token_state_address, metadata_obj);

        let total_balance_after =
            admin_balance_after + abc_balance_after + def_balance_after
                + recipient_balance_after + contract_balance_after
                + state_balance_after;

        // Total balance should be conserved
        assert!(total_balance_after == total_balance_before);

        // Verify specific expectations
        assert!(contract_balance_after == 0); // Contract should have no tokens
        assert!(state_balance_after == 0); // State should have no tokens
        assert!(
            recipient_balance_after == contract_balance_before + state_balance_before
        ); // Recipient got stuck tokens

        // Other balances should be unchanged
        assert!(admin_balance_after == admin_balance_before);
        assert!(abc_balance_after == abc_balance_before);
        assert!(def_balance_after == def_balance_before);
    }

    // ================================================================
    // |              Get All Frozen Accounts Tests                  |
    // ================================================================
    fun freeze_accounts_for_test(
        freezer: &signer, accounts: vector<address>
    ) {
        accounts.for_each(
            |account| {
                account::create_account_for_test(account);
                regulated_token::freeze_accounts(freezer, vector[account]);
            }
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        freeze_accounts_for_test(admin, vector[@0x1, @0x2, @0x3]);

        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 0
        );
        assert!(res.length() == 0);
        assert!(next_key == @0x0);
        assert!(has_more);

        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 3
        );
        assert!(res.length() == 3);
        assert!(vector[@0x1, @0x2, @0x3] == res);
        assert!(next_key == @0x3);
        assert!(!has_more);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_edge_cases(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Test case 1: Empty state
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 1
        );
        assert!(res.length() == 0);
        assert!(next_key == @0x0);
        assert!(!has_more);

        // Test case 2: Single frozen account
        freeze_accounts_for_test(admin, vector[@0x1]);
        let (res, _next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 1
        );
        assert!(res.length() == 1);
        assert!(res[0] == @0x1);
        assert!(!has_more);

        // Test case 3: Start from middle
        freeze_accounts_for_test(admin, vector[@0x2, @0x3]);
        let (res, _next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x1, 2
        );
        assert!(res.length() == 2);
        assert!(res[0] == @0x2);
        assert!(res[1] == @0x3);
        assert!(!has_more);

        // Test case 4: Request more than available
        let (res, _next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 5
        );
        assert!(res.length() == 3);
        assert!(res[0] == @0x1);
        assert!(res[1] == @0x2);
        assert!(res[2] == @0x3);
        assert!(!has_more);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_pagination(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        freeze_accounts_for_test(admin, vector[@0x1, @0x2, @0x3, @0x4, @0x5]);

        // Test pagination with different chunk sizes
        let current_key = @0x0;
        let total_accounts = vector[];

        // First page: get 2 accounts
        let (res, next_key, more) =
            regulated_token::get_all_frozen_accounts(current_key, 2);
        assert!(res.length() == 2);
        assert!(res[0] == @0x1);
        assert!(res[1] == @0x2);
        assert!(more);
        current_key = next_key;
        total_accounts.append(res);

        // Second page: get 2 more accounts
        let (res, next_key, more) =
            regulated_token::get_all_frozen_accounts(current_key, 2);
        assert!(res.length() == 2);
        assert!(res[0] == @0x3);
        assert!(res[1] == @0x4);
        assert!(more);
        current_key = next_key;
        total_accounts.append(res);

        // Last page: get remaining account
        let (res, _next_key, more) =
            regulated_token::get_all_frozen_accounts(current_key, 2);
        assert!(res.length() == 1);
        assert!(res[0] == @0x5);
        assert!(!more);
        total_accounts.append(res);

        // Verify we got all accounts in order
        assert!(total_accounts.length() == 5);
        assert!(total_accounts[0] == @0x1);
        assert!(total_accounts[1] == @0x2);
        assert!(total_accounts[2] == @0x3);
        assert!(total_accounts[3] == @0x4);
        assert!(total_accounts[4] == @0x5);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_non_existent(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        freeze_accounts_for_test(admin, vector[@0x1, @0x2, @0x3]);

        // Test starting from non-existent key
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x4, 1
        );
        assert!(res.length() == 0);
        assert!(next_key == @0x4);
        assert!(!has_more);

        // Test starting from key between existing accounts
        let (res, _next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x1, 1
        );
        assert!(res.length() == 1);
        assert!(res[0] == @0x2);
        assert!(has_more);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_with_unfreeze(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        // Freeze multiple accounts
        freeze_accounts_for_test(admin, vector[@0x1, @0x2, @0x3, @0x4]);

        // Verify all are frozen
        let (res, _next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(res.length() == 4);
        assert!(!has_more);

        // Unfreeze middle account
        regulated_token::unfreeze_accounts(admin, vector[@0x2]);

        // Verify list updated correctly
        let (res, _next_key, has_more) =
            regulated_token::get_all_frozen_accounts(@0x0, 10);
        assert!(res.length() == 3);
        assert!(res[0] == @0x1);
        assert!(res[1] == @0x3);
        assert!(res[2] == @0x4);
        assert!(!has_more);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_transfer_admin_wrapper(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        let new_admin = @0x123;

        // Test transfer_admin wrapper function
        regulated_token::transfer_admin(admin, new_admin);

        // Verify it correctly delegates to access_control
        let pending = regulated_token::pending_admin();
        assert!(pending == new_admin);

        // Verify admin unchanged until acceptance
        let current_admin = regulated_token::admin();
        assert!(current_admin == admin_addr);
    }

    #[test(new_admin = @0x123, regulated_token = @regulated_token, admin = @admin)]
    fun test_accept_admin_wrapper(
        new_admin: &signer, regulated_token: &signer, admin: &signer
    ) {
        setup(admin, regulated_token);
        let new_admin_addr = signer::address_of(new_admin);

        // First transfer admin
        regulated_token::transfer_admin(admin, new_admin_addr);

        // Test accept_admin wrapper function
        regulated_token::accept_admin(new_admin);

        // Verify it correctly delegates to access_control
        let current_admin = regulated_token::admin();
        assert!(current_admin == new_admin_addr);

        let pending = regulated_token::pending_admin();
        assert!(pending == @0x0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_SAME_ADMIN,
            location = regulated_token::access_control
        )
    ]
    // E_SAME_ADMIN from access_control
    fun test_transfer_admin_same_address(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);

        // Should fail when transferring to same admin
        regulated_token::transfer_admin(admin, admin_addr);
    }

    #[test(non_admin = @0x876, regulated_token = @regulated_token, admin = @admin)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    // E_NOT_ADMIN from access_control
    fun test_transfer_admin_unauthorized(
        non_admin: &signer, regulated_token: &signer, admin: &signer
    ) {
        setup(admin, regulated_token);

        // Should fail when non-admin tries to transfer
        regulated_token::transfer_admin(non_admin, signer::address_of(non_admin));
    }

    #[test(wrong_admin = @0x999, regulated_token = @regulated_token, admin = @admin)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    // E_NOT_ADMIN from access_control
    fun test_accept_admin_unauthorized(
        wrong_admin: &signer, regulated_token: &signer, admin: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::transfer_admin(admin, @0xb0b);

        // Should fail when wrong account tries to accept
        regulated_token::accept_admin(wrong_admin);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_get_all_frozen_accounts_max_count_variations(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let admin_addr = signer::address_of(admin);
        setup_roles(
            admin,
            admin_addr,
            admin_addr,
            admin_addr,
            admin_addr
        );

        freeze_accounts_for_test(admin, vector[@0x1, @0x2, @0x3]);

        // Test with max_count = 0 (should return empty with has_more = true)
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 0
        );
        assert!(res.length() == 0);
        assert!(next_key == @0x0);
        assert!(has_more);

        // Test with max_count = 1
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 1
        );
        assert!(res.length() == 1);
        assert!(res[0] == @0x1);
        assert!(next_key == @0x1);
        assert!(has_more);

        // Test with exact count
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 3
        );
        assert!(res.length() == 3);
        assert!(next_key == @0x3);
        assert!(!has_more);

        // Test with more than available
        let (res, next_key, has_more) = regulated_token::get_all_frozen_accounts(
            @0x0, 10
        );
        assert!(res.length() == 3);
        assert!(next_key == @0x3);
        assert!(!has_more);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_bridge_mint_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;

        account::create_account_for_test(bridge_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        // Call bridge_mint
        let fa = regulated_token::bridge_mint(bridge_signer, bridge_addr, 1000);

        // Verify the FungibleAsset was created with correct amount
        assert!(fungible_asset::amount(&fa) == 1000);

        // Clean up by burning the FA
        regulated_token::bridge_burn(bridge_signer, bridge_addr, fa);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_bridge_burn_success(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;

        account::create_account_for_test(bridge_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        let fa = regulated_token::bridge_mint(bridge_signer, bridge_addr, 1000);
        assert!(fungible_asset::amount(&fa) == 1000);

        regulated_token::bridge_burn(bridge_signer, bridge_addr, fa);

        let events = event::emitted_events<regulated_token::BridgeBurn>();
        assert!(events.length() == 1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_bridge_mint_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let unauthorized_addr = @0xbeef;

        account::create_account_for_test(unauthorized_addr);
        let unauthorized_signer = &account::create_signer_for_test(unauthorized_addr);

        // Should fail because unauthorized_signer doesn't have BRIDGE_MINTER_OR_BURNER_ROLE
        let fa = regulated_token::bridge_mint(
            unauthorized_signer, unauthorized_addr, 1000
        );
        burn_fa(admin, fa, unauthorized_addr);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_bridge_burn_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xcafe;
        let unauthorized_addr = @0xbeef;

        account::create_account_for_test(bridge_addr);
        account::create_account_for_test(unauthorized_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr only
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);
        let unauthorized_signer = &account::create_signer_for_test(unauthorized_addr);

        // Create a FungibleAsset with authorized signer
        let fa = regulated_token::bridge_mint(bridge_signer, bridge_addr, 1000);

        // Should fail because unauthorized_signer doesn't have BRIDGE_MINTER_OR_BURNER_ROLE
        burn_fa(unauthorized_signer, fa, bridge_addr);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_bridge_mint_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;

        account::create_account_for_test(bridge_addr);

        // Grant admin the pauser role
        let admin_addr = signer::address_of(admin);
        regulated_token::grant_role(admin, PAUSER_ROLE, admin_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        regulated_token::pause(admin);

        // Should fail because contract is paused
        let fa = regulated_token::bridge_mint(bridge_signer, bridge_addr, 1000);
        burn_fa(admin, fa, bridge_addr);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_PAUSED,
            location = regulated_token::regulated_token
        )
    ]
    fun test_bridge_burn_when_paused(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;
        account::create_account_for_test(bridge_addr);

        // Grant admin the pauser role
        let admin_addr = signer::address_of(admin);
        regulated_token::grant_role(admin, PAUSER_ROLE, admin_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        let fa = regulated_token::bridge_mint(bridge_signer, bridge_addr, 1000);

        regulated_token::pause(admin);

        // Should fail because contract is paused
        regulated_token::bridge_burn(bridge_signer, bridge_addr, fa);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_bridge_mint_to_frozen_account(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;
        let frozen_addr = @0xcafe;

        account::create_account_for_test(bridge_addr);
        account::create_account_for_test(frozen_addr);

        // Grant admin the freezer role
        let admin_addr = signer::address_of(admin);
        regulated_token::grant_role(admin, FREEZER_ROLE, admin_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        // Freeze the target account
        regulated_token::freeze_account(admin, frozen_addr);

        // Should fail because target account is frozen
        let fa = regulated_token::bridge_mint(bridge_signer, frozen_addr, 1000);
        burn_fa(admin, fa, bridge_addr);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_bridge_burn_from_frozen_account(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let bridge_addr = @0xbeef;
        let frozen_addr = @0xcafe;

        account::create_account_for_test(bridge_addr);
        account::create_account_for_test(frozen_addr);

        // Grant admin the freezer role
        let admin_addr = signer::address_of(admin);
        regulated_token::grant_role(admin, FREEZER_ROLE, admin_addr);

        // Grant BRIDGE_MINTER_OR_BURNER_ROLE to bridge_addr
        regulated_token::grant_role(admin, BRIDGE_MINTER_OR_BURNER_ROLE, bridge_addr);

        let bridge_signer = &account::create_signer_for_test(bridge_addr);

        let fa = regulated_token::bridge_mint(bridge_signer, frozen_addr, 1000);

        regulated_token::freeze_account(admin, frozen_addr);

        // Should fail because source account is frozen
        regulated_token::bridge_burn(bridge_signer, frozen_addr, fa);
    }

    fun burn_fa(admin: &signer, fa: FungibleAsset, sender: address) {
        let metadata = fungible_asset::metadata_from_asset(&fa);
        // Create a FungibleStore for SENDER so we can burn from it
        // This will call `regulated_token::bridge_burn` which attempts to check the sender's store
        // to make sure it's not frozen.
        let _store = primary_fungible_store::ensure_primary_store_exists(
            sender, metadata
        );
        regulated_token::bridge_burn(admin, sender, fa);
    }
}
