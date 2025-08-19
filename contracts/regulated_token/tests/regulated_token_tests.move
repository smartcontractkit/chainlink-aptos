#[test_only]
module regulated_token::regulated_token_test {
    use std::account;
    use std::fungible_asset::{Self};
    use std::option;
    use std::primary_fungible_store;
    use std::signer;
    use std::string;

    use regulated_token::regulated_token::{Self};

    const ADMIN: address = @admin;
    const OWNER: address = @0xcafe;
    const MINTER: address = @0xface;
    const BURNER: address = @0xbeef;
    const RECIPIENT: address = @0xabc;
    const SENDER: address = @0xdef;
    const FREEZER: address = @0x1234;
    const PAUSER: address = @0x5678;

    fun setup(owner: &signer, regulated_token: &signer) {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(regulated_token));

        // The regulated_token signer is created at the @regulated_token address from Move.toml
        regulated_token::init_module_for_testing(regulated_token);
    }

    fun setup_roles(
        admin: &signer,
        minter_addr: address,
        burner_addr: address,
        freezer_addr: address,
        pauser_addr: address
    ) {
        // Grant minter role (role_number = 4)
        regulated_token::grant_role(admin, 4, minter_addr);

        // Grant burner role (role_number = 5)
        regulated_token::grant_role(admin, 5, burner_addr);

        // Grant freezer role (role_number = 2)
        regulated_token::grant_role(admin, 2, freezer_addr);

        // Grant unfreezer role (role_number = 3)
        regulated_token::grant_role(admin, 3, freezer_addr);

        // Grant pauser role (role_number = 0)
        regulated_token::grant_role(admin, 0, pauser_addr);

        // Grant unpauser role (role_number = 1)
        regulated_token::grant_role(admin, 1, pauser_addr);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_init_module(admin: &signer, regulated_token: &signer) {
        setup(admin, regulated_token);

        let metadata_obj = regulated_token::token_metadata();
        assert!(fungible_asset::name(metadata_obj) == string::utf8(b"Regulated Token"));
        assert!(fungible_asset::symbol(metadata_obj) == string::utf8(b"RT"));
        assert!(fungible_asset::decimals(metadata_obj) == 6);
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
        // Setup env and mint tokens first
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
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_MINTER,
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
            abort_code = regulated_token::regulated_token::E_NOT_ALLOWED_BURNER,
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
        regulated_token::grant_role(admin, 4, minter_addr); // MINTER_ROLE = 4

        // Now minter can mint
        regulated_token::mint(minter, @0x123, 100);

        let metadata_obj = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(@0x123, metadata_obj) == 100);
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

        // Initially not frozen
        assert!(!primary_fungible_store::is_frozen(user_addr, metadata_obj));

        // Freeze the account
        regulated_token::freeze_accounts(admin, vector[user_addr]);

        // Now should be frozen
        assert!(primary_fungible_store::is_frozen(user_addr, metadata_obj));

        // Unfreeze the account
        regulated_token::unfreeze_accounts(admin, vector[user_addr]);

        // Should not be frozen anymore
        assert!(!primary_fungible_store::is_frozen(user_addr, metadata_obj));
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

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_to_frozen_account(
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

        // Freeze the account first
        regulated_token::freeze_accounts(admin, vector[user_addr]);

        // Try to mint to frozen account (should fail)
        regulated_token::mint(admin, user_addr, 100);
    }

    // ================================================================
    // |                      Zero Amount Tests                       |
    // ================================================================

    #[test(admin = @admin, recipient = @0xcafe, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_AMOUNT,
            location = regulated_token::regulated_token
        )
    ]
    fun test_mint_zero_amount_fails(
        admin: &signer, recipient: &signer, regulated_token: &signer
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

        let recipient_addr = signer::address_of(recipient);
        // Try to mint with zero amount (should fail)
        regulated_token::mint(admin, recipient_addr, 0);
    }

    #[test(admin = @admin, recipient = @0xcafe, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_INVALID_AMOUNT,
            location = regulated_token::regulated_token
        )
    ]
    fun test_burn_zero_amount_fails(
        admin: &signer, recipient: &signer, regulated_token: &signer
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

        let recipient_addr = signer::address_of(recipient);

        // First mint some tokens
        regulated_token::mint(admin, recipient_addr, 100);

        // Try to burn with zero amount (should fail)
        regulated_token::burn(admin, recipient_addr, 0);
    }

    // ================================================================
    // |                      Burn Frozen Funds Tests                |
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
}
