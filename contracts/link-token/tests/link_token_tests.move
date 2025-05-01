#[test_only]
module link::link_tests {
    use std::account;
    use std::debug;
    use std::fungible_asset::{Self, Metadata};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::Self;
    use std::object::{Self};

    use link::link_token::Self;

    const MAX_SUPPLY: u128 = 1000000;
    const DECIMALS: u8 = 8;
    const ICON: vector<u8> = b"http://chainlink.com/link-icon.png";
    const PROJECT: vector<u8> = b"ChainLink Project";
    const NAME: vector<u8> = b"ChainLink Token";
    const SYMBOL: vector<u8> = b"LINK";

    #[test_only]
    public fun setup(owner: &signer, link: &signer) {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(link));

        let constructor_ref = &object::create_named_object(owner, b"link_token_tests");

        let object_address =
            object::create_object_address(
                &signer::address_of(owner), b"link_token_tests"
            );
        // For debugging, use this as `@link` address in Move.toml
        debug::print(&object_address);

        let object_signer = object::generate_signer(constructor_ref);
        // Creates the Account to use for `@link`
        account::create_account_for_test(signer::address_of(&object_signer));

        link_token::init_module_for_testing(&object_signer);
    }

    #[test_only]
    public fun setup_minters_burners(
        owner: &signer, minter: &signer, burner: &signer
    ) {
        link_token::apply_allowed_minter_updates(
            owner,
            vector[],
            vector[signer::address_of(minter)]
        );
        link_token::apply_allowed_burner_updates(
            owner,
            vector[],
            vector[signer::address_of(burner)]
        );
    }

    #[test_only]
    public fun initialize_link(owner: &signer, max_supply: Option<u128>) {
        link_token::initialize(
            owner,
            max_supply,
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(owner = @0x999, link = @link)]
    public fun test_initialize_link(owner: &signer, link: &signer) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj =
            object::address_to_object<Metadata>(link_token::token_metadata());
        assert!(fungible_asset::name(metadata_obj) == string::utf8(NAME));
        assert!(fungible_asset::symbol(metadata_obj) == string::utf8(SYMBOL));
        assert!(fungible_asset::decimals(metadata_obj) == DECIMALS);
    }

    #[test(owner = @0x999, recipient = @0xcafe, link = @link)]
    public fun test_mint_link(
        owner: &signer, recipient: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let recipient_addr = signer::address_of(recipient);

        let mint_amount: u64 = 100;
        setup_minters_burners(owner, owner, owner);

        link_token::mint(owner, recipient_addr, mint_amount);

        let metadata_obj =
            object::address_to_object<Metadata>(link_token::token_metadata());
        assert!(fungible_asset::supply(metadata_obj)
            == option::some(mint_amount as u128));
        assert!(
            primary_fungible_store::balance(recipient_addr, metadata_obj) == mint_amount
        );
    }

    #[test(owner = @0x999, recipient = @0xcafe, link = @link)]
    public fun test_burn_link(
        owner: &signer, recipient: &signer, link: &signer
    ) {
        // Setup env and mint link first, mint 100 to recipient
        test_mint_link(owner, recipient, link);

        let recipient_addr = signer::address_of(recipient);
        let burn_amount: u64 = 50;

        link_token::burn(owner, recipient_addr, burn_amount);

        let metadata_obj =
            object::address_to_object<Metadata>(link_token::token_metadata());
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

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327683, location = link::ownable)]
    public fun test_unauthorized_initialize(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        // Attempt unauthorized initialize (should fail) E_ONLY_CALLABLE_BY_OWNER
        initialize_link(user, option::some(MAX_SUPPLY));
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_NOT_ALLOWED_MINTER,
            location = link::link_token
        )
    ]
    public fun test_unauthorized_mint(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Attempt unauthorized mint (should fail)
        link_token::mint(user, signer::address_of(user), 1000000);
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_NOT_ALLOWED_BURNER,
            location = link::link_token
        )
    ]
    public fun test_unauthorized_burn(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Attempt unauthorized burn (should fail)
        link_token::burn(user, signer::address_of(user), 1000000);
    }

    #[test(
        owner = @0x999, recipient1 = @0xface, recipient2 = @0xbeef, link = @link
    )]
    public fun test_token_transfer(
        owner: &signer,
        recipient1: &signer,
        recipient2: &signer,
        link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let recipient1_addr = signer::address_of(recipient1);
        let recipient2_addr = signer::address_of(recipient2);

        let mint_amount = 1000000;
        setup_minters_burners(owner, owner, owner);

        link_token::mint(owner, recipient1_addr, mint_amount);

        let metadata_obj =
            object::address_to_object<Metadata>(link_token::token_metadata());

        let sender_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient1_addr, metadata_obj
            );
        let receiver_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient2_addr, metadata_obj
            );

        let transfer_amount = 500000;
        fungible_asset::transfer(
            recipient1,
            sender_store,
            receiver_store,
            transfer_amount
        );

        assert!(
            primary_fungible_store::balance(recipient1_addr, metadata_obj)
                == mint_amount - transfer_amount
        );
        assert!(
            primary_fungible_store::balance(recipient2_addr, metadata_obj)
                == transfer_amount
        );
    }

    #[test(owner = @0x999, link = @link)]
    public fun test_initialize_with_max_supply(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj =
            object::address_to_object<Metadata>(link_token::token_metadata());
        assert!(fungible_asset::maximum(metadata_obj) == option::some(MAX_SUPPLY));
    }

    #[test(owner = @0x999, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED,
            location = link::link_token
        )
    ]
    public fun test_initialize_with_same_symbol_fails(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Second initialization (should fail)
        link_token::initialize(
            owner,
            option::none(),
            string::utf8(b"USDC Token"),
            string::utf8(b"USDC"),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(owner = @0x999, new_owner = @0xface, link = @link)]
    public fun test_ownership_transfer_flow(
        owner: &signer, new_owner: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        let owner_addr = signer::address_of(owner);
        let new_owner_addr = signer::address_of(new_owner);

        // Verify initial owner
        assert!(link_token::owner() == owner_addr);

        // Step 1: Owner requests transfer of ownership to new_owner
        link_token::transfer_ownership(owner, new_owner_addr);

        // Ownership should still be with the original owner
        assert!(link_token::owner() == owner_addr);

        // Step 2: New owner accepts the ownership
        link_token::accept_ownership(new_owner);

        // Ownership should still be with the original owner until execution
        assert!(link_token::owner() == owner_addr);

        // Step 3: Original owner executes the transfer
        link_token::execute_ownership_transfer(owner, new_owner_addr);

        // Verify that ownership has been transferred
        assert!(link_token::owner() == new_owner_addr);
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327683, location = link::ownable)]
    public fun test_unauthorized_transfer_ownership(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // User attempts to transfer ownership (should fail) E_ONLY_CALLABLE_BY_OWNER
        link_token::transfer_ownership(user, @0xbeef);
    }

    #[test(
        owner = @0x999, user = @0xface, other = @0xbeef, link = @link
    )]
    #[expected_failure(abort_code = 327681, location = link::ownable)]
    public fun test_wrong_account_accept_ownership(
        owner: &signer,
        user: &signer,
        other: &signer,
        link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // Owner requests transfer to user
        link_token::transfer_ownership(owner, signer::address_of(user));

        // Other account tries to accept (should fail) E_MUST_BE_PROPOSED_OWNER
        link_token::accept_ownership(other);
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327686, location = link::ownable)]
    public fun test_accept_ownership_without_transfer(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // User tries to accept ownership without a pending transfer (should fail) E_NO_PENDING_TRANSFER
        link_token::accept_ownership(user);
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 196615, location = link::ownable)]
    public fun test_execute_transfer_without_acceptance(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // Owner initiates transfer
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, user_addr);

        // Owner tries to execute transfer before user accepts (should fail) E_TRANSFER_NOT_ACCEPTED
        link_token::execute_ownership_transfer(owner, user_addr);
    }

    #[test(
        owner = @0x999, user = @0xface, other = @0xbeef, link = @link
    )]
    #[expected_failure(abort_code = 327684, location = link::ownable)]
    public fun test_execute_transfer_to_wrong_address(
        owner: &signer,
        user: &signer,
        other: &signer,
        link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // Owner initiates transfer to user
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, user_addr);

        // User accepts
        link_token::accept_ownership(user);

        // Owner tries to execute transfer to a different address (should fail) E_PROPOSED_OWNER_MISMATCH
        link_token::execute_ownership_transfer(owner, signer::address_of(other));
    }

    #[test(owner = @0x999, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327683, location = link::ownable)]
    public fun test_unauthorized_execute_transfer(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));

        // Owner initiates transfer
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, user_addr);

        // User accepts
        link_token::accept_ownership(user);

        // User tries to execute the transfer (should fail, only owner can execute) E_ONLY_CALLABLE_BY_OWNER
        link_token::execute_ownership_transfer(user, user_addr);
    }
}
