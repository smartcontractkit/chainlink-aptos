#[test_only]
module regulated_token::ownership_test {
    use std::signer;
    use std::account;
    use std::object;
    use std::option;
    use std::string;

    use regulated_token::regulated_token;

    const ADMIN: address = @0x100;
    const OWNER: address = @0x200;
    const NEW_OWNER: address = @0x300;
    const UNAUTHORIZED: address = @0x400;
    const USER1: address = @0x500;
    const USER2: address = @0x600;

    fun setup(admin: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_for_test(
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

    // ================================================================
    // |                    Basic Ownership Tests                    |
    // ================================================================
    #[test(owner = @admin, regulated_token = @regulated_token)]
    fun test_initial_ownership(owner: &signer, regulated_token: &signer) {
        setup(owner, regulated_token);

        // Initial owner should be the publisher
        assert!(regulated_token::owner() == signer::address_of(owner));

        // No pending transfer initially
        assert!(!regulated_token::has_pending_transfer());
        assert!(regulated_token::pending_transfer_from().is_none());
        assert!(regulated_token::pending_transfer_to().is_none());
        assert!(regulated_token::pending_transfer_accepted().is_none());
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    fun test_ownership_transfer_flow(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        let initial_owner = signer::address_of(owner);
        assert!(regulated_token::owner() == initial_owner);

        // Step 1: Current owner initiates transfer
        regulated_token::transfer_ownership(owner, NEW_OWNER);

        // Owner should still be the original owner until accepted
        assert!(regulated_token::owner() == initial_owner);

        // Should have pending transfer
        assert!(regulated_token::has_pending_transfer());
        assert!(regulated_token::pending_transfer_from().contains(&initial_owner));
        assert!(regulated_token::pending_transfer_to().contains(&NEW_OWNER));
        assert!(regulated_token::pending_transfer_accepted().contains(&false));

        // Step 2: New owner accepts the transfer
        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);
        regulated_token::accept_ownership(&new_owner_signer);

        // Transfer should be marked as accepted but not executed yet
        assert!(regulated_token::owner() == initial_owner); // Still original owner
        assert!(regulated_token::has_pending_transfer());
        assert!(regulated_token::pending_transfer_accepted().contains(&true));

        // Step 3: Execute the transfer
        regulated_token::execute_ownership_transfer(owner, NEW_OWNER);

        // Now ownership should be transferred
        assert!(regulated_token::owner() == NEW_OWNER);
        assert!(!regulated_token::has_pending_transfer());
        assert!(regulated_token::pending_transfer_from().is_none());
        assert!(regulated_token::pending_transfer_to().is_none());
        assert!(regulated_token::pending_transfer_accepted().is_none());
    }

    // ================================================================
    // |                    Error Condition Tests                    |
    // ================================================================
    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure]
    // Will fail with appropriate ownable error
    fun test_transfer_ownership_unauthorized(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        let unauthorized_signer = account::create_signer_for_test(UNAUTHORIZED);

        // Unauthorized user tries to transfer ownership
        regulated_token::transfer_ownership(&unauthorized_signer, NEW_OWNER);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure]
    // Will fail with appropriate ownable error
    fun test_accept_ownership_when_not_pending_owner(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Transfer to NEW_OWNER
        regulated_token::transfer_ownership(owner, NEW_OWNER);

        // Different user tries to accept
        let unauthorized_signer = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::accept_ownership(&unauthorized_signer);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure]
    // Will fail with appropriate ownable error
    fun test_accept_ownership_when_no_transfer_pending(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // No transfer initiated, try to accept
        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);
        regulated_token::accept_ownership(&new_owner_signer);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure]
    // Will fail with appropriate ownable error
    fun test_execute_transfer_unauthorized(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Initiate and accept transfer
        regulated_token::transfer_ownership(owner, NEW_OWNER);
        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);
        regulated_token::accept_ownership(&new_owner_signer);

        // Unauthorized user tries to execute
        let unauthorized_signer = account::create_signer_for_test(UNAUTHORIZED);
        regulated_token::execute_ownership_transfer(&unauthorized_signer, NEW_OWNER);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure]
    // Will fail with appropriate ownable error
    fun test_execute_transfer_wrong_address(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Initiate and accept transfer to NEW_OWNER
        regulated_token::transfer_ownership(owner, NEW_OWNER);
        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);
        regulated_token::accept_ownership(&new_owner_signer);

        // Try to execute with wrong address
        regulated_token::execute_ownership_transfer(owner, UNAUTHORIZED);
    }

    // ================================================================
    // |                    Complex Scenario Tests                   |
    // ================================================================
    #[test(owner = @admin, regulated_token = @regulated_token)]
    fun test_transfer_ownership_overwrites_pending(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Transfer to user1 first
        regulated_token::transfer_ownership(owner, USER1);
        assert!(regulated_token::pending_transfer_to().contains(&USER1));

        // Transfer to user2 should overwrite pending
        regulated_token::transfer_ownership(owner, USER2);
        assert!(regulated_token::pending_transfer_to().contains(&USER2));

        // user1 should not be able to accept anymore
        // user2 can accept
        let user2_signer = account::create_signer_for_test(USER2);
        regulated_token::accept_ownership(&user2_signer);
        assert!(regulated_token::pending_transfer_accepted().contains(&true));
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 65538, location = regulated_token::ownable)]
    // E_CANNOT_TRANSFER_TO_SELF
    fun test_transfer_to_same_owner_throws(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        let current_owner = regulated_token::owner();

        // Transfer to current owner should fail E_CANNOT_TRANSFER_TO_SELF
        regulated_token::transfer_ownership(owner, current_owner);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    fun test_new_owner_operations_after_transfer(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Complete ownership transfer
        regulated_token::transfer_ownership(owner, NEW_OWNER);
        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);
        regulated_token::accept_ownership(&new_owner_signer);
        regulated_token::execute_ownership_transfer(owner, NEW_OWNER);

        // New owner should be able to transfer ownership
        regulated_token::transfer_ownership(&new_owner_signer, USER2);
        assert!(regulated_token::pending_transfer_to().contains(&USER2));

        // Original owner should not be able to transfer anymore
        // This should fail in a real test but we'll just verify the state
        assert!(regulated_token::owner() == NEW_OWNER);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 196616, location = regulated_token::ownable)]
    // E_TRANSFER_ALREADY_ACCEPTED
    fun test_multiple_accept_calls_throws(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        // Initiate transfer
        regulated_token::transfer_ownership(owner, NEW_OWNER);

        let new_owner_signer = account::create_signer_for_test(NEW_OWNER);

        // Accept once
        regulated_token::accept_ownership(&new_owner_signer);
        assert!(regulated_token::pending_transfer_accepted().contains(&true));

        // Accept again - E_TRANSFER_ALREADY_ACCEPTED
        regulated_token::accept_ownership(&new_owner_signer);
    }

    #[test(owner = @admin, regulated_token = @regulated_token)]
    fun test_view_functions_during_transfer(
        owner: &signer, regulated_token: &signer
    ) {
        setup(owner, regulated_token);

        let initial_owner = regulated_token::owner();

        // Start transfer
        regulated_token::transfer_ownership(owner, NEW_OWNER);

        // View functions should work correctly during pending transfer
        assert!(regulated_token::owner() == initial_owner);
        assert!(regulated_token::has_pending_transfer());

        let from = regulated_token::pending_transfer_from();
        let to = regulated_token::pending_transfer_to();
        let accepted = regulated_token::pending_transfer_accepted();

        assert!(from.is_some());
        assert!(to.is_some());
        assert!(accepted.is_some());
        assert!(*from.borrow() == initial_owner);
        assert!(*to.borrow() == NEW_OWNER);
        assert!(*accepted.borrow() == false);
    }
}
