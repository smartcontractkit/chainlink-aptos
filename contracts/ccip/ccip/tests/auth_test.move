#[test_only]
module ccip::auth_test {
    use std::signer;
    use std::account;
    use std::option;
    use std::vector;
    use std::object;

    use ccip::auth;
    use ccip::state_object;

    const OWNER: address = @0x100;
    const NEW_OWNER: address = @0x200;
    const ONRAMP_1: address = @0x300;
    const ONRAMP_2: address = @0x400;
    const OFFRAMP_1: address = @0x500;
    const OFFRAMP_2: address = @0x600;
    const UNAUTHORIZED: address = @0x700;

    fun setup(ccip: &signer, owner: &signer): signer {
        account::create_account_for_test(signer::address_of(ccip));
        let new_owner_account = account::create_account_for_test(NEW_OWNER);
        account::create_account_for_test(UNAUTHORIZED);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        new_owner_account
    }

    // ================================================================
    // |                    Initialization Tests                      |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_initialization(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);

        let current_owner = auth::owner();
        assert!(current_owner == signer::address_of(owner), 0);

        let allowed_onramps = auth::get_allowed_onramps();
        assert!(vector::length(&allowed_onramps) == 0, 1);

        let allowed_offramps = auth::get_allowed_offramps();
        assert!(vector::length(&allowed_offramps) == 0, 2);

        assert!(!auth::has_pending_transfer(), 3);
        assert!(auth::pending_transfer_from() == option::none(), 4);
        assert!(auth::pending_transfer_to() == option::none(), 5);
    }

    // ================================================================
    // |                   Onramp Allowlist Tests                     |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_apply_allowed_onramp_updates_add(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        assert!(!auth::is_onramp_allowed(ONRAMP_1), 0);
        assert!(!auth::is_onramp_allowed(ONRAMP_2), 1);

        auth::apply_allowed_onramp_updates(
            ccip,
            vector[], // remove
            vector[ONRAMP_1, ONRAMP_2] // add
        );

        assert!(auth::is_onramp_allowed(ONRAMP_1), 2);
        assert!(auth::is_onramp_allowed(ONRAMP_2), 3);

        let allowed_onramps = auth::get_allowed_onramps();
        assert!(vector::length(&allowed_onramps) == 2, 4);
        assert!(vector::contains(&allowed_onramps, &ONRAMP_1), 5);
        assert!(vector::contains(&allowed_onramps, &ONRAMP_2), 6);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_apply_allowed_onramp_updates_remove(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        auth::apply_allowed_onramp_updates(
            ccip,
            vector[], // remove
            vector[ONRAMP_1, ONRAMP_2] // add
        );

        assert!(auth::is_onramp_allowed(ONRAMP_1), 0);
        assert!(auth::is_onramp_allowed(ONRAMP_2), 1);

        auth::apply_allowed_onramp_updates(
            ccip, vector[ONRAMP_1], // remove
            vector[] // add
        );

        assert!(!auth::is_onramp_allowed(ONRAMP_1), 2);
        assert!(auth::is_onramp_allowed(ONRAMP_2), 3);

        let allowed_onramps = auth::get_allowed_onramps();
        assert!(vector::length(&allowed_onramps) == 1, 4);
        assert!(vector::contains(&allowed_onramps, &ONRAMP_2), 5);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327684, location = ccip::auth)]
    fun test_apply_allowed_onramp_updates_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);
        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_CCIP - unauthorized user cannot update onramps
        auth::apply_allowed_onramp_updates(
            &unauthorized, vector[], // remove
            vector[ONRAMP_1] // add
        );
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_assert_is_allowed_onramp_success(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // Add onramp
        auth::apply_allowed_onramp_updates(
            ccip, vector[], // remove
            vector[ONRAMP_1] // add
        );

        // Should not abort
        auth::assert_is_allowed_onramp(ONRAMP_1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327682, location = ccip::auth)]
    fun test_assert_is_allowed_onramp_failure(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // E_NOT_ALLOWED_ONRAMP - onramp not in allowlist
        auth::assert_is_allowed_onramp(ONRAMP_1);
    }

    // ================================================================
    // |                   Offramp Allowlist Tests                    |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_apply_allowed_offramp_updates_add(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // Initially no offramps allowed
        assert!(!auth::is_offramp_allowed(OFFRAMP_1), 0);
        assert!(!auth::is_offramp_allowed(OFFRAMP_2), 1);

        // Add offramps
        auth::apply_allowed_offramp_updates(
            ccip,
            vector[], // remove
            vector[OFFRAMP_1, OFFRAMP_2] // add
        );

        // Verify offramps are now allowed
        assert!(auth::is_offramp_allowed(OFFRAMP_1), 2);
        assert!(auth::is_offramp_allowed(OFFRAMP_2), 3);

        let allowed_offramps = auth::get_allowed_offramps();
        assert!(vector::length(&allowed_offramps) == 2, 4);
        assert!(vector::contains(&allowed_offramps, &OFFRAMP_1), 5);
        assert!(vector::contains(&allowed_offramps, &OFFRAMP_2), 6);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_apply_allowed_offramp_updates_remove(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // First add offramps
        auth::apply_allowed_offramp_updates(
            ccip,
            vector[], // remove
            vector[OFFRAMP_1, OFFRAMP_2] // add
        );

        // Remove one offramp
        auth::apply_allowed_offramp_updates(
            ccip, vector[OFFRAMP_1], // remove
            vector[] // add
        );

        // Verify removal
        assert!(!auth::is_offramp_allowed(OFFRAMP_1), 0);
        assert!(auth::is_offramp_allowed(OFFRAMP_2), 1);

        let allowed_offramps = auth::get_allowed_offramps();
        assert!(vector::length(&allowed_offramps) == 1, 2);
        assert!(vector::contains(&allowed_offramps, &OFFRAMP_2), 3);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327684, location = ccip::auth)]
    fun test_apply_allowed_offramp_updates_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);
        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_CCIP - unauthorized user cannot update offramps
        auth::apply_allowed_offramp_updates(
            &unauthorized, vector[], // remove
            vector[OFFRAMP_1] // add
        );
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_assert_is_allowed_offramp_success(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // Add offramp
        auth::apply_allowed_offramp_updates(
            ccip, vector[], // remove
            vector[OFFRAMP_1] // add
        );

        // Should not abort
        auth::assert_is_allowed_offramp(OFFRAMP_1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::auth)]
    fun test_assert_is_allowed_offramp_failure(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);

        // E_NOT_ALLOWED_OFFRAMP - offramp not in allowlist
        auth::assert_is_allowed_offramp(OFFRAMP_1);
    }

    // ================================================================
    // |                    Ownership Tests                           |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_transfer_ownership_request(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);
        let owner_addr = signer::address_of(owner);
        // Initial state
        assert!(auth::owner() == owner_addr, 0);
        assert!(!auth::has_pending_transfer(), 1);

        // Request transfer
        auth::transfer_ownership(owner, NEW_OWNER);

        // Verify pending transfer state
        assert!(auth::owner() == owner_addr, 2); // Owner shouldn't change yet
        assert!(auth::has_pending_transfer(), 3);
        assert!(auth::pending_transfer_from() == option::some(owner_addr), 4);
        assert!(auth::pending_transfer_to() == option::some(NEW_OWNER), 5);
        assert!(auth::pending_transfer_accepted() == option::some(false), 6);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_accept_ownership(ccip: &signer, owner: &signer) {
        let new_owner_account = setup(ccip, owner);

        // Request transfer
        auth::transfer_ownership(owner, NEW_OWNER);

        // Accept ownership
        auth::accept_ownership(&new_owner_account);

        // Verify acceptance
        assert!(auth::owner() == signer::address_of(owner), 0); // Owner still shouldn't change
        assert!(auth::has_pending_transfer(), 1);
        assert!(auth::pending_transfer_accepted() == option::some(true), 2);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_complete_ownership_transfer(ccip: &signer, owner: &signer) {
        let new_owner_account = setup(ccip, owner);

        // Request transfer
        auth::transfer_ownership(owner, NEW_OWNER);

        // Accept ownership
        auth::accept_ownership(&new_owner_account);

        // Execute transfer
        auth::execute_ownership_transfer(owner, NEW_OWNER);

        // Verify complete transfer
        assert!(auth::owner() == NEW_OWNER, 0);
        assert!(!auth::has_pending_transfer(), 1);
        assert!(auth::pending_transfer_from() == option::none(), 2);
        assert!(auth::pending_transfer_to() == option::none(), 3);
        assert!(auth::pending_transfer_accepted() == option::none(), 4);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_transfer_ownership_only_owner(ccip: &signer, owner: &signer) {
        let new_owner_account = setup(ccip, owner);

        // E_ONLY_CALLABLE_BY_OWNER - non-owner cannot transfer ownership
        auth::transfer_ownership(&new_owner_account, NEW_OWNER);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327681, location = ccip::ownable)]
    fun test_accept_ownership_only_proposed(
        ccip: &signer, owner: &signer
    ) {
        let _new_owner_account = setup(ccip, owner);
        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // Request transfer to NEW_OWNER
        auth::transfer_ownership(owner, NEW_OWNER);

        // E_MUST_BE_PROPOSED_OWNER - unauthorized user cannot accept
        auth::accept_ownership(&unauthorized);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_assert_only_owner_success(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);

        // Should not abort for owner
        auth::assert_only_owner(signer::address_of(owner));
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_assert_only_owner_failure(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);

        // E_ONLY_CALLABLE_BY_OWNER - non-owner should fail
        auth::assert_only_owner(UNAUTHORIZED);
    }

    // ================================================================
    // |                   Owner or CCIP Access Tests                 |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_owner_can_update_allowlists_after_transfer(
        ccip: &signer, owner: &signer
    ) {
        let new_owner_account = setup(ccip, owner);

        // Complete ownership transfer
        auth::transfer_ownership(owner, NEW_OWNER);
        auth::accept_ownership(&new_owner_account);
        auth::execute_ownership_transfer(owner, NEW_OWNER);

        // New owner should be able to update allowlists
        auth::apply_allowed_onramp_updates(
            &new_owner_account, vector[], // remove
            vector[ONRAMP_1] // add
        );

        auth::apply_allowed_offramp_updates(
            &new_owner_account, vector[], // remove
            vector[OFFRAMP_1] // add
        );

        // Verify updates worked
        assert!(auth::is_onramp_allowed(ONRAMP_1), 0);
        assert!(auth::is_offramp_allowed(OFFRAMP_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_ccip_can_always_update_allowlists(
        ccip: &signer, owner: &signer
    ) {
        let new_owner_account = setup(ccip, owner);

        // Transfer ownership to someone else
        auth::transfer_ownership(owner, NEW_OWNER);
        auth::accept_ownership(&new_owner_account);
        auth::execute_ownership_transfer(owner, NEW_OWNER);

        // @ccip should still be able to update allowlists
        auth::apply_allowed_onramp_updates(
            ccip, vector[], // remove
            vector[ONRAMP_1] // add
        );

        auth::apply_allowed_offramp_updates(
            ccip, vector[], // remove
            vector[OFFRAMP_1] // add
        );

        // Verify updates worked
        assert!(auth::is_onramp_allowed(ONRAMP_1), 0);
        assert!(auth::is_offramp_allowed(OFFRAMP_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_multiple_allowlist_operations(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);

        // Add multiple onramps and offramps
        auth::apply_allowed_onramp_updates(
            ccip,
            vector[], // remove
            vector[ONRAMP_1, ONRAMP_2] // add
        );

        auth::apply_allowed_offramp_updates(
            ccip,
            vector[], // remove
            vector[OFFRAMP_1, OFFRAMP_2] // add
        );

        // Verify all are allowed
        assert!(auth::is_onramp_allowed(ONRAMP_1), 0);
        assert!(auth::is_onramp_allowed(ONRAMP_2), 1);
        assert!(auth::is_offramp_allowed(OFFRAMP_1), 2);
        assert!(auth::is_offramp_allowed(OFFRAMP_2), 3);

        // Remove some and add others in same transaction
        auth::apply_allowed_onramp_updates(
            ccip,
            vector[ONRAMP_1], // remove
            vector[UNAUTHORIZED] // add (reusing constant for different onramp)
        );

        // Verify state
        assert!(!auth::is_onramp_allowed(ONRAMP_1), 4);
        assert!(auth::is_onramp_allowed(ONRAMP_2), 5);
        assert!(auth::is_onramp_allowed(UNAUTHORIZED), 6);

        let allowed_onramps = auth::get_allowed_onramps();
        assert!(vector::length(&allowed_onramps) == 2, 7);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_empty_allowlist_operations(ccip: &signer, owner: &signer) {
        let _new_owner_account = setup(ccip, owner);

        // Empty operations should work
        auth::apply_allowed_onramp_updates(
            ccip, vector[], // remove nothing
            vector[] // add nothing
        );

        auth::apply_allowed_offramp_updates(
            ccip, vector[], // remove nothing
            vector[] // add nothing
        );

        // State should remain unchanged
        let allowed_onramps = auth::get_allowed_onramps();
        let allowed_offramps = auth::get_allowed_offramps();
        assert!(vector::length(&allowed_onramps) == 0, 0);
        assert!(vector::length(&allowed_offramps) == 0, 1);
    }
}
