#[test_only]
module regulated_token::access_control_test {
    use std::account;
    use std::string;
    use std::option;
    use std::object::{Self, Object};
    use std::signer;
    use std::fungible_asset::{Metadata};
    use std::primary_fungible_store;

    use regulated_token::access_control::{Self};

    enum TestRole has copy, drop, store {
        ADMIN_ROLE,
        USER_ROLE,
        MANAGER_ROLE,
        VIEWER_ROLE
    }

    const ADMIN: address = @0x100;
    const USER1: address = @0x200;
    const USER2: address = @0x300;
    const MANAGER: address = @0x400;

    fun setup_token_metadata(creator: &signer): Object<Metadata> {
        let constructor_ref =
            &object::create_named_object(creator, b"test_access_control");

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            string::utf8(b"Test Token"),
            string::utf8(b"TT"),
            8,
            string::utf8(b"https://test.com"),
            string::utf8(b"https://test.com")
        );

        access_control::init<TestRole>(constructor_ref, ADMIN);
        object::object_from_constructor_ref(constructor_ref)
    }

    // ================================================================
    // |                    Basic Functionality Tests                |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_initialization(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);

        let access_obj = setup_token_metadata(creator);

        // Check that the admin is set correctly
        let admin_addr = access_control::admin<Metadata, TestRole>(access_obj);
        assert!(admin_addr == ADMIN);

        // Check that pending admin is initially zero
        let pending_admin_addr =
            access_control::pending_admin<Metadata, TestRole>(access_obj);
        assert!(pending_admin_addr == @0x0);
    }

    #[test(creator = @0x999)]
    fun test_role_management(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Initially user should not have any role
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Grant role to user
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);

        // Now user should have the role
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Check role member count
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 1);

        // Check role members
        let members = access_control::get_role_members(access_obj, TestRole::USER_ROLE);
        assert!(members.length() == 1);
        assert!(members[0] == USER1);

        // Check get role member by index
        let member_at_0 =
            access_control::get_role_member(access_obj, TestRole::USER_ROLE, 0);
        assert!(member_at_0 == USER1);
    }

    #[test(creator = @0x999)]
    fun test_role_revocation(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant role first
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Revoke role
        access_control::revoke_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Check role member count is now 0
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 0);
    }

    #[test(creator = @0x999)]
    fun test_multiple_roles_same_user(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant multiple roles to same user
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        access_control::grant_role(
            &admin,
            access_obj,
            TestRole::MANAGER_ROLE,
            USER1
        );

        // Check both roles
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
        assert!(access_control::has_role(access_obj, USER1, TestRole::MANAGER_ROLE));

        // Revoke one role, other should remain
        access_control::revoke_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
        assert!(access_control::has_role(access_obj, USER1, TestRole::MANAGER_ROLE));
    }

    #[test(creator = @0x999)]
    fun test_multiple_users_same_role(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant same role to multiple users
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER2);

        // Check both users have the role
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
        assert!(access_control::has_role(access_obj, USER2, TestRole::USER_ROLE));

        // Check role member count
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 2);

        // Check all members are returned
        let members = access_control::get_role_members(access_obj, TestRole::USER_ROLE);
        assert!(members.length() == 2, 4);
        assert!(members.contains(&USER1), 5);
        assert!(members.contains(&USER2), 6);
    }

    #[test(creator = @0x999)]
    fun test_role_renunciation(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);
        let user1 = account::create_signer_for_test(USER1);

        // Grant role to user
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(
            access_control::has_role(access_obj, USER1, TestRole::USER_ROLE),
            1
        );

        // User renounces their own role
        access_control::renounce_role(&user1, access_obj, TestRole::USER_ROLE);
        assert!(
            !access_control::has_role(access_obj, USER1, TestRole::USER_ROLE),
            2
        );
    }

    // ================================================================
    // |                    Admin Transfer Tests                      |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_admin_transfer_flow(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);
        let new_admin = account::create_signer_for_test(USER1);

        // Initial state
        assert!(access_control::admin<Metadata, TestRole>(access_obj) == ADMIN);
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == @0x0);

        // Step 1: Current admin initiates transfer
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, USER1);

        // Admin should still be the current admin, but pending admin should be set
        assert!(access_control::admin<Metadata, TestRole>(access_obj) == ADMIN);
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == USER1);

        // Step 2: New admin accepts the role
        access_control::accept_admin<Metadata, TestRole>(&new_admin, access_obj);

        // Now USER1 should be the admin and pending should be reset
        assert!(access_control::admin<Metadata, TestRole>(access_obj) == USER1);
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == @0x0);
    }

    // ================================================================
    // |                    Authorization Tests                       |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_assert_role_success(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant role first
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);

        // Should not abort since USER1 has the role
        access_control::assert_role(access_obj, USER1, TestRole::USER_ROLE);
    }

    // ================================================================
    // |                    Error Condition Tests                     |
    // ================================================================

    #[test(creator = @0x999, user = @0x500)]
    #[
        expected_failure(
            abort_code = access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_grant_role(creator: &signer, user: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(signer::address_of(user));

        let access_obj = setup_token_metadata(creator);

        // Non-admin tries to grant role (should fail)
        access_control::grant_role(
            user,
            access_obj,
            TestRole::USER_ROLE,
            signer::address_of(user)
        );
    }

    #[test(creator = @0x999, user = @0x500)]
    #[
        expected_failure(
            abort_code = access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_revoke_role(creator: &signer, user: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(signer::address_of(user));

        let access_obj = setup_token_metadata(creator);

        // Non-admin tries to revoke role (should fail)
        access_control::revoke_role(
            user,
            access_obj,
            TestRole::USER_ROLE,
            signer::address_of(user)
        );
    }

    #[test(creator = @0x999, user = @0x500)]
    #[
        expected_failure(
            abort_code = access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_transfer_admin(
        creator: &signer, user: &signer
    ) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(signer::address_of(user));

        let access_obj = setup_token_metadata(creator);

        // Non-admin tries to transfer admin (should fail)
        access_control::transfer_admin<Metadata, TestRole>(
            user, access_obj, signer::address_of(user)
        );
    }

    #[test(creator = @0x999, user = @0x500)]
    #[
        expected_failure(
            abort_code = access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_unauthorized_accept_admin(creator: &signer, user: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(signer::address_of(user));

        let access_obj = setup_token_metadata(creator);

        // User tries to accept admin without being the pending admin (should fail)
        access_control::accept_admin<Metadata, TestRole>(user, access_obj);
    }

    #[test(creator = @0x999)]
    #[
        expected_failure(
            abort_code = access_control::E_SAME_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_transfer_admin_to_same_address(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Admin tries to transfer to themselves (should fail)
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, ADMIN);
    }

    #[test(creator = @0x999)]
    #[
        expected_failure(
            abort_code = access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_assert_role_failure(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);

        // Should abort since USER1 doesn't have the role
        access_control::assert_role(access_obj, USER1, TestRole::USER_ROLE);
    }

    #[test(creator = @0x999)]
    #[
        expected_failure(
            abort_code = access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    fun test_get_role_member_out_of_bounds(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);

        let access_obj = setup_token_metadata(creator);

        // Should abort since there are no members for USER_ROLE
        access_control::get_role_member(access_obj, TestRole::USER_ROLE, 0);
    }

    // ================================================================
    // |                    Edge Case Tests                          |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_duplicate_role_grant(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Grant role
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Grant same role again (should be idempotent)
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Should still only have one member
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 1);
    }

    #[test(creator = @0x999)]
    fun test_revoke_non_existent_role(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Try to revoke role that was never granted (should not crash)
        access_control::revoke_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
    }

    #[test(creator = @0x999)]
    fun test_empty_role_queries(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);

        let access_obj = setup_token_metadata(creator);

        // Check empty role queries
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 0);

        let members = access_control::get_role_members(access_obj, TestRole::USER_ROLE);
        assert!(members.length() == 0);

        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
    }

    // ================================================================
    // |                        Error Code Tests                      |
    // ================================================================

    #[test(creator = @0x999)]
    #[
        expected_failure(
            abort_code = access_control::E_ROLE_STATE_NOT_INITIALIZED,
            location = regulated_token::access_control
        )
    ]
    fun test_uninitialized_state_access_fails(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));

        // Create object but don't initialize access control
        let constructor_ref = &object::create_named_object(creator, b"test_uninit");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            string::utf8(b"Test Token"),
            string::utf8(b"TT"),
            8,
            string::utf8(b"https://test.com"),
            string::utf8(b"https://test.com")
        );
        let uninit_obj = object::object_from_constructor_ref<Metadata>(constructor_ref);

        // Try to access uninitialized state - should fail
        access_control::has_role(uninit_obj, USER1, TestRole::USER_ROLE);
    }

    // ================================================================
    // |                    Renounce Role Edge Cases                 |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_renounce_non_existent_role_noop(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let user1 = account::create_signer_for_test(USER1);

        // User tries to renounce role they don't have - should be no-op
        access_control::renounce_role(&user1, access_obj, TestRole::USER_ROLE);

        // Should still not have the role
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Role member count should still be 0
        let count = access_control::get_role_member_count(
            access_obj, TestRole::USER_ROLE
        );
        assert!(count == 0);
    }

    #[test(creator = @0x999)]
    fun test_renounce_role_idempotency(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);
        let user1 = account::create_signer_for_test(USER1);

        // Grant role first
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER1);
        assert!(access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Renounce role
        access_control::renounce_role(&user1, access_obj, TestRole::USER_ROLE);
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));

        // Try to renounce again - should be idempotent (no crash)
        access_control::renounce_role(&user1, access_obj, TestRole::USER_ROLE);
        assert!(!access_control::has_role(access_obj, USER1, TestRole::USER_ROLE));
    }

    // ================================================================
    // |                    Admin Transfer Edge Cases                |
    // ================================================================

    #[test(creator = @0x999)]
    fun test_transfer_admin_to_zero_address(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Transfer admin to zero address should work (no validation against it)
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, @0x0);

        // Pending admin should be zero address
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == @0x0);
        // Original admin should still be admin until accepted
        assert!(access_control::admin<Metadata, TestRole>(access_obj) == ADMIN);
    }

    #[test(creator = @0x999)]
    #[
        expected_failure(
            abort_code = access_control::E_NOT_ADMIN,
            location = regulated_token::access_control
        )
    ]
    fun test_accept_admin_when_no_pending_fails(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);

        let access_obj = setup_token_metadata(creator);
        let user1 = account::create_signer_for_test(USER1);

        // No transfer was initiated, so USER1 trying to accept should fail
        access_control::accept_admin<Metadata, TestRole>(&user1, access_obj);
    }

    #[test(creator = @0x999)]
    fun test_transfer_admin_overwrites_pending(creator: &signer) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Transfer to USER1 first
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, USER1);
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == USER1);

        // Transfer to USER2 should overwrite pending
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, USER2);
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == USER2);

        // USER1 should no longer be able to accept
        let _user1 = account::create_signer_for_test(USER1);
        // This should fail since USER2 is now the pending admin
    }

    #[test(creator = @0x999)]
    fun test_admin_operations_after_transfer_before_accept(
        creator: &signer
    ) {
        account::create_account_for_test(signer::address_of(creator));
        account::create_account_for_test(ADMIN);
        account::create_account_for_test(USER1);
        account::create_account_for_test(USER2);

        let access_obj = setup_token_metadata(creator);
        let admin = account::create_signer_for_test(ADMIN);

        // Transfer admin to USER1
        access_control::transfer_admin<Metadata, TestRole>(&admin, access_obj, USER1);

        // Original admin should still be able to perform admin operations
        access_control::grant_role(&admin, access_obj, TestRole::USER_ROLE, USER2);
        assert!(access_control::has_role(access_obj, USER2, TestRole::USER_ROLE));

        // Current admin should still be ADMIN
        assert!(access_control::admin<Metadata, TestRole>(access_obj) == ADMIN);
        // Pending should be USER1
        assert!(access_control::pending_admin<Metadata, TestRole>(access_obj) == USER1);
    }
}
