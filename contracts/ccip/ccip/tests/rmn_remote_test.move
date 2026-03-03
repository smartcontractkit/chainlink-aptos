#[test_only]
module ccip::rmn_remote_test {
    use std::signer;
    use std::account;
    use std::vector;
    use std::object;

    use ccip::auth;
    use ccip::rmn_remote;
    use ccip::state_object;

    const CHAIN_SELECTOR: u64 = 743186221051783445;

    const OWNER: address = @mcms;
    const CURSER_1: address = @0x100;
    const CURSER_2: address = @0x200;
    const CURSER_3: address = @0x300;
    const UNAUTHORIZED: address = @0x400;

    // 16-byte subject for curse tests
    const SUBJECT_1: vector<u8> = x"01000000000000000000000000000002";
    const SUBJECT_2: vector<u8> = x"01000000000000000000000000000003";

    fun setup(ccip: &signer, owner: &signer) {
        account::create_account_for_test(signer::address_of(ccip));
        account::create_account_for_test(CURSER_1);
        account::create_account_for_test(CURSER_2);
        account::create_account_for_test(CURSER_3);
        account::create_account_for_test(UNAUTHORIZED);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        // Use initialize_v1 for legacy tests (testing V1 -> V2 migration scenarios)
        rmn_remote::initialize_v1(owner, CHAIN_SELECTOR);
    }

    /// Setup function for tests that need full V2 initialization
    fun setup_v2(ccip: &signer, owner: &signer) {
        account::create_account_for_test(signer::address_of(ccip));
        account::create_account_for_test(CURSER_1);
        account::create_account_for_test(CURSER_2);
        account::create_account_for_test(CURSER_3);
        account::create_account_for_test(UNAUTHORIZED);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        // Use full initialize (creates both V1 and V2 resources)
        rmn_remote::initialize(owner, CHAIN_SELECTOR);
    }

    // ================================================================
    // |                  V2 Initialize Pattern Tests                  |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_initialize_creates_v2_resource(
        ccip: &signer, owner: &signer
    ) {
        setup_v2(ccip, owner);

        // AllowedCursersV2 should exist and be empty
        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 0, 0);

        // Owner can curse (V2 resource exists, no need to call initialize_allowed_cursers_v2)
        rmn_remote::curse(owner, SUBJECT_1);
        assert!(rmn_remote::is_cursed(SUBJECT_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_initialize_v2_can_add_cursers_directly(
        ccip: &signer, owner: &signer
    ) {
        setup_v2(ccip, owner);

        // With full initialize, we can add cursers directly (no need to initialize_allowed_cursers_v2)
        rmn_remote::add_allowed_cursers(owner, vector[CURSER_1]);

        assert!(rmn_remote::is_allowed_curser(CURSER_1), 0);

        let curser =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );

        // Curser can curse
        rmn_remote::curse(&curser, SUBJECT_1);
        assert!(rmn_remote::is_cursed(SUBJECT_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 524308, location = ccip::rmn_remote)]
    fun test_initialize_v2_cannot_call_initialize_allowed_cursers_v2(
        ccip: &signer, owner: &signer
    ) {
        setup_v2(ccip, owner);

        // E_ALLOWED_CURSERS_V2_ALREADY_INITIALIZED - V2 resource already exists from initialize
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);
    }

    // ================================================================
    // |       AllowedCursersV2 Initialization Tests (Legacy V1)       |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_initialize_allowed_cursers_v2_empty(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Before initialization, get_allowed_cursers should return empty
        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 0, 0);

        // Initialize with empty list
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[]);

        // Still empty after initialization
        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 0, 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_initialize_allowed_cursers_v2_with_cursers(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Initialize with cursers
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1, CURSER_2]);

        // Verify cursers are allowed
        assert!(rmn_remote::is_allowed_curser(CURSER_1), 0);
        assert!(rmn_remote::is_allowed_curser(CURSER_2), 1);
        assert!(!rmn_remote::is_allowed_curser(CURSER_3), 2);
        assert!(!rmn_remote::is_allowed_curser(UNAUTHORIZED), 3);

        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 2, 4);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 524308, location = ccip::rmn_remote)]
    fun test_initialize_allowed_cursers_v2_already_initialized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Initialize once
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // E_ALLOWED_CURSERS_V2_ALREADY_INITIALIZED - second initialization should fail
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_2]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_initialize_allowed_cursers_v2_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_ONLY_CALLABLE_BY_OWNER - non-owner cannot initialize
        rmn_remote::initialize_allowed_cursers_v2(&unauthorized, vector[CURSER_1]);
    }

    // ================================================================
    // |                Add/Remove Allowed Cursers Tests               |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_add_allowed_cursers(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Initialize first
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[]);

        // Add cursers
        rmn_remote::add_allowed_cursers(owner, vector[CURSER_1, CURSER_2]);

        // Verify
        assert!(rmn_remote::is_allowed_curser(CURSER_1), 0);
        assert!(rmn_remote::is_allowed_curser(CURSER_2), 1);
        assert!(!rmn_remote::is_allowed_curser(CURSER_3), 2);

        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 2, 3);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_remove_allowed_cursers(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Initialize with cursers
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1, CURSER_2]);

        // Remove one
        rmn_remote::remove_allowed_cursers(owner, vector[CURSER_1]);

        // Verify
        assert!(!rmn_remote::is_allowed_curser(CURSER_1), 0);
        assert!(rmn_remote::is_allowed_curser(CURSER_2), 1);

        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 1, 2);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 196629, location = ccip::rmn_remote)]
    fun test_add_allowed_cursers_not_initialized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // E_ALLOWED_CURSERS_V2_NOT_INITIALIZED - cannot add without initialization
        rmn_remote::add_allowed_cursers(owner, vector[CURSER_1]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 196629, location = ccip::rmn_remote)]
    fun test_remove_allowed_cursers_not_initialized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // E_ALLOWED_CURSERS_V2_NOT_INITIALIZED - cannot remove without initialization
        rmn_remote::remove_allowed_cursers(owner, vector[CURSER_1]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 524310, location = ccip::rmn_remote)]
    fun test_add_allowed_cursers_already_allowed(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // E_CURSER_ALREADY_ALLOWED - cannot add duplicate
        rmn_remote::add_allowed_cursers(owner, vector[CURSER_1]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 393239, location = ccip::rmn_remote)]
    fun test_remove_allowed_cursers_not_allowed(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // E_CURSER_NOT_ALLOWED - cannot remove non-existent curser
        rmn_remote::remove_allowed_cursers(owner, vector[CURSER_2]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_add_allowed_cursers_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[]);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_ONLY_CALLABLE_BY_OWNER - non-owner cannot add
        rmn_remote::add_allowed_cursers(&unauthorized, vector[CURSER_1]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_remove_allowed_cursers_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_ONLY_CALLABLE_BY_OWNER - non-owner cannot remove
        rmn_remote::remove_allowed_cursers(&unauthorized, vector[CURSER_1]);
    }

    // ================================================================
    // |                   Curse/Uncurse Authorization Tests           |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_curse_by_owner(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Owner can curse without AllowedCursersV2 initialized (backward compat)
        rmn_remote::curse(owner, SUBJECT_1);

        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_curse_by_owner_with_v2_initialized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Initialize V2
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // Owner can still curse
        rmn_remote::curse(owner, SUBJECT_1);

        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_curse_by_allowed_curser(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Initialize V2 with CURSER_1
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        let curser =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );

        // Allowed curser can curse
        rmn_remote::curse(&curser, SUBJECT_1);

        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_curse_multiple_by_allowed_curser(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        let curser =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );

        // Allowed curser can curse multiple subjects
        rmn_remote::curse_multiple(&curser, vector[SUBJECT_1, SUBJECT_2]);

        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);
        assert!(rmn_remote::is_cursed(SUBJECT_2), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327699, location = ccip::rmn_remote)]
    fun test_curse_by_unauthorized(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Initialize V2 but don't add UNAUTHORIZED
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_ALLOWED_CURSER - unauthorized cannot curse
        rmn_remote::curse(&unauthorized, SUBJECT_1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327699, location = ccip::rmn_remote)]
    fun test_curse_by_unauthorized_v1(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // V1 behavior: without AllowedCursersV2, only owner can curse
        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // Since V2 is not initialized, is_allowed_curser returns false
        // and caller is not owner, so it fails with E_NOT_OWNER_OR_ALLOWED_CURSER (19)
        rmn_remote::curse(&unauthorized, SUBJECT_1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_uncurse_by_owner(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Curse first
        rmn_remote::curse(owner, SUBJECT_1);
        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);

        // Owner can uncurse
        rmn_remote::uncurse(owner, SUBJECT_1);
        assert!(!rmn_remote::is_cursed(SUBJECT_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_uncurse_by_allowed_curser(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // Owner curses
        rmn_remote::curse(owner, SUBJECT_1);
        assert!(rmn_remote::is_cursed(SUBJECT_1), 0);

        let curser =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );

        // Allowed curser can uncurse
        rmn_remote::uncurse(&curser, SUBJECT_1);
        assert!(!rmn_remote::is_cursed(SUBJECT_1), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_uncurse_multiple_by_allowed_curser(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // Curse multiple
        rmn_remote::curse_multiple(owner, vector[SUBJECT_1, SUBJECT_2]);

        let curser =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );

        // Allowed curser can uncurse multiple
        rmn_remote::uncurse_multiple(&curser, vector[SUBJECT_1, SUBJECT_2]);

        assert!(!rmn_remote::is_cursed(SUBJECT_1), 0);
        assert!(!rmn_remote::is_cursed(SUBJECT_2), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327699, location = ccip::rmn_remote)]
    fun test_uncurse_by_unauthorized(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // Curse first
        rmn_remote::curse(owner, SUBJECT_1);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_ALLOWED_CURSER - unauthorized cannot uncurse
        rmn_remote::uncurse(&unauthorized, SUBJECT_1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327699, location = ccip::rmn_remote)]
    fun test_curse_multiple_by_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Initialize V2 but don't add UNAUTHORIZED
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_ALLOWED_CURSER - unauthorized cannot curse_multiple
        rmn_remote::curse_multiple(&unauthorized, vector[SUBJECT_1, SUBJECT_2]);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327699, location = ccip::rmn_remote)]
    fun test_uncurse_multiple_by_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);

        // Curse multiple subjects first
        rmn_remote::curse_multiple(owner, vector[SUBJECT_1, SUBJECT_2]);

        let unauthorized =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(UNAUTHORIZED)
            );

        // E_NOT_OWNER_OR_ALLOWED_CURSER - unauthorized cannot uncurse_multiple
        rmn_remote::uncurse_multiple(&unauthorized, vector[SUBJECT_1, SUBJECT_2]);
    }

    // ================================================================
    // |                       View Functions Tests                    |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_is_allowed_curser_without_v2(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Without V2 initialized, everyone returns false
        assert!(!rmn_remote::is_allowed_curser(CURSER_1), 0);
        assert!(!rmn_remote::is_allowed_curser(OWNER), 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_allowed_cursers_without_v2(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Without V2 initialized, returns empty vector
        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 0, 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_allowed_cursers_with_v2(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1, CURSER_2]);

        let cursers = rmn_remote::get_allowed_cursers();
        assert!(vector::length(&cursers) == 2, 0);
        assert!(vector::contains(&cursers, &CURSER_1), 1);
        assert!(vector::contains(&cursers, &CURSER_2), 2);
    }

    // ================================================================
    // |                   Curser Lifecycle Test                       |
    // ================================================================
    #[test(ccip = @ccip, owner = @mcms)]
    fun test_curser_lifecycle(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // 1. Initialize with one curser
        rmn_remote::initialize_allowed_cursers_v2(owner, vector[CURSER_1]);
        assert!(rmn_remote::is_allowed_curser(CURSER_1), 0);

        // 2. Curser can curse
        let curser1 =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_1)
            );
        rmn_remote::curse(&curser1, SUBJECT_1);
        assert!(rmn_remote::is_cursed(SUBJECT_1), 1);

        // 3. Add another curser
        rmn_remote::add_allowed_cursers(owner, vector[CURSER_2]);
        assert!(rmn_remote::is_allowed_curser(CURSER_2), 2);

        // 4. New curser can also curse
        let curser2 =
            account::create_signer_with_capability(
                &account::create_test_signer_cap(CURSER_2)
            );
        rmn_remote::curse(&curser2, SUBJECT_2);
        assert!(rmn_remote::is_cursed(SUBJECT_2), 3);

        // 5. Remove first curser
        rmn_remote::remove_allowed_cursers(owner, vector[CURSER_1]);
        assert!(!rmn_remote::is_allowed_curser(CURSER_1), 4);

        // 6. Second curser can uncurse both
        rmn_remote::uncurse_multiple(&curser2, vector[SUBJECT_1, SUBJECT_2]);
        assert!(!rmn_remote::is_cursed(SUBJECT_1), 5);
        assert!(!rmn_remote::is_cursed(SUBJECT_2), 6);
    }
}
