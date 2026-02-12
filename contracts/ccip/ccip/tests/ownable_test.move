#[test_only]
module ccip::ownable_test {
    use std::signer;
    use std::object::{Self, Object, ObjectCore};
    use std::account;
    use std::option;
    use std::event;

    use ccip::ownable::{
        Self,
        OwnershipTransferRequested,
        OwnershipTransferAccepted,
        OwnershipTransferred
    };

    const OWNER_ADDRESS: address = @0x123;
    const NEW_OWNER_ADDRESS: address = @0x456;

    fun setup(): (
        signer, signer, Object<ObjectCore>, ownable::OwnableState
    ) {
        let owner = account::create_account_for_test(OWNER_ADDRESS);
        let new_owner = account::create_account_for_test(NEW_OWNER_ADDRESS);

        let constructor_ref = &object::create_named_object(&owner, b"TestObject");
        let test_object =
            object::object_from_constructor_ref<ObjectCore>(constructor_ref);
        let object_address = object::object_address(&test_object);

        let ownable_state = ownable::new(&owner, object_address);

        (
            owner, new_owner, test_object, ownable_state
        )
    }

    #[test]
    fun test_initialization() {
        let (
            owner, _new_owner, _test_object, ownable_state
        ) = setup();

        let initial_owner = ownable::owner(&ownable_state);
        assert!(initial_owner == signer::address_of(&owner));

        ownable::destroy(ownable_state);
    }

    #[test]
    fun test_transfer_ownership_request() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();

        ownable::transfer_ownership(
            &owner, &mut ownable_state, signer::address_of(&new_owner)
        );

        let current_owner = ownable::owner(&ownable_state);
        assert!(current_owner == signer::address_of(&owner));

        let pending_transfer_from = ownable::pending_transfer_from(&ownable_state);
        let pending_transfer_to = ownable::pending_transfer_to(&ownable_state);
        let pending_transfer_accepted =
            ownable::pending_transfer_accepted(&ownable_state);
        assert!(pending_transfer_from == option::some(signer::address_of(&owner)));
        assert!(pending_transfer_to == option::some(signer::address_of(&new_owner)));
        assert!(pending_transfer_accepted == option::some(false));

        assert!(
            event::emitted_events_by_handle<OwnershipTransferRequested>(
                ownable::get_ownership_transfer_requested_events(&ownable_state)
            ).length() == 1
        );

        ownable::destroy(ownable_state);
    }

    #[test]
    fun test_accept_ownership() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();

        ownable::transfer_ownership(
            &owner, &mut ownable_state, signer::address_of(&new_owner)
        );

        ownable::accept_ownership(&new_owner, &mut ownable_state);

        let current_owner = ownable::owner(&ownable_state);
        assert!(current_owner == signer::address_of(&owner));

        let pending_transfer_from = ownable::pending_transfer_from(&ownable_state);
        let pending_transfer_to = ownable::pending_transfer_to(&ownable_state);
        let pending_transfer_accepted =
            ownable::pending_transfer_accepted(&ownable_state);
        assert!(pending_transfer_from == option::some(signer::address_of(&owner)));
        assert!(pending_transfer_to == option::some(signer::address_of(&new_owner)));
        assert!(pending_transfer_accepted == option::some(true));

        assert!(
            event::emitted_events_by_handle<OwnershipTransferAccepted>(
                ownable::get_ownership_transfer_accepted_events(&ownable_state)
            ).length() == 1
        );

        ownable::destroy(ownable_state);
    }

    #[test]
    fun test_complete_ownership_transfer() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();
        let new_owner_addr = signer::address_of(&new_owner);

        ownable::transfer_ownership(&owner, &mut ownable_state, new_owner_addr);
        ownable::accept_ownership(&new_owner, &mut ownable_state);
        ownable::execute_ownership_transfer(&owner, &mut ownable_state, new_owner_addr);

        let updated_owner = ownable::owner(&ownable_state);
        assert!(updated_owner == new_owner_addr);

        let pending_transfer_from = ownable::pending_transfer_from(&ownable_state);
        let pending_transfer_to = ownable::pending_transfer_to(&ownable_state);
        let pending_transfer_accepted =
            ownable::pending_transfer_accepted(&ownable_state);
        assert!(pending_transfer_from == option::none());
        assert!(pending_transfer_to == option::none());
        assert!(pending_transfer_accepted == option::none());

        assert!(
            event::emitted_events_by_handle<OwnershipTransferred>(
                ownable::get_ownership_transferred_events(&ownable_state)
            ).length() == 1
        );

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    // E_ONLY_CALLABLE_BY_OWNER
    fun test_only_owner_can_transfer() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();

        ownable::transfer_ownership(
            &new_owner, &mut ownable_state, signer::address_of(&owner)
        );

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = ccip::ownable)]
    // E_CANNOT_TRANSFER_TO_SELF
    fun test_cannot_transfer_to_self() {
        let (
            owner, _new_owner, _test_object, ownable_state
        ) = setup();

        ownable::transfer_ownership(
            &owner, &mut ownable_state, signer::address_of(&owner)
        );

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 327681, location = ccip::ownable)]
    // E_MUST_BE_PROPOSED_OWNER
    fun test_only_proposed_can_accept() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();

        let different_owner = @0x789;
        ownable::transfer_ownership(&owner, &mut ownable_state, different_owner);

        ownable::accept_ownership(&new_owner, &mut ownable_state);

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 327686, location = ccip::ownable)]
    // E_NO_PENDING_TRANSFER
    fun test_accept_without_pending_transfer() {
        let (
            _owner, new_owner, _test_object, ownable_state
        ) = setup();

        ownable::accept_ownership(&new_owner, &mut ownable_state);

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 196615, location = ccip::ownable)]
    // E_TRANSFER_NOT_ACCEPTED
    fun test_execute_without_accept() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();
        let new_owner_addr = signer::address_of(&new_owner);

        ownable::transfer_ownership(&owner, &mut ownable_state, new_owner_addr);

        ownable::execute_ownership_transfer(&owner, &mut ownable_state, new_owner_addr);

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 327684, location = ccip::ownable)]
    // E_PROPOSED_OWNER_MISMATCH
    fun test_execute_with_wrong_address() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();
        let new_owner_addr = signer::address_of(&new_owner);

        ownable::transfer_ownership(&owner, &mut ownable_state, new_owner_addr);
        ownable::accept_ownership(&new_owner, &mut ownable_state);
        ownable::execute_ownership_transfer(&owner, &mut ownable_state, @0x789); // Wrong address

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 196616, location = ccip::ownable)]
    // E_TRANSFER_ALREADY_ACCEPTED
    fun test_accept_twice() {
        let (
            owner, new_owner, _test_object, ownable_state
        ) = setup();

        ownable::transfer_ownership(
            &owner, &mut ownable_state, signer::address_of(&new_owner)
        );

        ownable::accept_ownership(&new_owner, &mut ownable_state);

        ownable::accept_ownership(&new_owner, &mut ownable_state);

        ownable::destroy(ownable_state);
    }

    #[test]
    #[expected_failure(abort_code = 327685, location = ccip::ownable)]
    // E_OWNER_CHANGED
    fun test_owner_changed_directly() {
        let (
            owner, new_owner, test_object, ownable_state
        ) = setup();
        let direct_recipient = account::create_account_for_test(@0x789);

        let proposed_owner = signer::address_of(&new_owner);
        ownable::transfer_ownership(&owner, &mut ownable_state, proposed_owner);

        // Change owner directly with object::transfer
        object::transfer(&owner, test_object, signer::address_of(&direct_recipient));

        // Try to accept the ownership - should fail since owner changed directly
        ownable::accept_ownership(&new_owner, &mut ownable_state);

        ownable::destroy(ownable_state);
    }
}
