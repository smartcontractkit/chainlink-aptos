#[test_only]
module regulated_token::store_owner_pin_test {
    use std::account;
    use std::dispatchable_fungible_asset;
    use std::event;
    use std::fungible_asset;
    use std::object::{Self, ObjectCore};
    use std::primary_fungible_store;

    use regulated_token::regulated_token;
    use regulated_token::store_test_helpers::{
        setup,
        new_nested_store,
        stage,
        drain_to_outside
    };

    // The accounts and amounts `store_test_helpers::setup` uses.
    const HOLDER: address = @0x1000;
    const OUTSIDE: address = @0x2000;
    const RECIPIENT: address = @0x3000;

    const MINTED: u64 = 1_000_000;
    const STAGED: u64 = 600_000;

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// A nested store works end to end while its ownership is unchanged.
    fun test_nested_store_roundtrip(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let metadata = regulated_token::token_metadata();
        let (_holding, store) = new_nested_store(HOLDER);

        stage(&holder, store, STAGED);
        stage(&holder, store, 100);
        drain_to_outside(&holder, store, STAGED + 100);

        assert!(fungible_asset::balance(store) == 0);
        assert!(
            primary_fungible_store::balance(OUTSIDE, metadata) == STAGED + 100
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// After the holding object moves to a new account, the store's funds stay put.
    fun test_withdraw_aborts_after_store_reparenting(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        object::transfer(&holder, holding, OUTSIDE);
        assert!(object::root_owner(store) == OUTSIDE);

        drain_to_outside(&outside, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// A funded store whose root owner changed rejects further deposits too.
    fun test_deposit_aborts_after_store_reparenting(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let metadata = regulated_token::token_metadata();
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        primary_fungible_store::transfer(&holder, metadata, OUTSIDE, 1000);

        object::transfer(&holder, holding, OUTSIDE);

        stage(&outside, store, 1000);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// Deleting the holding object does not release a funded store either.
    fun test_deposit_aborts_after_parent_object_deleted(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let holding_ref = object::create_object(HOLDER);
        let delete_ref = object::generate_delete_ref(&holding_ref);
        let store_ref =
            object::create_object(object::address_from_constructor_ref(&holding_ref));
        let store =
            fungible_asset::create_store(&store_ref, regulated_token::token_metadata());
        stage(&holder, store, STAGED);
        primary_fungible_store::transfer(
            &holder,
            regulated_token::token_metadata(),
            OUTSIDE,
            1000
        );

        object::delete(delete_ref);

        stage(&outside, store, 1000);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// An emptied store follows its new root owner on the next credit.
    fun test_empty_store_rebinds_after_reparenting(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let metadata = regulated_token::token_metadata();
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        drain_to_outside(&holder, store, STAGED);
        assert!(fungible_asset::balance(store) == 0);

        object::transfer(&holder, holding, OUTSIDE);

        stage(&outside, store, STAGED);
        drain_to_outside(&outside, store, STAGED);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// A pin write emits one module event naming the store and its root owner, a credit that
    /// keeps the pin emits none, and a rebind names the new root owner.
    fun test_pin_emits_module_event(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let (holding, store) = new_nested_store(HOLDER);
        let store_addr = object::object_address(&store);
        assert!(
            event::emitted_events<regulated_token::StoreOwnershipPinned>().length()
                == 0
        );

        stage(&holder, store, STAGED);
        assert!(
            event::emitted_events<regulated_token::StoreOwnershipPinned>()
                == vector[
                    regulated_token::store_ownership_pinned_event(store_addr, HOLDER)
                ]
        );

        stage(&holder, store, 100);
        assert!(
            event::emitted_events<regulated_token::StoreOwnershipPinned>().length()
                == 1
        );

        drain_to_outside(&holder, store, STAGED + 100);
        object::transfer(&holder, holding, OUTSIDE);
        stage(&outside, store, 100);
        assert!(
            event::emitted_events<regulated_token::StoreOwnershipPinned>()
                == vector[
                    regulated_token::store_ownership_pinned_event(store_addr, HOLDER),
                    regulated_token::store_ownership_pinned_event(store_addr, OUTSIDE)
                ]
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// One unit is a balance: a reparented store holding it rejects deposits.
    fun test_one_unit_store_rejects_deposit_after_reparenting(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let metadata = regulated_token::token_metadata();
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, 1);
        primary_fungible_store::transfer(&holder, metadata, OUTSIDE, 1);

        object::transfer(&holder, holding, OUTSIDE);

        stage(&outside, store, 1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// One unit is a balance: a reparented store holding it rejects withdrawals.
    fun test_one_unit_store_rejects_withdraw_after_reparenting(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, 1);

        object::transfer(&holder, holding, OUTSIDE);

        drain_to_outside(&outside, store, 1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// Known cost: anyone can pin an empty object store by sending it 1 unit, and after the
    /// holding object changes hands the new owner's deposit aborts until store recovery.
    fun test_one_unit_deposit_pins_empty_store_before_handoff(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let recipient = account::create_signer_for_test(RECIPIENT);
        let metadata = regulated_token::token_metadata();
        let (holding, store) = new_nested_store(HOLDER);
        primary_fungible_store::transfer(&holder, metadata, OUTSIDE, 1);
        primary_fungible_store::transfer(&holder, metadata, RECIPIENT, 100);

        stage(&outside, store, 1);
        object::transfer(&holder, holding, RECIPIENT);

        stage(&recipient, store, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// `recover_frozen_funds` pins an object destination's empty store, so the object spends
    /// the recovered funds right away.
    fun test_recover_frozen_funds_to_object_is_spendable(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let metadata = regulated_token::token_metadata();
        let dest_ref = object::create_object(RECIPIENT);
        let dest_addr = object::address_from_constructor_ref(&dest_ref);
        let dest_extend_ref = object::generate_extend_ref(&dest_ref);
        regulated_token::freeze_account(admin, HOLDER);

        regulated_token::recover_frozen_funds(admin, HOLDER, dest_addr);
        assert!(primary_fungible_store::balance(dest_addr, metadata) == MINTED);

        let dest = object::generate_signer_for_extending(&dest_extend_ref);
        primary_fungible_store::transfer(&dest, metadata, OUTSIDE, MINTED);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == MINTED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Minted balances are pinned at mint time and stay spendable.
    fun test_minted_balance_is_spendable(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let recipient = account::create_signer_for_test(RECIPIENT);
        let metadata = regulated_token::token_metadata();

        regulated_token::mint(admin, RECIPIENT, 100);
        regulated_token::mint(admin, RECIPIENT, 50);
        primary_fungible_store::transfer(&recipient, metadata, OUTSIDE, 150);

        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == 0);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == 150);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    /// Minting to a frozen root owner still aborts.
    fun test_mint_to_frozen_account_aborts(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::freeze_account(admin, HOLDER);
        regulated_token::mint(admin, HOLDER, 1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30012, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_NOT_PINNED)
    /// A store funded before pins existed (simulated) rejects ordinary withdrawal.
    fun test_unpinned_funded_store_rejects_withdraw(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::remove_store_pin_for_testing(object::object_address(&store));

        drain_to_outside(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30012, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_NOT_PINNED)
    /// A store funded before pins existed must not acquire a pin from a later deposit.
    fun test_unpinned_funded_store_rejects_deposit(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::remove_store_pin_for_testing(object::object_address(&store));

        stage(&holder, store, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Store freeze plus recovery drains an unpinned funded store; the funds stay spendable.
    fun test_unpinned_store_recovery_works(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let recipient = account::create_signer_for_test(RECIPIENT);
        let metadata = regulated_token::token_metadata();
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        regulated_token::remove_store_pin_for_testing(object::object_address(&store));

        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);
        regulated_token::recover_frozen_stores(
            admin, vector[object::object_address(&store)], RECIPIENT
        );

        assert!(fungible_asset::balance(store) == 0);
        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == STAGED);

        primary_fungible_store::transfer(&recipient, metadata, OUTSIDE, STAGED);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Recovered funds land pinned, so the recipient spends them right away.
    fun test_recovered_tokens_are_spendable(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let recipient = account::create_signer_for_test(RECIPIENT);
        let metadata = regulated_token::token_metadata();

        // Tokens stuck at the contract address.
        regulated_token::mint(admin, @regulated_token, 500);

        regulated_token::recover_tokens(admin, RECIPIENT);
        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == 500);

        // Spendable immediately, and the store keeps accepting credits.
        primary_fungible_store::transfer(&recipient, metadata, OUTSIDE, 500);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == 500);
        regulated_token::mint(admin, RECIPIENT, 1);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// Recovery refuses a destination whose store no longer matches its pin.
    fun test_recovery_aborts_when_destination_reparented(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);

        // Destination is the primary store of an object; fund it so it pins, then
        // hand the object to a different account.
        let dest_ref = object::create_object(HOLDER);
        let dest_addr = object::address_from_constructor_ref(&dest_ref);
        regulated_token::mint(admin, dest_addr, 100);
        let dest = object::object_from_constructor_ref<ObjectCore>(&dest_ref);
        object::transfer(&holder, dest, OUTSIDE);

        regulated_token::recover_frozen_stores(
            admin, vector[object::object_address(&store)], dest_addr
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Withdrawing nothing from a store that was never credited works: no balance, no pin needed.
    fun test_empty_store_zero_withdraw_needs_no_pin(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);

        let fa = dispatchable_fungible_asset::withdraw(&holder, store, 0);
        dispatchable_fungible_asset::deposit(store, fa);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    /// Freezing the holding object blocks withdrawal from its store, as before the root check.
    fun test_withdraw_aborts_when_parent_object_frozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_account(admin, object::object_address(&holding));

        drain_to_outside(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    /// Freezing the holding object blocks deposits into its store too.
    fun test_deposit_aborts_when_parent_object_frozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_account(admin, object::object_address(&holding));

        stage(&holder, store, 100);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// After an in-place upgrade no pins exist, yet an account's funded primary store still
    /// sends and receives: its owner can never change, so it needs no pin.
    fun test_unpinned_primary_store_sends_and_receives_after_upgrade(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let metadata = regulated_token::token_metadata();
        regulated_token::remove_store_owner_pins_for_testing();

        primary_fungible_store::transfer(&holder, metadata, OUTSIDE, 100);
        primary_fungible_store::transfer(&outside, metadata, HOLDER, 40);
        regulated_token::mint(admin, HOLDER, 1);

        assert!(
            primary_fungible_store::balance(HOLDER, metadata) == MINTED - 59
        );
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == 60);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Minting into an account's funded primary store works with no pins at all.
    fun test_unpinned_primary_store_accepts_mint_after_upgrade(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::remove_store_owner_pins_for_testing();

        regulated_token::mint(admin, HOLDER, 1);

        assert!(
            primary_fungible_store::balance(HOLDER, regulated_token::token_metadata())
                == MINTED + 1
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30012, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_NOT_PINNED)
    /// A funded nested store stays locked after an in-place upgrade: its owner can change.
    fun test_unpinned_nested_store_rejects_withdraw_after_upgrade(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        regulated_token::remove_store_owner_pins_for_testing();

        drain_to_outside(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x30011, location = regulated_token::regulated_token)]
    // invalid_state(E_STORE_OWNERSHIP_CHANGED)
    /// A frozen account cannot delete its object to free the object's pinned primary store.
    fun test_deleted_object_primary_store_keeps_pin(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holding_ref = object::create_object(HOLDER);
        let holding_addr = object::address_from_constructor_ref(&holding_ref);
        let extend_ref = object::generate_extend_ref(&holding_ref);
        let delete_ref = object::generate_delete_ref(&holding_ref);
        regulated_token::mint(admin, holding_addr, 500);
        regulated_token::freeze_account(admin, HOLDER);

        object::delete(delete_ref);

        let holding = object::generate_signer_for_extending(&extend_ref);
        primary_fungible_store::transfer(
            &holding,
            regulated_token::token_metadata(),
            OUTSIDE,
            500
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x50003, location = aptos_framework::fungible_asset)]
    // permission_denied(ESTORE_IS_FROZEN)
    /// An object's funded primary store with no pin, frozen after the upgrade as the README asks,
    /// stays locked when its frozen owner deletes the object.
    fun test_unpinned_deleted_object_primary_store_stays_frozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holding_ref = object::create_object(HOLDER);
        let holding_addr = object::address_from_constructor_ref(&holding_ref);
        let extend_ref = object::generate_extend_ref(&holding_ref);
        let delete_ref = object::generate_delete_ref(&holding_ref);
        regulated_token::mint(admin, holding_addr, 500);
        regulated_token::remove_store_owner_pins_for_testing();
        let store =
            primary_fungible_store::primary_store(
                holding_addr, regulated_token::token_metadata()
            );
        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);
        regulated_token::freeze_account(admin, HOLDER);

        object::delete(delete_ref);

        let holding = object::generate_signer_for_extending(&extend_ref);
        primary_fungible_store::transfer(
            &holding,
            regulated_token::token_metadata(),
            OUTSIDE,
            500
        );
    }
}
