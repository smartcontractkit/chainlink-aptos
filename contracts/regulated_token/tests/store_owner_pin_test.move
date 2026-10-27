#[test_only]
module regulated_token::store_owner_pin_test {
    use std::account;
    use std::dispatchable_fungible_asset;
    use std::fungible_asset::{Self, FungibleStore};
    use std::object::{Self, Object, ObjectCore};
    use std::option;
    use std::primary_fungible_store;
    use std::string;

    use regulated_token::regulated_token;

    const ADMIN: address = @admin;
    const HOLDER: address = @0x1000;
    const OUTSIDE: address = @0x2000;
    const RECIPIENT: address = @0x3000;

    const MINTED: u64 = 1_000_000;
    const STAGED: u64 = 600_000;

    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const RECOVERY_ROLE: u8 = 7;

    fun setup(admin: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );
        regulated_token::init_module_for_testing(regulated_token);
        regulated_token::initialize(
            admin,
            option::none(),
            string::utf8(b"Regulated Token"),
            string::utf8(b"RT"),
            6,
            string::utf8(
                b"https://regulatedtoken.com/images/pic.png"
            ),
            string::utf8(b"https://regulatedtoken.com")
        );
        regulated_token::grant_role(admin, FREEZER_ROLE, ADMIN);
        regulated_token::grant_role(admin, UNFREEZER_ROLE, ADMIN);
        regulated_token::grant_role(admin, MINTER_ROLE, ADMIN);
        regulated_token::grant_role(admin, BURNER_ROLE, ADMIN);
        regulated_token::grant_role(admin, RECOVERY_ROLE, ADMIN);
        account::create_account_for_test(HOLDER);
        account::create_account_for_test(OUTSIDE);
        account::create_account_for_test(RECIPIENT);
        regulated_token::mint(admin, HOLDER, MINTED);
    }

    /// root -> holding object -> store, the shape of a vault or position object a user owns.
    fun new_nested_store(root: address): (Object<ObjectCore>, Object<FungibleStore>) {
        let holding_ref = object::create_object(root);
        let holding = object::object_from_constructor_ref<ObjectCore>(&holding_ref);
        let store_ref =
            object::create_object(object::address_from_constructor_ref(&holding_ref));
        let store =
            fungible_asset::create_store(&store_ref, regulated_token::token_metadata());
        (holding, store)
    }

    fun stage(holder: &signer, store: Object<FungibleStore>, amount: u64) {
        let fa =
            primary_fungible_store::withdraw(
                holder, regulated_token::token_metadata(), amount
            );
        dispatchable_fungible_asset::deposit(store, fa);
    }

    fun drain_to_outside(
        signer_: &signer, store: Object<FungibleStore>, amount: u64
    ) {
        let fa = dispatchable_fungible_asset::withdraw(signer_, store, amount);
        primary_fungible_store::deposit(OUTSIDE, fa);
    }

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
    /// An unpinned funded store is drained by store freeze plus recovery, and the
    /// recovered funds stay spendable at the destination.
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
}
