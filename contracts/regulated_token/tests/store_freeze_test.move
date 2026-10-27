#[test_only]
module regulated_token::store_freeze_test {
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
    #[expected_failure(abort_code = 0x50003, location = std::fungible_asset)]
    // permission_denied(ESTORE_IS_FROZEN)
    /// A frozen nested store rejects withdrawals before the dispatch hook runs.
    fun test_freeze_stores_blocks_withdraw(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);

        drain_to_outside(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x50003, location = std::fungible_asset)]
    // permission_denied(ESTORE_IS_FROZEN)
    /// A frozen nested store rejects deposits too.
    fun test_freeze_stores_blocks_deposit(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);

        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);

        stage(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 0x50003, location = std::fungible_asset)]
    // permission_denied(ESTORE_IS_FROZEN)
    /// The flag lives on the store: handing the parent object to a clean account changes nothing.
    fun test_frozen_store_survives_parent_transfer(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let outside = account::create_signer_for_test(OUTSIDE);
        let (holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);
        object::transfer(&holder, holding, OUTSIDE);
        assert!(object::root_owner(store) == OUTSIDE);

        drain_to_outside(&outside, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Freeze then unfreeze: the view flips and the store moves funds again.
    fun test_unfreeze_stores_restores_store(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let metadata = regulated_token::token_metadata();
        let (_, store) = new_nested_store(HOLDER);
        let store_addr = object::object_address(&store);
        stage(&holder, store, STAGED);

        assert!(!regulated_token::is_store_frozen(store_addr));
        regulated_token::freeze_stores(admin, vector[store_addr]);
        assert!(regulated_token::is_store_frozen(store_addr));
        assert!(!regulated_token::is_frozen(HOLDER));

        regulated_token::unfreeze_stores(admin, vector[store_addr]);
        assert!(!regulated_token::is_store_frozen(store_addr));

        drain_to_outside(&holder, store, STAGED);
        assert!(primary_fungible_store::balance(OUTSIDE, metadata) == STAGED);
        assert!(fungible_asset::balance(store) == 0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ACCOUNT_FROZEN,
            location = regulated_token::regulated_token
        )
    ]
    /// An account freeze reaches a nested store through the root owner check in the hook.
    fun test_account_freeze_blocks_nested_store(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_account(admin, HOLDER);
        assert!(!regulated_token::is_store_frozen(object::object_address(&store)));

        drain_to_outside(&holder, store, STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Burns the frozen store in full, leaves the unfrozen one alone, and lowers supply.
    fun test_burn_frozen_stores_burns_only_frozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let metadata = regulated_token::token_metadata();
        let (_, frozen) = new_nested_store(HOLDER);
        let (_, open) = new_nested_store(HOLDER);
        stage(&holder, frozen, STAGED);
        stage(&holder, open, MINTED - STAGED);
        let supply_before = fungible_asset::supply(metadata);

        regulated_token::freeze_stores(admin, vector[object::object_address(&frozen)]);
        regulated_token::burn_frozen_stores(
            admin,
            vector[object::object_address(&frozen), object::object_address(&open)]
        );

        assert!(fungible_asset::balance(frozen) == 0);
        assert!(
            fungible_asset::balance(open) == MINTED - STAGED
        );
        assert!(
            fungible_asset::supply(metadata)
                == option::some(*supply_before.borrow() - (STAGED as u128))
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// Moves the frozen store's full balance to the recipient's primary store.
    fun test_recover_frozen_stores_moves_balance(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let metadata = regulated_token::token_metadata();
        let (_, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);
        regulated_token::recover_frozen_stores(
            admin, vector[object::object_address(&store)], RECIPIENT
        );

        assert!(fungible_asset::balance(store) == 0);
        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == STAGED);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_STORE_MUST_BE_FROZEN_FOR_RECOVERY,
            location = regulated_token::regulated_token
        )
    ]
    /// Recovery refuses a store that is not frozen.
    fun test_recover_frozen_stores_requires_frozen(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);

        regulated_token::recover_frozen_stores(
            admin, vector[object::object_address(&store)], RECIPIENT
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    /// Only the freezer role can freeze stores.
    fun test_freeze_stores_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);

        regulated_token::freeze_stores(&holder, vector[object::object_address(&store)]);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::access_control::E_MISSING_ROLE,
            location = regulated_token::access_control
        )
    ]
    /// Only the unfreezer role can unfreeze stores.
    fun test_unfreeze_stores_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);
        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);

        regulated_token::unfreeze_stores(
            &holder, vector[object::object_address(&store)]
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_ONLY_BURNER_OR_BRIDGE,
            location = regulated_token::regulated_token
        )
    ]
    /// Only a burner can burn frozen stores.
    fun test_burn_frozen_stores_unauthorized(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let holder = account::create_signer_for_test(HOLDER);
        let (_, store) = new_nested_store(HOLDER);
        regulated_token::freeze_stores(admin, vector[object::object_address(&store)]);

        regulated_token::burn_frozen_stores(
            &holder, vector[object::object_address(&store)]
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    /// `freeze_stores` on a primary store works like a plain flag freeze.
    fun test_freeze_stores_on_primary_store(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let metadata = regulated_token::token_metadata();
        let primary = primary_fungible_store::primary_store(HOLDER, metadata);
        let primary_addr = object::object_address(&primary);

        regulated_token::freeze_stores(admin, vector[primary_addr]);
        assert!(regulated_token::is_store_frozen(primary_addr));
        assert!(primary_fungible_store::is_frozen(HOLDER, metadata));
        assert!(!regulated_token::is_frozen(HOLDER));

        regulated_token::unfreeze_stores(admin, vector[primary_addr]);
        assert!(!primary_fungible_store::is_frozen(HOLDER, metadata));
    }
}
