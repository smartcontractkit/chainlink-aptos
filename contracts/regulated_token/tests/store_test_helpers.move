#[test_only]
/// Setup and store helpers shared by `store_freeze_test` and `store_owner_pin_test`.
module regulated_token::store_test_helpers {
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

    const FREEZER_ROLE: u8 = 2;
    const UNFREEZER_ROLE: u8 = 3;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const RECOVERY_ROLE: u8 = 7;

    /// Grants every store role to ADMIN, creates HOLDER, OUTSIDE and RECIPIENT, and mints MINTED to HOLDER.
    public fun setup(admin: &signer, regulated_token: &signer) {
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
    public fun new_nested_store(root: address): (Object<ObjectCore>, Object<FungibleStore>) {
        let holding_ref = object::create_object(root);
        let holding = object::object_from_constructor_ref<ObjectCore>(&holding_ref);
        let store_ref =
            object::create_object(object::address_from_constructor_ref(&holding_ref));
        let store =
            fungible_asset::create_store(&store_ref, regulated_token::token_metadata());
        (holding, store)
    }

    public fun stage(
        holder: &signer, store: Object<FungibleStore>, amount: u64
    ) {
        let fa =
            primary_fungible_store::withdraw(
                holder, regulated_token::token_metadata(), amount
            );
        dispatchable_fungible_asset::deposit(store, fa);
    }

    public fun drain_to_outside(
        signer_: &signer, store: Object<FungibleStore>, amount: u64
    ) {
        let fa = dispatchable_fungible_asset::withdraw(signer_, store, amount);
        primary_fungible_store::deposit(OUTSIDE, fa);
    }
}
