#[test_only]
/// Stands in for the registrar's `mcms_entrypoint`, which runs under `derived_supply` dispatch.
/// It sits in its own module because a hook in the test module aborts 4037 on itself.
module regulated_token::mcms_dispatch_hook {
    use std::account;
    use std::object::Object;
    use std::option::{Self, Option};

    use regulated_token::regulated_token;

    const ADMIN: address = @admin;
    const HOLDER: address = @0x1000;
    const RECIPIENT: address = @0x3000;

    const MODE_RECOVER_FROZEN_FUNDS: u8 = 0;
    const MODE_BURN_FROZEN_FUNDS: u8 = 1;
    const MODE_RECOVER_TOKENS: u8 = 2;
    const MODE_RECOVER_FROZEN_STORES: u8 = 3;
    const MODE_BURN_FROZEN_STORES: u8 = 4;
    const MODE_FREEZE_STORES: u8 = 5;

    struct Mode has key {
        mode: u8,
        store: address
    }

    public fun set_mode(admin: &signer, mode: u8, store: address) {
        move_to(admin, Mode { mode, store });
    }

    public fun hook<T: key>(_m: Object<T>): Option<u128> acquires Mode {
        let admin = &account::create_signer_for_test(ADMIN);
        let mode = Mode[ADMIN].mode;
        let store = Mode[ADMIN].store;
        if (mode == MODE_RECOVER_FROZEN_FUNDS) {
            regulated_token::recover_frozen_funds(admin, HOLDER, RECIPIENT);
        } else if (mode == MODE_BURN_FROZEN_FUNDS) {
            regulated_token::burn_frozen_funds(admin, HOLDER);
        } else if (mode == MODE_RECOVER_TOKENS) {
            regulated_token::recover_tokens(admin, RECIPIENT);
        } else if (mode == MODE_RECOVER_FROZEN_STORES) {
            regulated_token::recover_frozen_stores(admin, vector[store], RECIPIENT);
        } else if (mode == MODE_BURN_FROZEN_STORES) {
            regulated_token::burn_frozen_stores(admin, vector[store]);
        } else if (mode == MODE_FREEZE_STORES) {
            regulated_token::freeze_stores(admin, vector[store]);
        } else {
            regulated_token::unfreeze_stores(admin, vector[store]);
        };
        option::none()
    }
}

#[test_only]
/// Runs the token entries under `derived_supply` dispatch, the way MCMS calls them.
/// A direct call never has `dispatchable_fungible_asset` on the stack, so it misses reentrancy.
module regulated_token::mcms_dispatch_test {
    use std::account;
    use std::dispatchable_fungible_asset;
    use std::fungible_asset::{Self, FungibleStore, Metadata};
    use std::function_info;
    use std::object::{Self, Object};
    use std::option;
    use std::primary_fungible_store;
    use std::string;

    use regulated_token::mcms_dispatch_hook;
    use regulated_token::regulated_token;
    use regulated_token::store_test_helpers::{setup, new_nested_store, stage};

    const HOLDER: address = @0x1000;
    const RECIPIENT: address = @0x3000;

    const MINTED: u64 = 1_000_000;
    const STAGED: u64 = 100;

    const MODE_RECOVER_FROZEN_FUNDS: u8 = 0;
    const MODE_BURN_FROZEN_FUNDS: u8 = 1;
    const MODE_RECOVER_TOKENS: u8 = 2;
    const MODE_RECOVER_FROZEN_STORES: u8 = 3;
    const MODE_BURN_FROZEN_STORES: u8 = 4;
    const MODE_FREEZE_STORES: u8 = 5;
    const MODE_UNFREEZE_STORES: u8 = 6;

    /// Calls the hook through `derived_supply` on a second asset, as `mcms::dispatch` does.
    fun dispatch(admin: &signer, mode: u8, store: address) {
        mcms_dispatch_hook::set_mode(admin, mode, store);

        let constructor_ref = object::create_named_object(admin, b"mcms_dispatch");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(),
            string::utf8(b"Dispatch"),
            string::utf8(b"D"),
            0,
            string::utf8(b""),
            string::utf8(b"")
        );
        let hook =
            function_info::new_function_info_from_address(
                @regulated_token,
                string::utf8(b"mcms_dispatch_hook"),
                string::utf8(b"hook")
            );
        dispatchable_fungible_asset::register_derive_supply_dispatch_function(
            &constructor_ref, option::some(hook)
        );

        dispatchable_fungible_asset::derived_supply(
            object::object_from_constructor_ref<Metadata>(&constructor_ref)
        );
    }

    fun new_staged_store(): Object<FungibleStore> {
        let holder = account::create_signer_for_test(HOLDER);
        let (_holding, store) = new_nested_store(HOLDER);
        stage(&holder, store, STAGED);
        store
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_frozen_funds_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::freeze_account(admin, HOLDER);

        dispatch(admin, MODE_RECOVER_FROZEN_FUNDS, @0x0);

        let metadata = regulated_token::token_metadata();
        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == MINTED);
        assert!(primary_fungible_store::balance(HOLDER, metadata) == 0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_funds_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::freeze_account(admin, HOLDER);

        dispatch(admin, MODE_BURN_FROZEN_FUNDS, @0x0);

        assert!(
            primary_fungible_store::balance(HOLDER, regulated_token::token_metadata())
                == 0
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_tokens_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        regulated_token::mint(admin, @regulated_token, 10);

        dispatch(admin, MODE_RECOVER_TOKENS, @0x0);

        assert!(
            primary_fungible_store::balance(
                RECIPIENT, regulated_token::token_metadata()
            ) == 10
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_recover_frozen_stores_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let store = new_staged_store();
        let store_addr = object::object_address(&store);
        regulated_token::freeze_stores(admin, vector[store_addr]);

        dispatch(admin, MODE_RECOVER_FROZEN_STORES, store_addr);

        assert!(
            primary_fungible_store::balance(
                RECIPIENT, regulated_token::token_metadata()
            ) == STAGED
        );
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_burn_frozen_stores_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let store = new_staged_store();
        let store_addr = object::object_address(&store);
        regulated_token::freeze_stores(admin, vector[store_addr]);

        dispatch(admin, MODE_BURN_FROZEN_STORES, store_addr);

        assert!(fungible_asset::balance(store) == 0);
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_freeze_stores_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let store = new_staged_store();

        dispatch(admin, MODE_FREEZE_STORES, object::object_address(&store));

        assert!(fungible_asset::is_frozen(store));
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    fun test_unfreeze_stores_under_dispatch(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);
        let store = new_staged_store();
        let store_addr = object::object_address(&store);
        regulated_token::freeze_stores(admin, vector[store_addr]);

        dispatch(admin, MODE_UNFREEZE_STORES, store_addr);

        assert!(!fungible_asset::is_frozen(store));
    }
}
