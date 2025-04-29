// Copyright 2024 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[test_only]
module stablecoin::stablecoin_tests {
    use std::event;
    use std::option;
    use std::string::{Self, String, utf8};
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info::new_function_info;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, FungibleStore, Metadata};
    use aptos_framework::object::{Self, ConstructorRef, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::resource_account;

    use aptos_extensions::manageable;
    use aptos_extensions::ownable::{Self, OwnerRole};
    use aptos_extensions::pausable::{Self, PauseState};
    use aptos_extensions::test_utils::assert_eq;
    use aptos_extensions::upgradable;
    use stablecoin::blocklistable::{Self, test_blocklist};
    use stablecoin::metadata;
    use stablecoin::stablecoin;
    use stablecoin::stablecoin::test_StablecoinInitialized_event;
    use stablecoin::stablecoin_utils;
    use stablecoin::treasury;

    const RANDOM_ADDRESS: address = @0x10;

    const NAME: vector<u8> = b"name";
    const SYMBOL: vector<u8> = b"symbol";
    const DECIMALS: u8 = 6;
    const ICON_URI: vector<u8> = b"icon uri";
    const PROJECT_URI: vector<u8> = b"project uri";
    const TEST_SEED: vector<u8> = b"test_seed";

    /// error::not_found(object::EOBJECT_DOES_NOT_EXIST)
    const ERR_OBJ_OBJECT_DOES_NOT_EXIST: u64 = 393218; // 6 * 2^16 + 2

    #[test]
    fun init_module__should_create_stablecoin_correctly() {
        test_init_module();
    }

    #[test]
    fun initialize_v1__should_succeed() {
        test_init_module();

        test_initialize_v1(
            &create_signer_for_test(@deployer),
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI)
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_ADMIN)]
    fun initialize_v1__should_fail_if_caller_not_admin() {
        test_init_module();

        test_initialize_v1(
            &create_signer_for_test(RANDOM_ADDRESS),
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI)
        );
    }

    #[test, expected_failure(abort_code = stablecoin::stablecoin::ESTABLECOIN_VERSION_INITIALIZED)]
    fun initialize_v1__should_fail_if_already_initialized() {
        test_init_module();

        stablecoin::set_initialized_version_for_testing(1);

        test_initialize_v1(
            &create_signer_for_test(@deployer),
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI)
        );
    }

    #[test]
    fun stablecoin_address__should_return_stablecoin_address() {
        setup();

        assert_eq(stablecoin::stablecoin_address(), stablecoin_utils::stablecoin_address());
    }

    #[test]
    fun deposit__should_succeed_and_pass_all_assertions() {
        let stablecoin_metadata = setup();
        let owner = create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(&owner, stablecoin_metadata);

        test_deposit(fungible_store, 100);
    }

    #[test]
    fun deposit__should_succeed_and_pass_all_assertions_for_zero_amount() {
        let stablecoin_metadata = setup();
        let owner = create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(&owner, stablecoin_metadata);

        test_deposit(fungible_store, 0);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun deposit__should_fail_when_paused() {
        let stablecoin_metadata = setup();
        let owner = create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(&owner, stablecoin_metadata);

        pausable::set_paused_for_testing(stablecoin_utils::stablecoin_address(), true);

        test_deposit(fungible_store, 100);
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::EBLOCKLISTED)]
    fun deposit__should_fail_if_store_owner_is_blocklisted() {
        let stablecoin_metadata = setup();
        let owner = create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(&owner, stablecoin_metadata);
        let blocklister =
            create_signer_for_test(blocklistable::blocklister());

        test_blocklist(&blocklister, RANDOM_ADDRESS);

        test_deposit(fungible_store, 100);
    }

    #[test, expected_failure(abort_code = ERR_OBJ_OBJECT_DOES_NOT_EXIST, location = aptos_framework::object)]
    fun deposit__should_fail_if_store_does_not_have_owner() {
        let stablecoin_metadata = setup();
        let secondary_store_constructor_ref = object::create_object(RANDOM_ADDRESS);
        let secondary_store_addr =
            object::address_from_constructor_ref(&secondary_store_constructor_ref);
        let secondary_store_delete_ref = object::generate_delete_ref(&secondary_store_constructor_ref);
        let fungible_store =
            fungible_asset::create_store(&secondary_store_constructor_ref, stablecoin_metadata);

        object::delete(secondary_store_delete_ref);
        assert_eq(object::is_object(secondary_store_addr), false);

        test_deposit(fungible_store, 100);
    }

    #[test, expected_failure(abort_code = stablecoin::stablecoin::ESTABLECOIN_METADATA_MISMATCH)]
    fun deposit__should_fail_if_depositing_other_assets() {
        setup();
        // create alternative fungible asset
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let (mint_ref, transfer_ref, _, _, metadata) = fungible_asset::create_fungible_asset(owner);
        let store = fungible_asset::create_test_store(owner, metadata);
        let fa = fungible_asset::mint(&mint_ref, 100);

        stablecoin::override_deposit(store, fa, &transfer_ref);
    }

    #[test]
    fun withdraw__should_succeed_and_pass_all_assertions() {
        let stablecoin_metadata = setup();
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(owner, stablecoin_metadata);

        // Deposit first
        test_deposit(fungible_store, 100);

        // Withdraw
        test_withdraw(
            owner,
            fungible_store,
            50,
        )
    }

    #[test]
    fun withdraw__should_succeed_and_pass_all_assertions_when_called_by_indirect_owner() {
        let stablecoin_metadata = setup();
        let indirect_owner = &create_signer_for_test(RANDOM_ADDRESS);
        let owner = &object::generate_signer(&object::create_object(RANDOM_ADDRESS));
        let fungible_store = fungible_asset::create_test_store(owner, stablecoin_metadata);

        // Deposit first
        test_deposit(fungible_store, 100);

        // Withdraw
        test_withdraw(
            indirect_owner,
            fungible_store,
            50,
        )
    }

    #[test]
    fun withdraw__should_succeed_and_pass_all_assertions_for_zero_amount() {
        let stablecoin_metadata = setup();
        let owner = &create_signer_for_test(RANDOM_ADDRESS);

        test_withdraw(
            owner,
            fungible_asset::create_test_store(owner, stablecoin_metadata),
            0,
        )
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun withdraw__should_fail_when_paused() {
        let stablecoin_metadata = setup();
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(owner, stablecoin_metadata);

        // Deposit first
        test_deposit(fungible_store, 100);

        // Pause
        pausable::set_paused_for_testing(stablecoin_utils::stablecoin_address(), true);

        // Withdraw
        test_withdraw(
            owner,
            fungible_store,
            100,
        )
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::EBLOCKLISTED)]
    fun withdraw__should_fail_if_store_owner_is_blocklisted() {
        let stablecoin_metadata = setup();
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let fungible_store = fungible_asset::create_test_store(owner, stablecoin_metadata);
        let blocklister =
            create_signer_for_test(blocklistable::blocklister());

        test_blocklist(&blocklister, RANDOM_ADDRESS);

        test_withdraw(
            owner,
            fungible_store,
            100,
        )
    }

    #[test, expected_failure(abort_code = ERR_OBJ_OBJECT_DOES_NOT_EXIST, location = aptos_framework::object)]
    fun withdraw__should_fail_if_store_does_not_have_owner() {
        let stablecoin_metadata = setup();
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let secondary_store_constructor_ref = object::create_object(RANDOM_ADDRESS);
        let secondary_store_addr =
            object::address_from_constructor_ref(&secondary_store_constructor_ref);
        let secondary_store_delete_ref = object::generate_delete_ref(&secondary_store_constructor_ref);
        let fungible_store =
            fungible_asset::create_store(&secondary_store_constructor_ref, stablecoin_metadata);

        object::delete(secondary_store_delete_ref);
        assert_eq(object::is_object(secondary_store_addr), false);

        test_withdraw(
            owner,
            fungible_store,
            100,
        )
    }

    #[test, expected_failure(abort_code = stablecoin::stablecoin::ESTABLECOIN_METADATA_MISMATCH)]
    fun withdraw__should_fail_if_withdrawing_other_assets() {
        setup();
        // create alternative fungible asset
        let owner = &create_signer_for_test(RANDOM_ADDRESS);
        let (mint_ref, transfer_ref, burn_ref, _, metadata) = fungible_asset::create_fungible_asset(owner);
        let store = fungible_asset::create_test_store(owner, metadata);
        let amount = 100;
        fungible_asset::mint_to(&mint_ref, store, amount);

        let fa = stablecoin::override_withdraw(store, amount, &transfer_ref);

        fungible_asset::burn(&burn_ref, fa);
    }

    // === Helpers ===

    public fun setup(): (Object<Metadata>) {
        test_init_module();

        let stablecoin_metadata = test_initialize_v1(
            &create_signer_for_test(@deployer),
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI)
        );

        stablecoin_metadata
    }

    fun test_init_module() {
        let resource_acct_signer = deploy_package();

        stablecoin::test_init_module(&resource_acct_signer);

        validate_stablecoin_object_state(stablecoin_utils::stablecoin_address(),
            utf8(vector[]),
            utf8(vector[]),
            0,
            utf8(vector[]),
            utf8(vector[]),
            @deployer,
            @deployer,
            @deployer,
            @deployer,
            @deployer,
            @deployer
        );
    }

    fun test_initialize_v1(
        caller: &signer,
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    ): Object<Metadata> {
        stablecoin::test_initialize_v1(
            caller,
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );

        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_utils::stablecoin_address());

        // verify the fungible asset metadata is updated correctly
        assert_eq(fungible_asset::name(stablecoin_metadata), name);
        assert_eq(fungible_asset::symbol(stablecoin_metadata), symbol);
        assert_eq(fungible_asset::decimals(stablecoin_metadata), decimals);
        assert_eq(fungible_asset::icon_uri(stablecoin_metadata), icon_uri);
        assert_eq(fungible_asset::project_uri(stablecoin_metadata), project_uri);

        // verify the initialized state is updated correctly
        assert_eq(stablecoin::initialized_version_for_testing(), 1);

        // verify the StablecoinInitialized event is emitted
        let stablecoin_initialized_event = test_StablecoinInitialized_event(1);
        assert_eq(event::was_event_emitted(&stablecoin_initialized_event), true);

        stablecoin_metadata
    }

    public fun validate_stablecoin_object_state(
        stablecoin_address: address,
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String,
        admin: address,
        owner: address,
        pauser: address,
        blocklister: address,
        master_minter: address,
        metadata_updater: address
    ) {
        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_address);

        // Ensure that all the expected resources exists.
        assert_eq(object::object_exists<fungible_asset::ConcurrentSupply>(stablecoin_address), true);
        assert_eq(object::object_exists<fungible_asset::DispatchFunctionStore>(stablecoin_address), true);
        assert_eq(object::object_exists<fungible_asset::Metadata>(stablecoin_address), true);
        assert_eq(object::object_exists<fungible_asset::Untransferable>(stablecoin_address), true);
        assert_eq(object::object_exists<dispatchable_fungible_asset::TransferRefStore>(stablecoin_address), true);
        assert_eq(object::object_exists<primary_fungible_store::DeriveRefPod>(stablecoin_address), true);
        assert_eq(object::object_exists<blocklistable::BlocklistState>(stablecoin_address), true);
        assert_eq(object::object_exists<metadata::MetadataState>(stablecoin_address), true);
        assert_eq(object::object_exists<ownable::OwnerRole>(stablecoin_address), true);
        assert_eq(object::object_exists<pausable::PauseState>(stablecoin_address), true);
        assert_eq(object::object_exists<stablecoin::StablecoinState>(stablecoin_address), true);
        assert_eq(object::object_exists<treasury::TreasuryState>(stablecoin_address), true);
        assert_eq(manageable::admin_role_exists_for_testing(@stablecoin), true);
        assert_eq(upgradable::signer_cap_store_exists_for_testing(@stablecoin), true);

        // Ensure that the fungible asset has been configured correctly.
        assert_eq(fungible_asset::name(stablecoin_metadata), name);
        assert_eq(fungible_asset::symbol(stablecoin_metadata), symbol);
        assert_eq(fungible_asset::decimals(stablecoin_metadata), decimals);
        assert_eq(fungible_asset::icon_uri(stablecoin_metadata), icon_uri);
        assert_eq(fungible_asset::project_uri(stablecoin_metadata), project_uri);
        assert_eq(fungible_asset::supply(stablecoin_metadata), option::some(0));
        assert_eq(fungible_asset::maximum(stablecoin_metadata), option::none());
        assert_eq(fungible_asset::is_untransferable(stablecoin_metadata), true);

        // Ensure that stablecoin state is correct
        assert_eq(stablecoin::initialized_version_for_testing(), 0);
        assert_eq(stablecoin::extend_ref_address_for_testing(), stablecoin_address);
        assert_eq(treasury::mint_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(treasury::burn_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(treasury::master_minter(), master_minter);
        assert_eq(treasury::num_controllers_for_testing(), 0);
        assert_eq(treasury::num_mint_allowances_for_testing(), 0);
        assert_eq(blocklistable::transfer_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(blocklistable::num_blocklisted_for_testing(), 0);
        assert_eq(blocklistable::blocklister(), blocklister);
        assert_eq(metadata::mutate_metadata_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(metadata::metadata_updater(), metadata_updater);

        // Ensure the upgradable signer capability is setup correctly
        let capability = &upgradable::extract_signer_cap_for_testing(@stablecoin);
        assert_eq(account::get_signer_capability_address(capability), @stablecoin);

        // Ensure the stablecoin admin, owner and pauser are setup correctly
        let owner_role = object::address_to_object<OwnerRole>(stablecoin_address);
        let pausable_state = object::address_to_object<PauseState>(stablecoin_address);
        assert_eq(manageable::admin(@stablecoin), admin);
        assert_eq(manageable::pending_admin(@stablecoin), option::none());
        assert_eq(ownable::owner(owner_role), owner);
        assert_eq(ownable::pending_owner(owner_role), option::none());
        assert_eq(pausable::pauser(pausable_state), pauser);
        assert_eq(pausable::is_paused(pausable_state), false);

        // Ensure that the dispatchable functions have been correctly registered.
        let withdraw_function_info =
            new_function_info(
                &create_signer_for_test(@stablecoin),
                string::utf8(b"stablecoin"),
                string::utf8(b"override_withdraw"),
            );
        let deposit_function_info =
            new_function_info(
                &create_signer_for_test(@stablecoin),
                string::utf8(b"stablecoin"),
                string::utf8(b"override_deposit"),
            );

        let store = fungible_asset::create_test_store(&create_signer_for_test(RANDOM_ADDRESS), stablecoin_metadata);
        assert_eq(
            fungible_asset::deposit_dispatch_function(store),
            option::some(deposit_function_info),
        );
        assert_eq(
            fungible_asset::withdraw_dispatch_function(store),
            option::some(withdraw_function_info),
        );
    }

    fun test_deposit(
        fungible_store: Object<FungibleStore>,
        amount: u64
    ) {
        let minted_asset = treasury::test_mint(amount);
        dispatchable_fungible_asset::deposit(fungible_store, minted_asset);

        // Event emission
        let store_owner = object::owner(fungible_store);
        let store_address = object::object_address(&fungible_store);
        let expected_event = stablecoin::test_Deposit_event(
            store_owner,
            store_address,
            amount
        );
        assert_eq(event::was_event_emitted(&expected_event), true);

        // Balance check
        assert_eq(fungible_asset::balance(fungible_store), amount);
    }

    fun test_withdraw(
        owner: &signer,
        fungible_store: Object<FungibleStore>,
        amount: u64
    ) {
        let balance_before = fungible_asset::balance(fungible_store);
        let withdrawn_asset =
            dispatchable_fungible_asset::withdraw(owner, fungible_store, amount);

        // Event emission
        let store_owner = object::owner(fungible_store);
        let store_address = object::object_address(&fungible_store);
        let expected_event = stablecoin::test_Withdraw_event(
            store_owner,
            store_address,
            amount
        );
        assert_eq(event::was_event_emitted(&expected_event), true);

        // Balance check
        assert_eq(balance_before - amount, fungible_asset::balance(fungible_store));
        assert_eq(fungible_asset::amount(&withdrawn_asset), amount);

        // Clean up the assets
        treasury::test_burn(withdrawn_asset);
    }

    fun destroy_fungible_asset(constructor_ref: &ConstructorRef, asset: FungibleAsset) {
        let burn_ref = fungible_asset::generate_burn_ref(constructor_ref);
        fungible_asset::burn(&burn_ref, asset);
    }

    fun deploy_package(): signer {
        account::create_account_for_test(@deployer);

        // deploy an empty package to a new resource account
        resource_account::create_resource_account_and_publish_package(
            &create_signer_for_test(@deployer),
            TEST_SEED,
            x"04746573740100000000000000000000000000", // empty BCS serialized PackageMetadata
            vector::empty()
        );

        // compute the resource account address
        let resource_account_address = account::create_resource_address(&@deployer, TEST_SEED);

        // verify the resource account address is the same as the configured test package address
        assert_eq(@stablecoin, resource_account_address);

        // return a resource account signer
        let resource_account_signer = create_signer_for_test(resource_account_address);
        resource_account_signer
    }
}
