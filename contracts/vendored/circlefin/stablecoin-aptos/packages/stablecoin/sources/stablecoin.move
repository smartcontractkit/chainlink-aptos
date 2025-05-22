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

/// This module defines core stablecoin logic, including stablecoin resource creation,
/// initialization, and dispatchable deposit and withdraw functions.
module stablecoin::stablecoin {
    use std::event;
    use std::option;
    use std::string::{Self, String, utf8};
    use std::vector;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, TransferRef};
    use aptos_framework::object::{Self, ExtendRef, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::resource_account;

    use aptos_extensions::manageable;
    use aptos_extensions::ownable;
    use aptos_extensions::pausable;
    use aptos_extensions::upgradable;
    use stablecoin::blocklistable;
    use stablecoin::metadata;
    use stablecoin::stablecoin_utils;
    use stablecoin::treasury;

    // === Errors ===

    /// Input metadata does not match stablecoin metadata.
    const ESTABLECOIN_METADATA_MISMATCH: u64 = 1;
    /// The stablecoin version has been initialized previously.
    const ESTABLECOIN_VERSION_INITIALIZED: u64 = 2;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct StablecoinState has key {
        /// The capability to update the stablecoin object's storage.
        extend_ref: ExtendRef,
        /// The stablecoin's initialized version.
        initialized_version: u8
    }

    // === Events ===

    #[event]
    struct Deposit has drop, store {
        store_owner: address,
        store: address,
        amount: u64
    }

    #[event]
    struct Withdraw has drop, store {
        store_owner: address,
        store: address,
        amount: u64
    }

    #[event]
    /// Emitted when a stablecoin version is initialized.
    struct StablecoinInitialized has drop, store {
        initialized_version: u8
    }

    // === View functions ===

    #[view]
    public fun stablecoin_address(): address {
        stablecoin_utils::stablecoin_address()
    }

    // === Write functions ===

    /// Creates the stablecoin fungible asset, resources and roles.
    fun init_module(resource_acct_signer: &signer) {
        // Create the stablecoin's object container.
        let stablecoin_obj_constructor_ref =
            &object::create_named_object(resource_acct_signer, stablecoin_utils::stablecoin_obj_seed());

        // Create the fungible asset primary store resources with default values.
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            stablecoin_obj_constructor_ref,
            option::none() /* maximum supply */,
            utf8(vector::empty()),
            utf8(vector::empty()),
            0,
            utf8(vector::empty()),
            utf8(vector::empty())
        );

        // Ensure that stores derived from the stablecoin are untransferable.
        fungible_asset::set_untransferable(stablecoin_obj_constructor_ref);

        // Create the StablecoinState resource.
        let stablecoin_obj_signer = &object::generate_signer(stablecoin_obj_constructor_ref);
        move_to(
            stablecoin_obj_signer,
            StablecoinState {
                extend_ref: object::generate_extend_ref(stablecoin_obj_constructor_ref),
                initialized_version: 0
            }
        );

        // Initialize the stablecoin's roles with default addresses.
        ownable::new(stablecoin_obj_signer, @deployer);
        pausable::new(stablecoin_obj_signer, @deployer);
        blocklistable::new(stablecoin_obj_constructor_ref, @deployer);
        metadata::new(stablecoin_obj_constructor_ref, @deployer);
        treasury::new(stablecoin_obj_constructor_ref, @deployer);

        // Retrieve the resource account signer capability and initialize the managable::AdminRole and upgradable::SignerCapStore resources.
        let signer_cap = resource_account::retrieve_resource_account_cap(resource_acct_signer, @deployer);
        manageable::new(resource_acct_signer, @deployer);
        upgradable::new(resource_acct_signer, signer_cap);

        // Create and register the custom deposit and withdraw dispatchable functions.
        let withdraw_function =
            function_info::new_function_info(
                resource_acct_signer,
                string::utf8(b"stablecoin"),
                string::utf8(b"override_withdraw")
            );
        let deposit_function =
            function_info::new_function_info(
                resource_acct_signer,
                string::utf8(b"stablecoin"),
                string::utf8(b"override_deposit")
            );
        dispatchable_fungible_asset::register_dispatch_functions(
            stablecoin_obj_constructor_ref,
            option::some(withdraw_function),
            option::some(deposit_function),
            option::none() /* omit override for derived_balance */
        );
    }

    /// Initializes the stablecoin's metadata.
    entry fun initialize_v1(
        caller: &signer,
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    ) acquires StablecoinState {
        manageable::assert_is_admin(caller, @stablecoin);
        let stablecoin_address = stablecoin_utils::stablecoin_address();
        let stablecoin_state = borrow_global_mut<StablecoinState>(stablecoin_address);
        assert!(stablecoin_state.initialized_version == 0, ESTABLECOIN_VERSION_INITIALIZED);

        stablecoin_state.initialized_version = 1;

        metadata::mutate_asset_metadata(
            option::some(name),
            option::some(symbol),
            option::some(decimals),
            option::some(icon_uri),
            option::some(project_uri)
        );

        event::emit(StablecoinInitialized { initialized_version: 1 });
    }

    /// Dispatchable deposit implementation
    public fun override_deposit<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) {
        let stablecoin_address = stablecoin_utils::stablecoin_address();
        assert!(
            object::object_address(&fungible_asset::store_metadata(store)) == stablecoin_address,
            ESTABLECOIN_METADATA_MISMATCH
        );

        let store_owner = object::owner(store);
        let amount = fungible_asset::amount(&fa);

        pausable::assert_not_paused(stablecoin_address);
        blocklistable::assert_not_blocklisted(store_owner);
        fungible_asset::deposit_with_ref(transfer_ref, store, fa);

        event::emit(Deposit { store_owner, store: object::object_address(&store), amount })
    }

    /// Dispatchable withdraw implementation
    public fun override_withdraw<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        let stablecoin_address = stablecoin_utils::stablecoin_address();
        assert!(
            object::object_address(&fungible_asset::store_metadata(store)) == stablecoin_address,
            ESTABLECOIN_METADATA_MISMATCH
        );

        let store_owner = object::owner(store);

        pausable::assert_not_paused(stablecoin_address);
        blocklistable::assert_not_blocklisted(store_owner);
        let asset = fungible_asset::withdraw_with_ref(transfer_ref, store, amount);

        event::emit(Withdraw { store_owner, store: object::object_address(&store), amount });

        asset
    }

    // === Test Only ===

    #[test_only]
    public fun test_init_module(resource_acct_signer: &signer) {
        init_module(resource_acct_signer);
    }

    #[test_only]
    public fun test_initialize_v1(
        caller: &signer,
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    ) acquires StablecoinState {
        initialize_v1(caller, name, symbol, decimals, icon_uri, project_uri);
    }

    #[test_only]
    public fun initialized_version_for_testing(): u8 acquires StablecoinState {
        borrow_global<StablecoinState>(stablecoin_utils::stablecoin_address()).initialized_version
    }

    #[test_only]
    public fun set_initialized_version_for_testing(initialized_version: u8) acquires StablecoinState {
        borrow_global_mut<StablecoinState>(stablecoin_utils::stablecoin_address()).initialized_version = initialized_version;
    }

    #[test_only]
    public fun extend_ref_address_for_testing(): address acquires StablecoinState {
        object::address_from_extend_ref(
            &borrow_global<StablecoinState>(stablecoin_utils::stablecoin_address()).extend_ref
        )
    }

    #[test_only]
    public fun test_Deposit_event(store_owner: address, store: address, amount: u64): Deposit {
        Deposit { store_owner, store, amount }
    }

    #[test_only]
    public fun test_Withdraw_event(store_owner: address, store: address, amount: u64): Withdraw {
        Withdraw { store_owner, store, amount }
    }

    #[test_only]
    public fun test_StablecoinInitialized_event(initialized_version: u8): StablecoinInitialized {
        StablecoinInitialized { initialized_version }
    }
}
