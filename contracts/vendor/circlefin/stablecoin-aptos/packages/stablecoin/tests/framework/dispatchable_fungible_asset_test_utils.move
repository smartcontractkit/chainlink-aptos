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
module stablecoin::dispatchable_fungible_asset_test_utils {
    use std::option;
    use std::string;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info::{Self, FunctionInfo};
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata, TransferRef};
    use aptos_framework::object::{Self, ConstructorRef, Object};
    use aptos_framework::primary_fungible_store;

    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::fungible_asset_tests::{Self, setup_fa};

    const NAME: vector<u8> = b"name";
    const SYMBOL: vector<u8> = b"symbol";
    const DECIMALS: u8 = 6;
    const ICON_URI: vector<u8> = b"icon uri";
    const PROJECT_URI: vector<u8> = b"project uri";

    const RANDOM_ADDRESS: address = @0x10;

    // === Errors ===

    const ENO_DEPOSIT: u64 = 0;
    const ENO_WITHDRAW: u64 = 1;

    // === Tests ===

    #[test]
    fun setup_with_failing_deposit__should_succeed_and_register_failing_deposit_function() {
        let (_, metadata) = setup_dfa_with_failing_deposit(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::deposit_dispatch_function(store),
            option::some(create_function_info(b"failing_deposit"))
        );
    }

    #[test]
    fun setup_with_failing_deposit__should_succeed_and_register_succeeding_withdraw_function() {
        let (_, metadata) = setup_dfa_with_failing_deposit(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::withdraw_dispatch_function(store),
            option::some(create_function_info(b"succeeding_withdraw"))
        );
    }

    #[test]
    fun setup_with_failing_withdraw__should_succeed_and_register_succeeding_deposit_function() {
        let (_, metadata) = setup_dfa_with_failing_withdraw(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::deposit_dispatch_function(store),
            option::some(create_function_info(b"succeeding_deposit"))
        );
    }

    #[test]
    fun setup_with_failing_withdraw__should_succeed_and_register_failing_withdraw_function() {
        let (_, metadata) = setup_dfa_with_failing_withdraw(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::withdraw_dispatch_function(store),
            option::some(create_function_info(b"failing_withdraw"))
        );
    }

    #[test]
    fun setup__should_succeed_and_register_succeeding_deposit_function() {
        let (_, metadata) = setup_dfa(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::deposit_dispatch_function(store),
            option::some(create_function_info(b"succeeding_deposit"))
        );
    }

    #[test]
    fun setup__should_succeed_and_register_succeeding_withdraw_function() {
        let (_, metadata) = setup_dfa(RANDOM_ADDRESS);

        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);
        assert_eq(
            fungible_asset::withdraw_dispatch_function(store),
            option::some(create_function_info(b"succeeding_withdraw"))
        );
    }

    #[test, expected_failure(
        abort_code = ENO_DEPOSIT
    )]
    fun failing_deposit__should_fail() {
        // Setup a Fungible Asset
        let (constructor_ref, metadata, _) = setup_fa(RANDOM_ADDRESS);
        
        // Get transfer ref 
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Deposit should fail
        failing_deposit(
            primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata),
            fungible_asset::zero(metadata),
            &transfer_ref
        );
    }

    #[test]
    fun succeeding_deposit__should_succeed() {
        // Setup a Fungible Asset
        let (constructor_ref, metadata, _) = setup_fa(RANDOM_ADDRESS);
        
        // Get transfer ref 
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Create a store 
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Deposit should succeed
        let deposit_amount: u64 = 100;
        succeeding_deposit(
            store,
            fungible_asset_tests::mint(&constructor_ref, deposit_amount),
            &transfer_ref
        );
        assert_eq(fungible_asset::balance(store), deposit_amount);
    }

    #[test, expected_failure(
        abort_code = ENO_WITHDRAW
    )]
    fun failing_withdraw__should_fail() {
        // Setup a Fungible Asset
        let (constructor_ref, metadata, _) = setup_fa(RANDOM_ADDRESS);
        
        // Get transfer ref 
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Create a store 
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Withdraw should fail
        let withdrawn_asset = failing_withdraw(
            store,
            1,
            &transfer_ref
        );
        
        // Redeposit asset; this will never be reached
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test]
    fun succeeding_withdraw__should_succeed() {
        // Setup a Fungible Asset
        let (constructor_ref, metadata, _) = setup_fa(RANDOM_ADDRESS);
        
        // Get transfer ref 
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);

        // Create a store 
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Deposit into it
        fungible_asset::deposit(store, fungible_asset_tests::mint(&constructor_ref, 100));
        
        // Withdraw should succeed
        let withdrawn_asset = succeeding_withdraw(
            store,
            1,
            &transfer_ref
        );
        assert_eq(fungible_asset::balance(store), 99);
        
        // Redeposit asset
        fungible_asset::deposit(store, withdrawn_asset);
    }

    // === Helpers ===

    public fun failing_deposit<T: key>(
        _store: Object<T>,
        _fa: FungibleAsset,
        _transfer_ref: &TransferRef
    ) {
        abort ENO_DEPOSIT
    }

    public fun succeeding_deposit<T: key>(
        store: Object<T>,
        fa: FungibleAsset,
        transfer_ref: &TransferRef
    ) {
        fungible_asset::deposit_with_ref(transfer_ref, store, fa);
    }

    public fun failing_withdraw<T: key>(
        _store: Object<T>,
        _amount: u64,
        _transfer_ref: &TransferRef,
    ): FungibleAsset {
        abort ENO_WITHDRAW
    }

    public fun succeeding_withdraw<T: key>(
        store: Object<T>,
        amount: u64,
        transfer_ref: &TransferRef,
    ): FungibleAsset {
        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    public fun setup_dfa_with_failing_deposit(owner: address): (ConstructorRef, Object<Metadata>) {
        create_dfa(owner, true, false)
    }

    public fun setup_dfa_with_failing_withdraw(owner: address): (ConstructorRef, Object<Metadata>) {
        create_dfa(owner, false, true)
    }

    public fun setup_dfa(owner: address): (ConstructorRef, Object<Metadata>) {
        create_dfa(owner, false, false)
    }

    fun create_dfa(
        owner: address,
        fail_deposit: bool,
        fail_withdraw: bool
    ): (ConstructorRef, Object<Metadata>) {
        let constructor_ref = object::create_sticky_object(owner);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(),
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI),
        );

        let fungible_asset_address = object::address_from_constructor_ref(&constructor_ref);
        let metadata = object::address_to_object<Metadata>(fungible_asset_address);

        let deposit_function: FunctionInfo;
        if (fail_deposit) {
            deposit_function = create_function_info(b"failing_deposit");
        } else {
            deposit_function = create_function_info(b"succeeding_deposit")
        };

        let withdraw_function: FunctionInfo;
        if (fail_withdraw) {
            withdraw_function = create_function_info(b"failing_withdraw");
        } else {
            withdraw_function = create_function_info(b"succeeding_withdraw");
        };
        
        dispatchable_fungible_asset::register_dispatch_functions(
            &constructor_ref,
            option::some(withdraw_function),
            option::some(deposit_function),
            option::none(),
        );

        (constructor_ref, metadata)
    }

    fun create_function_info(selector: vector<u8>): FunctionInfo {
        function_info::new_function_info(
            &create_signer_for_test(@stablecoin),
            string::utf8(b"dispatchable_fungible_asset_test_utils"),
            string::utf8(selector)
        )
    }
}
