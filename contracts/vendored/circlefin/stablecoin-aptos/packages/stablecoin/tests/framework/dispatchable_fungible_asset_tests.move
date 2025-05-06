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
module stablecoin::dispatchable_fungible_asset_tests {
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::fungible_asset;
    use aptos_framework::primary_fungible_store;

    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::dispatchable_fungible_asset_test_utils::{
        Self,
        setup_dfa,
        setup_dfa_with_failing_deposit,
        setup_dfa_with_failing_withdraw
    };

    const DEPOSIT_AMOUNT: u64 = 100;

    const OWNER: address = @0x10;
    const RANDOM_ADDRESS: address = @0x20;

    // === Framework Errors ===

    /// error::invalid_argument(fungible_asset::EINVALID_DISPATCHABLE_OPERATIONS)
    const ERR_INVALID_ARGUMENT_INVALID_DISPATCHABLE_OPERATIONS: u64 = 65564; // 1 * 2^16 + 28

    // === Tests ===

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_INVALID_DISPATCHABLE_OPERATIONS,
        location = aptos_framework::fungible_asset
    )]
    fun deposit__should_fail_if_bypassing_dispatchable_function() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Create asset to deposit
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);

        // Try to deposit outside of dispatchable_fungible_asset::deposit
        fungible_asset::deposit(store, minted_asset);
    }

    #[test, expected_failure(
        abort_code = dispatchable_fungible_asset_test_utils::ENO_DEPOSIT
    )]
    fun deposit__should_fail_if_dispatchable_function_fails() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa_with_failing_deposit(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Create asset to deposit
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);

        // Invoke dispatchable deposit
        dispatchable_fungible_asset::deposit(store, minted_asset);
    }

    #[test]
    fun deposit__should_succeed_if_dispatchable_function_succeeds() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Create asset to deposit
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);

        // Invoke dispatchable deposit
        assert_eq(fungible_asset::balance(store), 0);
        dispatchable_fungible_asset::deposit(store, minted_asset);
        assert_eq(fungible_asset::balance(store), DEPOSIT_AMOUNT);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_INVALID_DISPATCHABLE_OPERATIONS,
        location = aptos_framework::fungible_asset
    )]
    fun withdraw__should_fail_if_bypassing_dispatchable_function() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Deposit an asset first
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);
        dispatchable_fungible_asset::deposit(store, minted_asset);
        assert_eq(fungible_asset::balance(store), DEPOSIT_AMOUNT);

        // Try to withdraw outside of dispatchable_fungible_asset::withdraw
        let withdrawn_asset = fungible_asset::withdraw(
            &create_signer_for_test(RANDOM_ADDRESS),
            store,
            DEPOSIT_AMOUNT
        );

        // Redeposit, even though this won't be reached
        dispatchable_fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = dispatchable_fungible_asset_test_utils::ENO_WITHDRAW
    )]
    fun withdraw__should_fail_if_dispatchable_function_fails() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa_with_failing_withdraw(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Deposit an asset first
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);
        dispatchable_fungible_asset::deposit(store, minted_asset);
        assert_eq(fungible_asset::balance(store), DEPOSIT_AMOUNT);

        // Invoke dispatchable withdraw
        let withdrawn_asset = dispatchable_fungible_asset::withdraw(
            &create_signer_for_test(RANDOM_ADDRESS),
            store,
            DEPOSIT_AMOUNT
        );

        // Redeposit, even though this won't be reached 
        dispatchable_fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test]
    fun withdraw__should_succeed_if_dispatchable_function_succeeds() {
        // Create DFA
        let (constructor_ref, metadata) = setup_dfa(OWNER);

        // Create a store
        let store = primary_fungible_store::create_primary_store(RANDOM_ADDRESS, metadata);

        // Deposit an asset first
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let minted_asset = fungible_asset::mint(&mint_ref, DEPOSIT_AMOUNT);
        dispatchable_fungible_asset::deposit(store, minted_asset);
        assert_eq(fungible_asset::balance(store), DEPOSIT_AMOUNT);

        // Invoke dispatchable withdraw
        assert_eq(fungible_asset::balance(store), DEPOSIT_AMOUNT);
        let withdrawn_asset = dispatchable_fungible_asset::withdraw(
            &create_signer_for_test(RANDOM_ADDRESS),
            store,
            DEPOSIT_AMOUNT
        );
        assert_eq(fungible_asset::balance(store), 0);

        // Redeposit
        dispatchable_fungible_asset::deposit(store, withdrawn_asset);
    }
}
