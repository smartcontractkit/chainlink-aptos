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
module stablecoin::fungible_asset_tests {
    use std::option::{Self, Option};
    use std::string;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use aptos_framework::object::{Self, ConstructorRef, Object};
    use aptos_framework::primary_fungible_store;
    use stablecoin::stablecoin_utils::stablecoin_obj_seed;

    use aptos_extensions::test_utils::assert_eq;

    const NAME: vector<u8> = b"name";
    const SYMBOL: vector<u8> = b"symbol";
    const DECIMALS: u8 = 6;
    const ICON_URI: vector<u8> = b"icon uri";
    const PROJECT_URI: vector<u8> = b"project uri";

    const DEPOSIT_AMOUNT: u64 = 100;
    const U64_MAX: u64 = (1 << 63) | ((1 << 63) - 1);

    const OWNER_ONE: address = @0x10;
    const OWNER_TWO: address = @0x20;

    const HOLDER_ONE: address = @0x30;
    const HOLDER_TWO: address = @0x40;

    // === Framework Errors ===

    // error::invalid_argument(fungible_asset::EFUNGIBLE_ASSET_AND_STORE_MISMATCH))
    const ERR_INVALID_ARGUMENT_ASSET_STORE_MISMATCH: u64 = 65547; 
    // error::invalid_argument(fungible_asset::ETRANSFER_REF_AND_FUNGIBLE_ASSET_MISMATCH)
    const ERR_INVALID_ARGUMENT_TRANSFER_REF_ASSET_MISMATCH: u64 = 65538;
    // error::invalid_argument(fungible_asset::ETRANSFER_REF_AND_STORE_MISMATCH)
    const ERR_INVALID_ARGUMENT_TRANSFER_REF_STORE_MISMATCH: u64 = 65545;
    /// error::invalid_argument(fungible_asset::EINSUFFICIENT_BALANCE)
    const ERR_INVALID_ARGUMENT_INSUFFICIENT_BALANCE: u64 = 65540; // 1 * 2^16 + 4
    /// error::invalid_argument(fungible_asset::EBURN_REF_AND_FUNGIBLE_ASSET_MISMATCH)
    const ERR_INVALID_ARGUMENT_BURN_REF_AND_FUNGIBLE_ASSET_MISMATCH: u64 = 65549; // 1 * 2^16 + 13
    /// error::permission_denied(ENOT_STORE_OWNER))
    const ERR_PERMISSION_DENIED_NOT_STORE_OWNER: u64 = 327688;
    /// error::permission_denied(ENO_UNGATED_TRANSFERS)
    const ERR_PERMISSION_DENIED_NO_UNGATED_TRANSFERS: u64 = 327683;
    /// error::out_of_range(aggregator_v2::EAGGREGATOR_OVERFLOW)
    const ERR_AGGREGATOR_V2_EAGGREGATOR_OVERFLOW: u64 = 131073; // 2 * 2^16 + 1
    /// error::out_of_range(fungible_asset::EMAX_SUPPLY_EXCEEDED)
    const ERR_FUNGIBLE_ASSET_EMAX_SUPPLY_EXCEEDED: u64 = 131077; // 2 * 2^16 + 5

    // === Tests ===

    #[test]
    fun setup__should_create_fungible_asset_with_metadata() {
        let (_, metadata, fungible_asset_address) = setup_fa(OWNER_ONE);

        // Validate resources were created
        assert_eq(object::object_exists<fungible_asset::ConcurrentSupply>(fungible_asset_address), true);
        assert_eq(object::object_exists<fungible_asset::Metadata>(fungible_asset_address), true);
        assert_eq(object::object_exists<fungible_asset::Untransferable>(fungible_asset_address), true);
        assert_eq(object::object_exists<primary_fungible_store::DeriveRefPod>(fungible_asset_address), true);

        // Validate fungible asset state 
        assert_eq(fungible_asset::name(metadata), string::utf8(NAME));
        assert_eq(fungible_asset::symbol(metadata), string::utf8(SYMBOL));
        assert_eq(fungible_asset::decimals(metadata), DECIMALS);
        assert_eq(fungible_asset::icon_uri(metadata), string::utf8(ICON_URI));
        assert_eq(fungible_asset::project_uri(metadata), string::utf8(PROJECT_URI));
        assert_eq(fungible_asset::supply(metadata), option::some(0));
        assert_eq(fungible_asset::maximum(metadata), option::none());
        assert_eq(fungible_asset::is_untransferable(metadata), true);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_ASSET_STORE_MISMATCH,
        location = aptos_framework::fungible_asset
    )]
    fun deposit__should_fail_for_mismatched_fungible_assets() {
        // Create two distinct fungible assets
        let (_, metadata_one, _) = setup_fa(OWNER_ONE);
        let (constructor_ref_two, _, _) = setup_fa(OWNER_TWO);

        // Create a store for the first one 
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata_one);

        // Mint an amount of the second one
        let deposit_asset = mint(&constructor_ref_two, DEPOSIT_AMOUNT);

        // Try to deposit
        fungible_asset::deposit(store, deposit_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_TRANSFER_REF_ASSET_MISMATCH,
        location = aptos_framework::fungible_asset
    )]
    fun deposit_with_ref__should_fail_if_ref_does_not_match_asset() {
        // Create two distinct fungible assets
        let (constructor_ref_one, metadata_one, _) = setup_fa(OWNER_ONE);
        let (constructor_ref_two, _, _) = setup_fa(OWNER_TWO);

        // Create a store for the first asset 
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata_one);

        // Mint an amount of the first asset
        let deposit_asset = mint(&constructor_ref_one, DEPOSIT_AMOUNT);

        // Generate a TransferRef for the SECOND asset
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref_two);

        // Attempt to use second TransferRef to deposit directly
        // Note that deposit_asset.metadata == store.metadata; sanity-check
        assert_eq(fungible_asset::store_metadata(store), fungible_asset::metadata_from_asset(&deposit_asset));

        // Attempt to transfer
        fungible_asset::deposit_with_ref(&transfer_ref, store, deposit_asset);
    }

    #[test, expected_failure(arithmetic_error, location = aptos_framework::fungible_asset)]
    fun deposit_with_ref__concurrent_fungible_balance_disabled__should_fail_if_store_balance_overflow() {
        // Disable the ConcurrentFungibleBalance feature.
        std::features::change_feature_flags_for_testing(
            &create_signer_for_test(@std),
            vector[], /* enable */
            vector[std::features::get_default_to_concurrent_fungible_balance_feature()], /* disable */
        );

        let (constructor_ref, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store with u64_max balance.
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);
        primary_fungible_store::mint(&fungible_asset::generate_mint_ref(&constructor_ref), HOLDER_ONE, U64_MAX);
        assert_eq(primary_fungible_store::balance(HOLDER_ONE, metadata), U64_MAX);

        // Attempt to deposit another unit of asset to the same store, expect failure.
        let deposit_asset = mint(&constructor_ref, 1);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);
        fungible_asset::deposit_with_ref(&transfer_ref, store, deposit_asset);
    }

    #[test, expected_failure(abort_code = ERR_AGGREGATOR_V2_EAGGREGATOR_OVERFLOW, location = aptos_framework::aggregator_v2)]
    fun deposit_with_ref__concurrent_fungible_balance_enabled__should_fail_if_store_balance_overflow() {
        // Enable the ConcurrentFungibleBalance feature.
        std::features::change_feature_flags_for_testing(
            &create_signer_for_test(@std),
            vector[std::features::get_default_to_concurrent_fungible_balance_feature()], /* enable  */
            vector[], /* disable */
        );

        let (constructor_ref, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store with u64_max balance.
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);
        primary_fungible_store::mint(&fungible_asset::generate_mint_ref(&constructor_ref), HOLDER_ONE, U64_MAX);
        assert_eq(primary_fungible_store::balance(HOLDER_ONE, metadata), U64_MAX);

        // Attempt to deposit another unit of asset to the same store, expect failure.
        let deposit_asset = mint(&constructor_ref, 1);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);
        fungible_asset::deposit_with_ref(&transfer_ref, store, deposit_asset);
    }

    #[test]
    fun withdraw__should_succeed_if_caller_is_indirect_owner() {
        // Create a fungible asset
        let (fa_constructor_ref, metadata, _) = setup_fa(OWNER_ONE);

        // Create an intermediary object that an EOA owns.
        let object_constructor_ref = object::create_object(HOLDER_ONE);
        let object_address = object::address_from_constructor_ref(&object_constructor_ref);

        // Create a store which the object owns.
        let store = primary_fungible_store::create_primary_store(object_address, metadata);

        // Sanity check that the store is empty, is directly owned by the object
        // and is indirectly owned by the EOA.
        assert_eq(fungible_asset::balance(store), 0);
        assert_eq(object::owner(store), object_address);
        assert_eq(object::owns(store, HOLDER_ONE), true);

        // Deposit into the store 
        let deposit_asset = mint(&fa_constructor_ref, DEPOSIT_AMOUNT);
        fungible_asset::deposit(store, deposit_asset);

        // EOA attempts to withdraw any amount, should succeed.
        let withdrawn_asset = fungible_asset::withdraw(&create_signer_for_test(HOLDER_ONE), store, 10);

        // Must redeposit it so it is consumed, even though this won't be reached 
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_INSUFFICIENT_BALANCE,
        location = aptos_framework::fungible_asset
    )]
    fun withdraw__should_fail_if_store_is_empty() {
        // Create a fungible asset
        let (_, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);
        // Sanity check store is empty 
        assert_eq(fungible_asset::balance(store), 0);

        // Withdraw any amount
        let owner = create_signer_for_test(HOLDER_ONE);
        let withdrawn_asset = fungible_asset::withdraw(&owner, store, 10);

        // Must redeposit it so it is consumed, even though this won't be reached 
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_INSUFFICIENT_BALANCE,
        location = aptos_framework::fungible_asset
    )]
    fun withdraw__should_fail_if_amount_exceeds_store_balance() {
        // Create a fungible asset
        let (constructor_ref, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);

        // Deposit into the store 
        let deposit_asset = mint(&constructor_ref, DEPOSIT_AMOUNT);
        fungible_asset::deposit(store, deposit_asset);

        // Withdraw more than deposit amount 
        let owner = create_signer_for_test(HOLDER_ONE);
        let withdrawn_asset = fungible_asset::withdraw(&owner, store, DEPOSIT_AMOUNT + 1);
        
        // Must redeposit it so it is consumed, even though this won't be reached 
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_PERMISSION_DENIED_NOT_STORE_OWNER,
        location = aptos_framework::fungible_asset
    )]
    fun withdraw__should_fail_if_not_owner() {
        // Create a fungible asset
        let (constructor_ref, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);

        // Deposit into the store 
        let deposit_asset = mint(&constructor_ref, DEPOSIT_AMOUNT);
        fungible_asset::deposit(store, deposit_asset);

        // Withdraw as different owner
        let not_owner = create_signer_for_test(HOLDER_TWO);
        let withdrawn_asset = fungible_asset::withdraw(&not_owner, store, 1);
        
        // Must redeposit it so it is consumed, even though this won't be reached 
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_INVALID_ARGUMENT_TRANSFER_REF_STORE_MISMATCH,
        location = aptos_framework::fungible_asset
    )]
    fun withdraw_with_ref__should_fail_if_ref_does_not_match_asset() {
        // Create two distinct fungible assets
        let (constructor_ref_one, metadata_one, _) = setup_fa(OWNER_ONE);
        let (constructor_ref_two, _, _) = setup_fa(OWNER_TWO);

        // Create a store for the first asset, and deposit into it
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata_one);
        let deposit_asset = mint(&constructor_ref_one, DEPOSIT_AMOUNT);
        fungible_asset::deposit(store, deposit_asset);
        
        // Generate a TransferRef for the SECOND asset
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref_two);

        // Attempt to use second TransferRef to withdraw from the store
        let withdrawn_asset = fungible_asset::withdraw_with_ref(&transfer_ref, store, DEPOSIT_AMOUNT);

        // Must redeposit it so it is consumed, even though this won't be reached 
        fungible_asset::deposit(store, withdrawn_asset);
    }

    #[test, expected_failure(
        abort_code = ERR_PERMISSION_DENIED_NO_UNGATED_TRANSFERS,
        location = aptos_framework::object
    )]
    fun transfer_store__fails_if_asset_is_untransferable() {
        // Create a fungible asset
        let (_, metadata, _) = setup_fa(OWNER_ONE);

        // Create a store
        let store = primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);

        // Sanity check it's untransferable 
        assert_eq(object::is_untransferable(store), true);

        // Transfer store
        let owner = create_signer_for_test(HOLDER_ONE);
        object::transfer(&owner, store, HOLDER_TWO);
    }

    #[test, expected_failure(abort_code = ERR_FUNGIBLE_ASSET_EMAX_SUPPLY_EXCEEDED, location = aptos_framework::fungible_asset)]
    fun mint__should_fail_if_exceed_max_total_supply() {
        let max_supply: u128 = ((U64_MAX as u128) + 100_000);
        let (constructor_ref, metadata, _) = setup_fa_with_max_supply(OWNER_ONE, option::some(max_supply));

        // Set total supply to u64_max.
        primary_fungible_store::create_primary_store(HOLDER_ONE, metadata);
        primary_fungible_store::mint(&fungible_asset::generate_mint_ref(&constructor_ref), HOLDER_ONE, U64_MAX);
        assert_eq(option::extract(&mut fungible_asset::supply(metadata)), (U64_MAX as u128));
        
        // Attempt to mint more units of asset than the max supply allows for, expect failure.
        let asset = fungible_asset::mint(&fungible_asset::generate_mint_ref(&constructor_ref), 100_001);

        // Must redeposit it so it is consumed, even though this won't be reached 
        destroy_fungible_asset(&constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = ERR_INVALID_ARGUMENT_BURN_REF_AND_FUNGIBLE_ASSET_MISMATCH, location = aptos_framework::fungible_asset)]
    fun burn__should_fail_if_burn_ref_metadata_does_not_match_fa_metadata() {
        // Create a fungible asset
        let (constructor_ref_1, _, _) = setup_fa(OWNER_ONE);
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref_1);
        let fa = fungible_asset::mint(&mint_ref, 100);

        // Create BurnRef of a different fungible asset
        let (constructor_ref_2, _, _) = setup_fa(OWNER_TWO);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref_2);

        fungible_asset::burn(&burn_ref, fa);
    }

    // === Helpers ===

    public fun setup_fa(owner: address): (ConstructorRef, Object<Metadata>, address) {
        setup_fa_with_max_supply(owner, option::none())
    }

    fun setup_fa_with_max_supply(owner: address, max_supply: Option<u128>): (ConstructorRef, Object<Metadata>, address) {
        let constructor_ref = object::create_named_object(&create_signer_for_test(owner), stablecoin_obj_seed());
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            max_supply,
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON_URI),
            string::utf8(PROJECT_URI),
        );

        fungible_asset::set_untransferable(&constructor_ref);

        let fungible_asset_address = object::address_from_constructor_ref(&constructor_ref);
        let metadata = object::address_to_object<Metadata>(fungible_asset_address);

        (constructor_ref, metadata, fungible_asset_address)
    }

    public fun mint(
        constructor_ref: &ConstructorRef,
        amount: u64
    ): FungibleAsset {
        let mint_ref = fungible_asset::generate_mint_ref(constructor_ref);
        fungible_asset::mint(&mint_ref, amount)
    }

    fun destroy_fungible_asset(constructor_ref: &ConstructorRef, asset: FungibleAsset) {
        let burn_ref = fungible_asset::generate_burn_ref(constructor_ref);
        fungible_asset::burn(&burn_ref, asset);
    }
}
