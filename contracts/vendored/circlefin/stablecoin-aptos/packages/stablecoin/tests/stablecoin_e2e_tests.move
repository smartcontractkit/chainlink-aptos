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
module stablecoin::stablecoin_e2e_tests {
    use std::event;
    use std::vector;
    use std::option;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use aptos_framework::transaction_context::generate_auid_address;

    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::stablecoin;
    use stablecoin::stablecoin_tests::setup;
    use stablecoin::treasury;

    /// Address definition must match ones in `stablecoin_tests.move`.
    const MASTER_MINTER: address = @0x50;
    const CONTROLLER: address = @0x60;
    const MINTER: address = @0x70;
    const RANDOM_ADDRESS: address = @0x80;

    #[test]
    fun mint_and_deposit__should_succeed() {
        let stablecoin_metadata = setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);

        // Set up controller and minter.
        treasury::test_configure_controller(&create_signer_for_test(MASTER_MINTER), CONTROLLER, MINTER);
        treasury::test_configure_minter(&create_signer_for_test(CONTROLLER), 1_000_000);

        // Set up store for recipient.
        let store = fungible_asset::create_store(
            &object::create_object(RANDOM_ADDRESS),
            stablecoin_metadata
        );

        // Mint a FungibleAsset and deposit it.
        {
            let asset = treasury::mint(&create_signer_for_test(MINTER), 1_000_000);
            dispatchable_fungible_asset::deposit(store, asset);

            assert_eq(fungible_asset::supply(stablecoin_metadata), option::some((1_000_000 as u128)));
            assert_eq(fungible_asset::balance(store), 1_000_000);

            let mint_event = treasury::test_Mint_event(MINTER, 1_000_000);
            let deposit_event = stablecoin::test_Deposit_event(
                RANDOM_ADDRESS, /* store owner */
                object::object_address(&store),
                1_000_000
            );
            assert_eq(event::was_event_emitted(&mint_event), true);
            assert_eq(event::was_event_emitted(&deposit_event), true);
        };
    }

    #[test]
    fun batch_mint_and_deposit__should_succeed() {
        let stablecoin_metadata = setup();

        // Set up test scenario.
        let mint_allowance = 6_000_000;
        let recipients = vector::empty<address>();
        let mint_amounts = vector::empty<u64>();

        vector::push_back(&mut recipients, generate_auid_address());
        vector::push_back(&mut mint_amounts, 1_000_000);

        vector::push_back(&mut recipients, generate_auid_address());
        vector::push_back(&mut mint_amounts, 2_000_000);

        vector::push_back(&mut recipients, generate_auid_address());
        vector::push_back(&mut mint_amounts, 3_000_000);

        // Set up controller and minter.
        treasury::set_master_minter_for_testing(MASTER_MINTER);
        treasury::test_configure_controller(&create_signer_for_test(MASTER_MINTER), CONTROLLER, MINTER);
        treasury::test_configure_minter(
            &create_signer_for_test(CONTROLLER),
            mint_allowance
        );

        // Mint a large amount of FungibleAsset.
        let minted_asset = treasury::mint(
            &create_signer_for_test(MINTER),
            mint_allowance
        );
        let expected_mint_events = vector::singleton(treasury::test_Mint_event(MINTER, mint_allowance));

        // Batch mint to each recipient's fungible store.
        let expected_deposit_events = vector::empty<stablecoin::Deposit>();
        {
            let i = 0;
            while (i < vector::length(&recipients)) {
                let recipient = *vector::borrow(&recipients, i);
                let mint_amount = *vector::borrow(&mint_amounts, i);

                let store = fungible_asset::create_store(
                    &object::create_object(recipient),
                    stablecoin_metadata
                );
                let asset = fungible_asset::extract(&mut minted_asset, mint_amount);
                dispatchable_fungible_asset::deposit(store, asset);

                vector::push_back(
                    &mut expected_deposit_events,
                    stablecoin::test_Deposit_event(
                        recipient,
                        object::object_address(&store),
                        mint_amount
                    )
                );

                i = i + 1;
            }
        };

        fungible_asset::destroy_zero(minted_asset);

        // Ensure that the correct events were emitted.
        assert_eq(vector::length(&expected_mint_events), 1);
        assert_eq(vector::length(&expected_deposit_events), 3);
        assert_eq(event::emitted_events<treasury::Mint>(), expected_mint_events);
        assert_eq(event::emitted_events<stablecoin::Deposit>(), expected_deposit_events);
    }

    #[test]
    fun withdraw_and_burn__should_succeed() {
        let stablecoin_metadata = setup();

        // Set up controller and minter.
        treasury::set_master_minter_for_testing(MASTER_MINTER);
        treasury::test_configure_controller(&create_signer_for_test(MASTER_MINTER), CONTROLLER, MINTER);
        treasury::test_configure_minter(&create_signer_for_test(CONTROLLER), 10_000_000);

        // Set up store for recipient.
        let store = fungible_asset::create_store(
            &object::create_object(RANDOM_ADDRESS),
            stablecoin_metadata
        );

        // Mint and deposit to store.
        {
            let asset = treasury::mint(&create_signer_for_test(MINTER), 10_000_000);
            dispatchable_fungible_asset::deposit(store, asset);

            assert_eq(fungible_asset::supply(stablecoin_metadata), option::some((10_000_000 as u128)));
            assert_eq(fungible_asset::balance(store), 10_000_000);
        };

        // Withdraw from store and burn.
        {
            let asset = dispatchable_fungible_asset::withdraw(&create_signer_for_test(RANDOM_ADDRESS), store, 1_000_000);
            treasury::burn(&create_signer_for_test(MINTER), asset);

            assert_eq(fungible_asset::supply(stablecoin_metadata), option::some((9_000_000 as u128)));
            assert_eq(fungible_asset::balance(store), 9_000_000);

            let withdraw_event = stablecoin::test_Withdraw_event(
                RANDOM_ADDRESS, /* store owner */
                object::object_address(&store),
                1_000_000
            );
            let burn_event = treasury::test_Burn_event(MINTER, 1_000_000);
            assert_eq(event::was_event_emitted(&withdraw_event), true);
            assert_eq(event::was_event_emitted(&burn_event), true);
        };
    }
}
