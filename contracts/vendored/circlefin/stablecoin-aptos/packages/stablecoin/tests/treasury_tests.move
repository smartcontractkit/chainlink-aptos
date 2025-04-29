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
module stablecoin::treasury_tests {
    use std::event;
    use std::option;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use aptos_framework::object::{Self, ConstructorRef, Object};

    use aptos_extensions::ownable;
    use aptos_extensions::pausable;
    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::blocklistable;
    use stablecoin::fungible_asset_tests::setup_fa;
    use stablecoin::stablecoin_utils::stablecoin_address;
    use stablecoin::treasury;

    const OWNER: address = @0x10;
    const PAUSER: address = @0x20;
    const BLOCKLISTER: address = @0x30;
    const MASTER_MINTER: address = @0x40;
    const CONTROLLER: address = @0x50;
    const MINTER: address = @0x60;
    const RANDOM_ADDRESS: address = @0x70;

    const U64_MAX: u64 = (1 << 63) | ((1 << 63) - 1);

    #[test]
    fun master_minter__should_return_master_minter_address() {
        setup();
        treasury::set_master_minter_for_testing(MASTER_MINTER);

        assert_eq(treasury::master_minter(), MASTER_MINTER);
    }

    #[test]
    fun get_minter__should_return_none_if_address_is_not_a_controller() {
        setup();
        treasury::force_remove_controller_for_testing(CONTROLLER);

        assert_eq(treasury::get_minter(CONTROLLER), option::none());
    }

    #[test]
    fun get_minter__should_return_controlled_minter() {
        setup();
        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);

        assert_eq(treasury::get_minter(CONTROLLER), option::some(MINTER));
    }

    #[test]
    fun is_minter__should_return_false_if_not_minter() {
        setup();
        treasury::force_remove_minter_for_testing(MINTER);

        assert_eq(treasury::is_minter(MINTER), false);
    }

    #[test]
    fun is_minter__should_return_true_if_minter() {
        setup();
        treasury::force_configure_minter_for_testing(MINTER, 1_000_000);

        assert_eq(treasury::is_minter(MINTER), true);
    }

    #[test]
    fun mint_allowance__should_return_zero_if_address_is_not_a_minter() {
        setup();
        treasury::force_remove_minter_for_testing(MINTER);

        assert_eq(treasury::mint_allowance(MINTER), 0);
    }

    #[test]
    fun mint_allowance__should_return_mint_allowance() {
        setup();
        treasury::force_configure_minter_for_testing(MINTER, 1_000_000);

        assert_eq(treasury::mint_allowance(MINTER), 1_000_000);
    }

    #[test]
    fun new__should_succeed() {
        let (stablecoin_obj_constructor_ref, _, _) = setup_fa(@stablecoin);
        test_new(&stablecoin_obj_constructor_ref, MASTER_MINTER);
    }

    #[test]
    fun configure_controller__should_succeed_and_configure_new_controller() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);
        assert_eq(treasury::is_controller_for_testing(CONTROLLER), false);

        test_configure_controller(MASTER_MINTER, CONTROLLER, MINTER);
    }

    #[test]
    fun configure_controller__should_succeed_and_update_existing_controller() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);
        treasury::force_configure_controller_for_testing(CONTROLLER, RANDOM_ADDRESS);
        assert_eq(treasury::get_minter(CONTROLLER), option::some(RANDOM_ADDRESS));

        test_configure_controller(MASTER_MINTER, CONTROLLER, MINTER);
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MASTER_MINTER)]
    fun configure_controller__should_fail_if_caller_is_not_master_minter() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);

        treasury::test_configure_controller(
            &create_signer_for_test(RANDOM_ADDRESS),
            CONTROLLER,
            MINTER,
        );
    }

    #[test]
    fun remove_controller__should_succeed() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);
        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);

        treasury::test_remove_controller(
            &create_signer_for_test(MASTER_MINTER),
            CONTROLLER,
        );

        let expected_event =
            treasury::test_ControllerRemoved_event(CONTROLLER);
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::get_minter(CONTROLLER), option::none());
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MASTER_MINTER)]
    fun remove_controller__should_fail_if_caller_is_not_master_minter() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);
        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);

        treasury::test_remove_controller(
            &create_signer_for_test(RANDOM_ADDRESS),
            CONTROLLER,
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_CONTROLLER)]
    fun remove_controller__should_fail_if_controller_is_unset() {
        setup();

        treasury::set_master_minter_for_testing(MASTER_MINTER);
        assert_eq(treasury::is_controller_for_testing(CONTROLLER), false);

        treasury::test_remove_controller(
            &create_signer_for_test(MASTER_MINTER),
            CONTROLLER,
        );
    }

    #[test]
    fun configure_minter__should_succeed_and_configure_new_minter() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        assert_eq(treasury::is_minter(MINTER), false);

        test_configure_minter(CONTROLLER, MINTER, 1_000_000);
    }

    #[test]
    fun configure_minter__should_succeed_and_update_existing_minter() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        test_configure_minter(CONTROLLER, MINTER, 1_000_000);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun configure_minter__should_fail_when_paused() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        pausable::set_paused_for_testing(stablecoin_address(), true);

        treasury::test_configure_minter(
            &create_signer_for_test(CONTROLLER),
            1_000_000,
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_CONTROLLER)]
    fun configure_minter__should_fail_if_caller_is_not_controller() {
        setup();

        assert_eq(treasury::is_controller_for_testing(CONTROLLER), false);

        treasury::test_configure_minter(
            &create_signer_for_test(CONTROLLER),
            1_000_000,
        );
    }

    #[test]
    fun increment_minter_allowance__should_succeed() {
        setup();
        let initial_allowance = 100_000_000;
        let allowance_increment = 1_000_000;

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, initial_allowance);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER),
            allowance_increment,
        );

        let new_allowance = initial_allowance + allowance_increment;
        let expected_event =
            treasury::test_MinterAllowanceIncremented_event(
                CONTROLLER,
                MINTER,
                allowance_increment,
                new_allowance,
            );
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::mint_allowance(MINTER), new_allowance);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun increment_minter_allowance__should_fail_when_paused() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);
        pausable::set_paused_for_testing(stablecoin_address(), true);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER),
            1_000_000,
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::EZERO_AMOUNT)]
    fun increment_minter_allowance__should_fail_if_increment_is_zero() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER), 0
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_CONTROLLER)]
    fun increment_minter_allowance__should_fail_if_caller_is_not_controller() {
        setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);
        assert_eq(treasury::is_controller_for_testing(CONTROLLER), false);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER),
            1_000_000,
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MINTER)]
    fun increment_minter_allowance__should_fail_if_minter_is_not_configured() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        assert_eq(treasury::is_minter(MINTER), false);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER),
            1_000_000,
        );
    }

    #[test, expected_failure(arithmetic_error, location = stablecoin::treasury)]
    fun increment_minter_allowance__should_fail_if_overflow() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, U64_MAX);

        treasury::test_increment_minter_allowance(
            &create_signer_for_test(CONTROLLER), 1
        );
    }

    #[test]
    fun remove_minter__should_succeed() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        treasury::test_remove_minter(
            &create_signer_for_test(CONTROLLER)
        );

        let expected_event =
            treasury::test_MinterRemoved_event(CONTROLLER, MINTER);
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::is_minter(MINTER), false);
        assert_eq(treasury::mint_allowance(MINTER), 0);
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_CONTROLLER)]
    fun remove_minter__should_fail_if_caller_is_not_controller() {
        setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);
        assert_eq(treasury::is_controller_for_testing(CONTROLLER), false);

        treasury::test_remove_minter(
            &create_signer_for_test(CONTROLLER)
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MINTER)]
    fun remove_minter__should_fail_if_minter_is_unset() {
        setup();

        treasury::force_configure_controller_for_testing(CONTROLLER, MINTER);
        assert_eq(treasury::is_minter(MINTER), false);

        treasury::test_remove_minter(
            &create_signer_for_test(CONTROLLER)
        );
    }

    #[test]
    fun mint__should_succeed_and_return_minted_asset() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        let asset =
            test_mint(
                MINTER,
                1_000_000, /* mint amount */
                1_000_000, /* expected total supply */
                100_000_000 - 1_000_000, /* expected mint allowance */
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test]
    fun mint__should_succeed_given_mint_amount_is_equal_to_allowance() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        let asset =
            test_mint(
                MINTER,
                100_000_000, /* mint amount */
                100_000_000, /* expected total supply */
                0, /* expected mint allowance */
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::EZERO_AMOUNT)]
    fun mint__should_fail_if_mint_amount_is_zero() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        let asset =
            treasury::mint(
                &create_signer_for_test(MINTER), 0
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun mint__should_fail_when_paused() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);
        pausable::set_paused_for_testing(stablecoin_address(), true);

        let asset =
            treasury::mint(
                &create_signer_for_test(MINTER),
                1_000_000,
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MINTER)]
    fun mint__should_fail_if_caller_is_not_minter() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        assert_eq(treasury::is_minter(MINTER), false);

        let asset =
            treasury::mint(
                &create_signer_for_test(MINTER),
                1_000_000,
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::EBLOCKLISTED)]
    fun mint__should_fail_if_caller_is_blocklisted() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);
        blocklistable::set_blocklisted_for_testing(MINTER, true);

        let asset =
            treasury::mint(
                &create_signer_for_test(MINTER),
                1_000_000,
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::EINSUFFICIENT_ALLOWANCE)]
    fun mint__should_fail_if_minter_has_insufficient_allowance() {
        let (stablecoin_obj_constructor_ref, _) = setup();

        treasury::force_configure_minter_for_testing(MINTER, 100_000_000);

        let asset =
            treasury::mint(
                &create_signer_for_test(MINTER),
                100_000_001,
            );
        destroy_fungible_asset(&stablecoin_obj_constructor_ref, asset);
    }

    #[test]
    fun burn__should_succeed() {
        let (stablecoin_obj_constructor_ref, stablecoin_metadata) = setup();
        let mint_ref =
            fungible_asset::generate_mint_ref(&stablecoin_obj_constructor_ref);

        treasury::force_configure_minter_for_testing(MINTER, 0);
        let asset = fungible_asset::mint(&mint_ref, 1_000_000);

        assert_eq(fungible_asset::amount(&asset), 1_000_000);
        assert_eq(fungible_asset::supply(stablecoin_metadata), option::some((1_000_000 as u128)));

        treasury::burn(
            &create_signer_for_test(MINTER), asset
        );

        let expected_event = treasury::test_Burn_event(MINTER, 1_000_000);
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(fungible_asset::supply(stablecoin_metadata), option::some((0 as u128)));
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::EZERO_AMOUNT)]
    fun burn__should_fail_if_burn_amount_is_zero() {
        let (stablecoin_obj_constructor_ref, _) = setup();
        let mint_ref =
            fungible_asset::generate_mint_ref(&stablecoin_obj_constructor_ref);

        treasury::force_configure_minter_for_testing(MINTER, 0);
        let asset = fungible_asset::mint(&mint_ref, 0);
        assert_eq(fungible_asset::amount(&asset), 0);

        treasury::burn(
            &create_signer_for_test(MINTER), asset
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    fun burn__should_fail_when_paused() {
        let (stablecoin_obj_constructor_ref, _) = setup();
        let mint_ref =
            fungible_asset::generate_mint_ref(&stablecoin_obj_constructor_ref);

        treasury::force_configure_minter_for_testing(MINTER, 0);
        let asset = fungible_asset::mint(&mint_ref, 1_000_000);
        assert_eq(fungible_asset::amount(&asset), 1_000_000);
        pausable::set_paused_for_testing(stablecoin_address(), true);

        treasury::burn(
            &create_signer_for_test(MINTER), asset
        );
    }

    #[test, expected_failure(abort_code = stablecoin::treasury::ENOT_MINTER)]
    fun burn__should_fail_if_caller_is_not_minter() {
        let (stablecoin_obj_constructor_ref, _) = setup();
        let mint_ref =
            fungible_asset::generate_mint_ref(&stablecoin_obj_constructor_ref);

        let asset = fungible_asset::mint(&mint_ref, 1_000_000);
        assert_eq(fungible_asset::amount(&asset), 1_000_000);
        assert_eq(treasury::is_minter(MINTER), false);

        treasury::burn(
            &create_signer_for_test(MINTER), asset
        );
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::EBLOCKLISTED)]
    fun burn__should_fail_if_caller_is_blocklisted() {
        let (stablecoin_obj_constructor_ref, _) = setup();
        let mint_ref =
            fungible_asset::generate_mint_ref(&stablecoin_obj_constructor_ref);

        treasury::force_configure_minter_for_testing(MINTER, 0);
        let asset = fungible_asset::mint(&mint_ref, 1_000_000);
        assert_eq(fungible_asset::amount(&asset), 1_000_000);
        blocklistable::set_blocklisted_for_testing(MINTER, true);

        treasury::burn(
            &create_signer_for_test(MINTER), asset
        );
    }

    #[test]
    fun update_master_minter__should_update_role_to_different_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_master_minter(caller, OWNER, RANDOM_ADDRESS);
    }

    #[test]
    fun update_master_minter__should_succeed_with_same_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_master_minter(caller, OWNER, OWNER);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    fun update_master_minter__should_fail_if_caller_is_not_owner() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);

        test_update_master_minter(caller, OWNER, RANDOM_ADDRESS);
    }

    // === Helpers ===

    fun setup(): (ConstructorRef, Object<Metadata>) {
        let (stablecoin_obj_constructor_ref, stablecoin_metadata, _) = setup_fa(@stablecoin);
        test_new(&stablecoin_obj_constructor_ref, MASTER_MINTER);
        (stablecoin_obj_constructor_ref, stablecoin_metadata)
    }

    fun test_new(
        stablecoin_obj_constructor_ref: &ConstructorRef, master_minter: address,
    ) {
        let stablecoin_signer = object::generate_signer(stablecoin_obj_constructor_ref);
        let stablecoin_address =
            object::address_from_constructor_ref(stablecoin_obj_constructor_ref);
        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_address);

        ownable::new(&stablecoin_signer, OWNER);
        pausable::new(&stablecoin_signer, PAUSER);
        blocklistable::new_for_testing(stablecoin_obj_constructor_ref, BLOCKLISTER);
        treasury::new_for_testing(stablecoin_obj_constructor_ref, master_minter);

        assert_eq(treasury::mint_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(treasury::burn_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(treasury::master_minter(), master_minter);
        assert_eq(treasury::num_controllers_for_testing(), 0);
        assert_eq(treasury::num_mint_allowances_for_testing(), 0);
    }

    fun test_configure_controller(
        master_minter: address,
        controller: address,
        minter: address
    ) {
        treasury::test_configure_controller(
            &create_signer_for_test(master_minter),
            controller,
            minter,
        );

        let expected_event =
            treasury::test_ControllerConfigured_event(
                controller, minter
            );
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::get_minter(controller), option::some(minter));
    }

    fun test_configure_minter(
        controller: address,
        minter: address,
        allowance: u64
    ) {
        treasury::test_configure_minter(
            &create_signer_for_test(controller),
            allowance,
        );

        let expected_event =
            treasury::test_MinterConfigured_event(
                controller,
                minter,
                allowance,
            );
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::is_minter(minter), true);
        assert_eq(treasury::mint_allowance(minter), allowance);
    }

    fun test_mint(
        minter: address,
        amount: u64,
        expected_total_supply: u128,
        expected_mint_allowance: u64
    ): FungibleAsset {
        let asset =
            treasury::mint(
                &create_signer_for_test(minter), amount
            );

        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_address());

        assert_eq(fungible_asset::amount(&asset), amount);
        assert_eq(fungible_asset::metadata_from_asset(&asset), stablecoin_metadata);

        let expected_event = treasury::test_Mint_event(minter, amount);
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(fungible_asset::supply(stablecoin_metadata), option::some(expected_total_supply));
        assert_eq(treasury::mint_allowance(minter), expected_mint_allowance);

        asset
    }

    fun test_update_master_minter(
        caller: &signer,
        old_master_minter: address,
        new_master_minter: address
    ) {
        treasury::set_master_minter_for_testing(old_master_minter);

        treasury::test_update_master_minter(caller, new_master_minter);

        let expected_event =
            treasury::test_MasterMinterChanged_event(
                old_master_minter, new_master_minter
            );
        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(treasury::master_minter(), new_master_minter);
    }

    fun destroy_fungible_asset(constructor_ref: &ConstructorRef, asset: FungibleAsset) {
        let burn_ref = fungible_asset::generate_burn_ref(constructor_ref);
        fungible_asset::burn(&burn_ref, asset);
    }
}
