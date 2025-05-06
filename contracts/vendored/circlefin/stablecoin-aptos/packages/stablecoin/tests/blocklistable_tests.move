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
module stablecoin::blocklistable_tests {
    use std::event;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, ConstructorRef};

    use aptos_extensions::ownable;
    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::blocklistable;
    use stablecoin::fungible_asset_tests::setup_fa;

    friend stablecoin::stablecoin_tests;

    const OWNER: address = @0x10;
    const BLOCKLISTER: address = @0x20;
    const RANDOM_ADDRESS: address = @0x30;

    #[test]
    fun is_blocklisted__should_return_true_if_blocklisted() {
        setup();
        blocklistable::set_blocklisted_for_testing(RANDOM_ADDRESS, true);

        assert_eq(blocklistable::is_blocklisted(RANDOM_ADDRESS), true);
    }

    #[test]
    fun is_blocklisted__should_return_false_by_default() {
        setup();

        assert_eq(blocklistable::is_blocklisted(RANDOM_ADDRESS), false);
    }

    #[test]
    fun is_blocklisted__should_return_false_if_not_blocklisted() {
        setup();
        blocklistable::set_blocklisted_for_testing(RANDOM_ADDRESS, false);

        assert_eq(blocklistable::is_blocklisted(RANDOM_ADDRESS), false);
    }

    #[test]
    fun blocklister__should_return_blocklister_address() {
        setup();
        blocklistable::set_blocklister_for_testing(BLOCKLISTER);

        assert_eq(blocklistable::blocklister(), BLOCKLISTER);
    }

    #[test]
    fun new__should_succeed() {
        let (stablecoin_obj_constructor_ref, _, _) = setup_fa(@stablecoin);
        test_new(
            &stablecoin_obj_constructor_ref,
            BLOCKLISTER,
        );
    }

    #[test]
    fun blocklist__should_succeed_with_unblocked_address() {
        setup();
        let blocklister =
            &create_signer_for_test(blocklistable::blocklister());

        test_blocklist(blocklister, RANDOM_ADDRESS);
    }

    #[test]
    fun blocklist__should_be_idempotent() {
        setup();
        let blocklister =
            &create_signer_for_test(blocklistable::blocklister());
        blocklistable::set_blocklisted_for_testing(RANDOM_ADDRESS, true);

        test_blocklist(blocklister, RANDOM_ADDRESS);
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::ENOT_BLOCKLISTER)]
    fun blocklist__should_fail_if_caller_is_not_blocklister() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);

        test_blocklist(caller, RANDOM_ADDRESS);
    }

    #[test]
    fun unblocklist__should_unblock_blocked_address() {
        setup();
        let blocklister =
            &create_signer_for_test(blocklistable::blocklister());
        blocklistable::set_blocklisted_for_testing(RANDOM_ADDRESS, true);

        test_unblocklist(blocklister, RANDOM_ADDRESS);
    }

    #[test]
    fun unblocklist__should_succeed_on_unblocklisted_address() {
        setup();
        let blocklister =
            &create_signer_for_test(blocklistable::blocklister());

        test_unblocklist(blocklister, RANDOM_ADDRESS);
    }

    #[test]
    fun unblocklist__should_be_idempotent() {
        setup();
        let blocklister =
            &create_signer_for_test(blocklistable::blocklister());
        blocklistable::set_blocklisted_for_testing(RANDOM_ADDRESS, false);

        test_unblocklist(blocklister, RANDOM_ADDRESS);
    }

    #[test, expected_failure(abort_code = stablecoin::blocklistable::ENOT_BLOCKLISTER)]
    fun unblocklist__should_fail_if_caller_is_not_blocklister() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);

        test_unblocklist(caller, RANDOM_ADDRESS);
    }

    #[test]
    fun update_blocklister__should_update_role_to_different_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_blocklister(caller, OWNER, RANDOM_ADDRESS);
    }

    #[test]
    fun update_blocklister__should_succeed_with_same_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_blocklister(caller, OWNER, OWNER);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    fun update_blocklister__should_fail_if_caller_is_not_owner() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);

        test_update_blocklister(caller, OWNER, RANDOM_ADDRESS);
    }

    // === Helpers ===

    fun setup() {
        let (stablecoin_obj_constructor_ref, _, _) = setup_fa(@stablecoin);
        test_new(&stablecoin_obj_constructor_ref, BLOCKLISTER);
    }

    fun test_new(
        stablecoin_obj_constructor_ref: &ConstructorRef,
        blocklister: address,
    ) {
        let stablecoin_address = object::address_from_constructor_ref(stablecoin_obj_constructor_ref);
        let stablecoin_signer = object::generate_signer(stablecoin_obj_constructor_ref);
        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_address);

        ownable::new(&stablecoin_signer, OWNER);
        blocklistable::new_for_testing(stablecoin_obj_constructor_ref, blocklister);

        assert_eq(blocklistable::transfer_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(blocklistable::num_blocklisted_for_testing(), 0);
        assert_eq(blocklistable::blocklister(), blocklister);
    }

    fun test_blocklist(caller: &signer, addr: address) {
        let expected_event = blocklistable::test_Blocklisted_event(addr);

        blocklistable::test_blocklist(caller, addr);

        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(blocklistable::is_blocklisted(addr), true);
    }

    fun test_unblocklist(caller: &signer, addr: address) {
        let expected_event = blocklistable::test_Unblocklisted_event(addr);

        blocklistable::test_unblocklist(caller, addr);

        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(blocklistable::is_blocklisted(addr), false);
    }

    fun test_update_blocklister(
        caller: &signer,
        old_blocklister: address,
        new_blocklister: address
    ) {
        blocklistable::set_blocklister_for_testing(old_blocklister);
        let expected_event = blocklistable::test_BlocklisterChanged_event(
            old_blocklister, new_blocklister
        );

        blocklistable::test_update_blocklister(caller, new_blocklister);

        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(blocklistable::blocklister(), new_blocklister);
    }
}
