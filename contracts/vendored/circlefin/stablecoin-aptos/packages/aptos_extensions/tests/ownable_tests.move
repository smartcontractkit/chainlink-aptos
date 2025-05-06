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
module aptos_extensions::ownable_tests {
    use std::option;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::event;
    use aptos_framework::object::{Self, Object};

    use aptos_extensions::ownable::{Self, OwnerRole};
    use aptos_extensions::test_utils::{assert_eq, create_and_move_custom_resource};

    // Test addresses
    const OWNER_ADDRESS: address = @0x1111;
    const OWNER_ADDRESS_2: address = @0x2222;
    const OWNER_ADDRESS_3: address = @0x3333;
    const RANDOM_ADDRESS: address = @0x4444;

    #[test]
    public fun new__should_set_ownable_state() {
        let (signer, obj_address) = create_and_move_custom_resource();

        ownable::new(&signer, OWNER_ADDRESS);

        let obj = object::address_to_object<OwnerRole>(obj_address);
        assert_eq(
            ownable::owner(obj),
            OWNER_ADDRESS
        );
        assert_eq(
            ownable::pending_owner(obj),
            option::none()
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENON_EXISTENT_OBJECT)]
    public fun new__should_fail_if_non_existent_object() {
        let signer = create_signer_for_test(RANDOM_ADDRESS);

        ownable::new(&signer, OWNER_ADDRESS);
    }

    #[test]
    public fun owner__should_return_owner_address() {
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);

        ownable::set_owner_for_testing(obj_address, OWNER_ADDRESS_2);

        assert_eq(
            ownable::owner(obj),
            OWNER_ADDRESS_2
        );
    }

    #[test]
    public fun pending_owner__should_return_pending_owner_address() {
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_2);

        assert_eq(
            ownable::pending_owner(obj),
            option::some(OWNER_ADDRESS_2)
        );
    }

    #[test]
    public fun assert_is_owner__should_succeed_if_called_by_owner() {
        let (_, obj_address) = setup_ownable(OWNER_ADDRESS);
        ownable::assert_is_owner(&create_signer_for_test(OWNER_ADDRESS), obj_address);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    public fun assert_is_owner__should_abort_if_not_called_by_owner() {
        let (_, obj_address) = setup_ownable(OWNER_ADDRESS);
        ownable::assert_is_owner(&create_signer_for_test(OWNER_ADDRESS_2), obj_address);
    }

    #[test]
    public fun transfer_ownership__should_set_pending_owner() {
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        let transfer_started_event = ownable::test_OwnershipTransferStarted_event(
            obj_address,
            OWNER_ADDRESS,
            OWNER_ADDRESS_2
        );

        ownable::test_transfer_ownership(owner_signer, obj, OWNER_ADDRESS_2);

        assert_eq(
            ownable::pending_owner(obj),
            option::some(OWNER_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&transfer_started_event), true);
    }

    #[test]
    public fun transfer_ownership__should_reset_pending_owner_if_already_set() {
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        let transfer_started_event = ownable::test_OwnershipTransferStarted_event(
            obj_address,
            OWNER_ADDRESS,
            OWNER_ADDRESS_2
        );

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_3);
        ownable::test_transfer_ownership(owner_signer, obj, OWNER_ADDRESS_2);

        assert_eq(
            ownable::pending_owner(obj),
            option::some(OWNER_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&transfer_started_event), true);
    }

    #[test]
    public fun transfer_ownership__should_set_same_pending_owner() {
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        let transfer_started_event = ownable::test_OwnershipTransferStarted_event(
            obj_address,
            OWNER_ADDRESS,
            OWNER_ADDRESS_2
        );

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_2);
        ownable::test_transfer_ownership(owner_signer, obj, OWNER_ADDRESS_2);

        assert_eq(
            ownable::pending_owner(obj),
            option::some(OWNER_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&transfer_started_event), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    public fun transfer_ownership__should_fail_if_caller_not_owner() {
        let (obj, _) = setup_ownable(OWNER_ADDRESS);
        let invalid_owner_signer = &create_signer_for_test(OWNER_ADDRESS_2);

        ownable::test_transfer_ownership(invalid_owner_signer, obj, OWNER_ADDRESS_2);
    }

    #[test]
    public fun accept_ownership__should_change_owner() {
        let new_owner_signer = &create_signer_for_test(OWNER_ADDRESS_2);
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);
        let ownership_transferred_event = ownable::test_OwnershipTransferred_event(
            obj_address,
            OWNER_ADDRESS,
            OWNER_ADDRESS_2
        );

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_2);
        ownable::test_accept_ownership(new_owner_signer, obj);

        assert_eq(
            ownable::owner(obj),
            OWNER_ADDRESS_2
        );
        assert_eq(event::was_event_emitted(&ownership_transferred_event), true);
    }

    #[test]
    public fun accept_ownership__should_reset_pending_owner() {
        let new_owner_signer = &create_signer_for_test(OWNER_ADDRESS_2);
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_2);
        ownable::test_accept_ownership(new_owner_signer, obj);

        assert_eq(
            ownable::pending_owner(obj),
            option::none()
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::EPENDING_OWNER_NOT_SET)]
    public fun accept_ownership__should_fail_if_pending_owner_is_not_set() {
        let new_owner_signer = &create_signer_for_test(OWNER_ADDRESS_2);
        let (obj, _) = setup_ownable(OWNER_ADDRESS);

        ownable::test_accept_ownership(new_owner_signer, obj);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_PENDING_OWNER)]
    public fun accept_ownership__should_fail_if_caller_is_not_pending_owner() {
        let invalid_pending_owner_signer = &create_signer_for_test(OWNER_ADDRESS_3);
        let (obj, obj_address) = setup_ownable(OWNER_ADDRESS);

        ownable::set_pending_owner_for_testing(obj_address, OWNER_ADDRESS_2);
        ownable::test_accept_ownership(invalid_pending_owner_signer, obj);
    }

    #[test]
    public fun accept_ownership__should_pass_if_pending_owner_same_as_owner() {
        let (obj, _) = setup_ownable(OWNER_ADDRESS);
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);

        ownable::test_transfer_ownership(owner_signer, obj, OWNER_ADDRESS);
        ownable::test_accept_ownership(owner_signer, obj);

        assert_eq(
            ownable::owner(obj),
            OWNER_ADDRESS
        );
        assert_eq(
            ownable::pending_owner(obj),
            option::none()
        );
    }

    #[test]
    public fun destroy__should_remove_owner_role_resource() {
        let (_, obj_address) = setup_ownable(OWNER_ADDRESS);
        let object_signer = create_signer_for_test(obj_address);
        let owner_role_destroyed_event = ownable::test_OwnerRoleDestroyed_event(obj_address);

        assert_eq(object::object_exists<OwnerRole>(obj_address), true);

        ownable::destroy(&object_signer);

        assert_eq(object::object_exists<OwnerRole>(obj_address), false);
        assert_eq(event::was_event_emitted(&owner_role_destroyed_event), true);
    }

    // === Test helpers ===

    fun setup_ownable(owner: address): (Object<OwnerRole>, address) {
        let (signer, obj_address) = create_and_move_custom_resource();
        ownable::new(&signer, owner);
        (object::address_to_object<OwnerRole>(obj_address), obj_address)
    }
}
