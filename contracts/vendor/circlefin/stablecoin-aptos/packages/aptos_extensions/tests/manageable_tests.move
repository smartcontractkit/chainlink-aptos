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
module aptos_extensions::manageable_tests {
    use std::option;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::event;

    use aptos_extensions::manageable;
    use aptos_extensions::test_utils::{assert_eq, create_and_move_custom_resource};

    // Test addresses
    const ADMIN_ADDRESS: address = @0x1111;
    const ADMIN_ADDRESS_2: address = @0x2222;
    const ADMIN_ADDRESS_3: address = @0x3333;
    const RESOURCE_ADDRESS: address = @0x4444;

    #[test]
    fun new__should_create_object_admin_role_state_correctly() {
        let (signer, obj_address) = create_and_move_custom_resource();

        manageable::new(&signer, ADMIN_ADDRESS);

        assert_eq(manageable::admin_role_exists_for_testing(obj_address), true);

        assert_eq(
            manageable::admin(obj_address),
            ADMIN_ADDRESS
        );
        assert_eq(
            manageable::pending_admin(obj_address),
            option::none()
        );
    }

    #[test]
    fun new__should_create_account_admin_role_state_correctly() {
        manageable::new(&create_signer_for_test(RESOURCE_ADDRESS), ADMIN_ADDRESS);

        assert_eq(
            manageable::admin(RESOURCE_ADDRESS),
            ADMIN_ADDRESS
        );
        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::none()
        );
    }

    #[test]
    fun admin__should_return_admin_address() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        manageable::set_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);

        assert_eq(manageable::admin(RESOURCE_ADDRESS), ADMIN_ADDRESS_2);
    }

    #[test]
    fun pending_admin__should_return_pending_admin_address() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);

        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::some(ADMIN_ADDRESS_2)
        );
    }

    #[test]
    fun assert_is_admin__should_succeed_if_called_by_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        manageable::assert_is_admin(&create_signer_for_test(ADMIN_ADDRESS), RESOURCE_ADDRESS);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_ADMIN)]
    fun assert_is_admin__should_abort_if_not_called_by_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        manageable::assert_is_admin(&create_signer_for_test(ADMIN_ADDRESS_2), RESOURCE_ADDRESS);
    }

    #[test]
    fun assert_admin_exists__should_succeed_if_resource_exists() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        manageable::assert_admin_exists(RESOURCE_ADDRESS);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::EMISSING_ADMIN_RESOURCE)]
    fun assert_admin_exists__should_abort_if_admin_resource_does_not_exist() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        manageable::assert_admin_exists(ADMIN_ADDRESS);
    }

    #[test]
    fun change_admin__should_set_pending_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let admin_signer = &create_signer_for_test(ADMIN_ADDRESS);
        let admin_change_started_event = manageable::test_AdminChangeStarted_event(
            RESOURCE_ADDRESS,
            ADMIN_ADDRESS,
            ADMIN_ADDRESS_2
        );

        manageable::test_change_admin(admin_signer, RESOURCE_ADDRESS, ADMIN_ADDRESS_2);

        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::some(ADMIN_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&admin_change_started_event), true);
    }

    #[test]
    fun change_admin__should_reset_pending_admin_if_already_set() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let admin_signer = &create_signer_for_test(ADMIN_ADDRESS);
        let admin_change_started_event = manageable::test_AdminChangeStarted_event(
            RESOURCE_ADDRESS,
            ADMIN_ADDRESS,
            ADMIN_ADDRESS_2
        );

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_3);
        manageable::test_change_admin(admin_signer, RESOURCE_ADDRESS, ADMIN_ADDRESS_2);

        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::some(ADMIN_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&admin_change_started_event), true);
    }

    #[test]
    fun change_admin__should_set_same_pending_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let admin_signer = &create_signer_for_test(ADMIN_ADDRESS);
        let admin_change_started_event = manageable::test_AdminChangeStarted_event(
            RESOURCE_ADDRESS,
            ADMIN_ADDRESS,
            ADMIN_ADDRESS_2
        );

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);
        manageable::test_change_admin(admin_signer, RESOURCE_ADDRESS, ADMIN_ADDRESS_2);

        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::some(ADMIN_ADDRESS_2)
        );
        assert_eq(event::was_event_emitted(&admin_change_started_event), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_ADMIN)]
    fun change_admin__should_fail_if_caller_not_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let invalid_admin_signer = &create_signer_for_test(ADMIN_ADDRESS_2);
        manageable::test_change_admin(invalid_admin_signer, RESOURCE_ADDRESS, ADMIN_ADDRESS_2);
    }

    #[test]
    fun accept_admin__should_change_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let new_admin_signer = &create_signer_for_test(ADMIN_ADDRESS_2);
        let admin_changed_event = manageable::test_AdminChanged_event(
            RESOURCE_ADDRESS,
            ADMIN_ADDRESS,
            ADMIN_ADDRESS_2
        );

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);
        manageable::test_accept_admin(new_admin_signer, RESOURCE_ADDRESS);

        assert_eq(
            manageable::admin(RESOURCE_ADDRESS),
            ADMIN_ADDRESS_2
        );
        assert_eq(event::was_event_emitted(&admin_changed_event), true);
    }

    #[test]
    fun accept_admin__should_reset_pending_admin() {
        let new_admin_signer = &create_signer_for_test(ADMIN_ADDRESS_2);
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);
        manageable::test_accept_admin(new_admin_signer, RESOURCE_ADDRESS);

        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::none()
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::EPENDING_ADMIN_NOT_SET)]
    fun accept_admin__should_fail_if_pending_admin_is_not_set() {
        let new_admin_signer = &create_signer_for_test(ADMIN_ADDRESS_2);
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        manageable::test_accept_admin(new_admin_signer, RESOURCE_ADDRESS);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_PENDING_ADMIN)]
    fun accept_admin__should_fail_if_caller_is_not_pending_admin() {
        let new_admin_signer = &create_signer_for_test(ADMIN_ADDRESS_3);
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        manageable::set_pending_admin_for_testing(RESOURCE_ADDRESS, ADMIN_ADDRESS_2);
        manageable::test_accept_admin(new_admin_signer, RESOURCE_ADDRESS);
    }

    #[test]
    fun accept_admin__should_pass_if_pending_admin_same_as_admin() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let admin_signer = &create_signer_for_test(ADMIN_ADDRESS);

        manageable::test_change_admin(admin_signer, RESOURCE_ADDRESS, ADMIN_ADDRESS);
        manageable::test_accept_admin(admin_signer, RESOURCE_ADDRESS);

        assert_eq(
            manageable::admin(RESOURCE_ADDRESS),
            ADMIN_ADDRESS
        );
        assert_eq(
            manageable::pending_admin(RESOURCE_ADDRESS),
            option::none()
        );
    }

    #[test]
    public fun destroy__should_remove_admin_role_resource() {
        setup_manageable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let resource_signer = create_signer_for_test(RESOURCE_ADDRESS);
        let admin_role_destroyed_event = manageable::test_AdminRoleDestroyed_event(RESOURCE_ADDRESS);

        assert_eq(manageable::admin_role_exists_for_testing(RESOURCE_ADDRESS), true);

        manageable::destroy(&resource_signer);

        assert_eq(manageable::admin_role_exists_for_testing(RESOURCE_ADDRESS), false);
        assert_eq(event::was_event_emitted(&admin_role_destroyed_event), true);
    }

    // === Test helpers ===

    fun setup_manageable(resource_address: address, admin: address) {
        manageable::new(&create_signer_for_test(resource_address), admin);
    }
}
