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
module aptos_extensions::pausable_tests {
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::event;
    use aptos_framework::object::{Self, Object};

    use aptos_extensions::ownable;
    use aptos_extensions::pausable::{Self, PauseState};
    use aptos_extensions::test_utils::{assert_eq, create_and_move_custom_resource};

    // Test addresses
    const PAUSER_ADDRESS: address = @0x1111;
    const PAUSER_ADDRESS_2: address = @0x2222;
    const OWNER_ADDRESS: address = @0x3333;
    const RANDOM_ADDRESS: address = @0x4444;

    #[test]
    public fun new__should_set_pausable_address() {
        let (signer, obj_address) = create_and_move_custom_resource();
        ownable::new(&signer, OWNER_ADDRESS);
        pausable::new(&signer, PAUSER_ADDRESS);

        let obj = object::address_to_object<PauseState>(obj_address);
        assert_eq(
            pausable::pauser(obj),
            PAUSER_ADDRESS
        );
    }

    #[test]
    public fun new__should_set_paused_to_false() {
        let (signer, obj_address) = create_and_move_custom_resource();
        ownable::new(&signer, OWNER_ADDRESS);

        pausable::new(&signer, PAUSER_ADDRESS);

        let obj = object::address_to_object<PauseState>(obj_address);
        assert_eq(
            pausable::is_paused(obj),
            false
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::ENON_EXISTENT_OBJECT)]
    public fun new__should_fail_when_object_does_not_exist() {
        let signer = create_signer_for_test(RANDOM_ADDRESS);

        pausable::new(&signer, PAUSER_ADDRESS);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::ENON_EXISTENT_OWNER)]
    public fun new__should_fail_if_owner_role_not_created() {
        let (signer, _) = create_and_move_custom_resource();

        pausable::new(&signer, PAUSER_ADDRESS);
    }

    #[test]
    public fun is_paused__should_return_false_if_not_paused() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);

        pausable::set_paused_for_testing(obj_address, false);

        assert_eq(pausable::is_paused(obj), false);
    }

    #[test]
    public fun is_paused__should_return_true_if_paused() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);

        pausable::set_paused_for_testing(obj_address, true);

        assert_eq(pausable::is_paused(obj), true);
    }

    #[test]
    public fun pauser__should_return_pauser_address() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);

        pausable::set_pauser_for_testing(obj_address, PAUSER_ADDRESS_2);

        assert_eq(pausable::pauser(obj), PAUSER_ADDRESS_2);
    }

    #[test]
    public fun assert_not_paused__should_succeed_if_not_paused() {
        let (_, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        pausable::set_paused_for_testing(obj_address, false);

        pausable::assert_not_paused(obj_address);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::EPAUSED)]
    public fun assert_not_paused__should_abort_if_paused() {
        let (_, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        pausable::set_paused_for_testing(obj_address, true);

        pausable::assert_not_paused(obj_address);
    }

    #[test]
    public fun pause__should_set_paused_to_true() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_signer = &create_signer_for_test(PAUSER_ADDRESS);
        let pause_event = pausable::test_Pause_event(obj_address);

        pausable::test_pause(pauser_signer, obj);

        assert_eq(pausable::is_paused(obj), true);
        assert_eq(event::was_event_emitted(&pause_event), true);
    }

    #[test]
    public fun pause__should_succeed_if_already_paused() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_signer = &create_signer_for_test(PAUSER_ADDRESS);
        let pause_event = pausable::test_Pause_event(obj_address);

        pausable::set_paused_for_testing(obj_address, true);
        pausable::test_pause(pauser_signer, obj);

        assert_eq(pausable::is_paused(obj), true);
        assert_eq(event::was_event_emitted(&pause_event), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::ENOT_PAUSER)]
    public fun pause__should_fail_if_caller_is_not_pauser() {
        let (obj, _) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let invalid_signer = &create_signer_for_test(PAUSER_ADDRESS_2);

        pausable::test_pause(invalid_signer, obj);
    }

    #[test]
    public fun unpause__should_set_paused_to_false() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_signer = &create_signer_for_test(PAUSER_ADDRESS);
        let unpause_event = pausable::test_Unpause_event(obj_address);

        pausable::set_paused_for_testing(obj_address, true);
        pausable::test_unpause(pauser_signer, obj);

        assert_eq(pausable::is_paused(obj), false);
        assert_eq(event::was_event_emitted(&unpause_event), true);
    }

    #[test]
    public fun unpause__should_succeed_if_already_unpaused() {
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_signer = &create_signer_for_test(PAUSER_ADDRESS);
        let unpause_event = pausable::test_Unpause_event(obj_address);

        pausable::set_paused_for_testing(obj_address, false);
        pausable::test_unpause(pauser_signer, obj);

        assert_eq(pausable::is_paused(obj), false);
        assert_eq(event::was_event_emitted(&unpause_event), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::pausable::ENOT_PAUSER)]
    public fun unpause__should_fail_if_caller_not_pauser() {
        let (obj, _) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let invalid_signer = &create_signer_for_test(PAUSER_ADDRESS_2);

        pausable::test_unpause(invalid_signer, obj);
    }

    #[test]
    public fun update_pauser__should_set_new_pauser() {
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_changed_event = pausable::test_PauserChanged_event(
            obj_address,
            PAUSER_ADDRESS_2,
            PAUSER_ADDRESS
        );

        assert_eq(pausable::pauser(obj), PAUSER_ADDRESS);

        pausable::test_update_pauser(owner_signer, obj, PAUSER_ADDRESS_2);

        assert_eq(pausable::pauser(obj), PAUSER_ADDRESS_2);
        assert_eq(event::was_event_emitted(&pauser_changed_event), true);
    }

    #[test]
    public fun update_pauser__should_be_idempotent() {
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        let (obj, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let pauser_changed_event_1 = pausable::test_PauserChanged_event(
            obj_address,
            PAUSER_ADDRESS_2,
            PAUSER_ADDRESS
        );
        let pauser_changed_event_2 = pausable::test_PauserChanged_event(
            obj_address,
            PAUSER_ADDRESS_2,
            PAUSER_ADDRESS_2
        );

        pausable::test_update_pauser(owner_signer, obj, PAUSER_ADDRESS_2);
        pausable::test_update_pauser(owner_signer, obj, PAUSER_ADDRESS_2);

        assert_eq(pausable::pauser(obj), PAUSER_ADDRESS_2);
        assert_eq(event::was_event_emitted(&pauser_changed_event_1), true);
        assert_eq(event::was_event_emitted(&pauser_changed_event_2), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    public fun update_pauser__should_fail_if_caller_not_owner() {
        let invalid_owner_signer = &create_signer_for_test(PAUSER_ADDRESS_2);
        let (obj, _) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);

        pausable::test_update_pauser(invalid_owner_signer, obj, PAUSER_ADDRESS_2);
    }

    #[test]
    public fun destroy__should_remove_pausable_state_resource() {
        let (_, obj_address) = setup_pausable(OWNER_ADDRESS, PAUSER_ADDRESS);
        let object_signer = create_signer_for_test(obj_address);
        let pause_state_destroyed_event = pausable::test_PauseStateDestroyed_event(obj_address);

        assert_eq(object::object_exists<PauseState>(obj_address), true);

        pausable::destroy(&object_signer);

        assert_eq(object::object_exists<PauseState>(obj_address), false);
        assert_eq(event::was_event_emitted(&pause_state_destroyed_event), true);
    }

    // === Test helpers ===

    fun setup_pausable(owner: address, pauser: address): (Object<PauseState>, address) {
        let (signer, obj_address) = create_and_move_custom_resource();
        ownable::new(&signer, owner);
        pausable::new(&signer, pauser);
        (object::address_to_object<PauseState>(obj_address), obj_address)
    }
}
