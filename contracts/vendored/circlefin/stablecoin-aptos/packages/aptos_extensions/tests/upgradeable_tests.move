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
module aptos_extensions::upgradeable_tests {
    use std::vector;
    use aptos_framework::account::{create_signer_for_test, create_test_signer_cap};
    use aptos_framework::event;

    use aptos_extensions::manageable;
    use aptos_extensions::test_utils::assert_eq;
    use aptos_extensions::upgradable;

    const RESOURCE_ADDRESS: address = @0x1111;
    const ADMIN_ADDRESS: address = @0x2222;
    const RANDOM_ADDRESS: address = @0x3333;

    const TEST_METADATA_SERIALIZED: vector<u8> = x"04746573740100000000000000000000000000"; // empty BCS serialized PackageMetadata

    #[test]
    fun new__should_create_signer_cap_store_correctly() {
        let resource_acct_signer = &create_signer_for_test(RESOURCE_ADDRESS);
        let resource_acct_signer_cap = create_test_signer_cap(RESOURCE_ADDRESS);

        manageable::new(resource_acct_signer, ADMIN_ADDRESS);
        upgradable::new(resource_acct_signer, resource_acct_signer_cap);

        assert_eq(upgradable::signer_cap_store_exists_for_testing(RESOURCE_ADDRESS), true);

        let extracted_signer_cap = upgradable::extract_signer_cap_for_testing(RESOURCE_ADDRESS);
        assert_eq(extracted_signer_cap, create_test_signer_cap(RESOURCE_ADDRESS));
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::EMISSING_ADMIN_RESOURCE)]
    fun new__should_fail_if_admin_resource_is_missing() {
        upgradable::new(
            &create_signer_for_test(RESOURCE_ADDRESS),
            create_test_signer_cap(RESOURCE_ADDRESS)
        );
    }

    #[test, expected_failure(abort_code = aptos_extensions::upgradable::EMISMATCHED_SIGNER_CAP)]
    fun new__should_fail_if_signer_cap_is_for_different_address() {
        let resource_acct_signer = &create_signer_for_test(RESOURCE_ADDRESS);
        manageable::new(resource_acct_signer, ADMIN_ADDRESS);
        upgradable::new(
            &create_signer_for_test(RESOURCE_ADDRESS),
            create_test_signer_cap(RANDOM_ADDRESS)
        );
    }

    #[test]
    fun upgrade_package__should_succeed() {
        setup_upgradeable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let package_upgraded_event = upgradable::test_PackageUpgraded_event(
            RESOURCE_ADDRESS
        );
        upgradable::test_upgrade_package(
            &create_signer_for_test(ADMIN_ADDRESS),
            RESOURCE_ADDRESS,
            TEST_METADATA_SERIALIZED,
            vector::empty()
        );

        assert_eq(event::was_event_emitted(&package_upgraded_event), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_ADMIN)]
    fun upgrade_package__should_fail_if_caller_not_admin() {
        setup_upgradeable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        upgradable::test_upgrade_package(
            &create_signer_for_test(RANDOM_ADDRESS),
            RESOURCE_ADDRESS,
            TEST_METADATA_SERIALIZED,
            vector::empty()
        );
    }

    #[test]
    fun extract_signer_cap__should_extract_signer_capability() {
        setup_upgradeable(RESOURCE_ADDRESS, ADMIN_ADDRESS);
        let cap_extracted_event = upgradable::test_SignerCapExtracted_event(RESOURCE_ADDRESS);

        let signer_cap = upgradable::extract_signer_cap(
            &create_signer_for_test(ADMIN_ADDRESS),
            RESOURCE_ADDRESS
        );

        assert_eq(create_test_signer_cap(RESOURCE_ADDRESS), signer_cap);
        assert_eq(event::was_event_emitted(&cap_extracted_event), true);
    }

    #[test]
    fun extract_signer_cap__should_remove_signer_cap_store_resource() {
        setup_upgradeable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        assert_eq(upgradable::signer_cap_store_exists_for_testing(RESOURCE_ADDRESS), true);

        upgradable::extract_signer_cap(
            &create_signer_for_test(ADMIN_ADDRESS),
            RESOURCE_ADDRESS
        );

        assert_eq(upgradable::signer_cap_store_exists_for_testing(RESOURCE_ADDRESS), false);
    }

    #[test, expected_failure(abort_code = aptos_extensions::manageable::ENOT_ADMIN)]
    fun extract_signer_cap__should_fail_if_caller_not_admin() {
        setup_upgradeable(RESOURCE_ADDRESS, ADMIN_ADDRESS);

        upgradable::extract_signer_cap(&create_signer_for_test(RANDOM_ADDRESS), RESOURCE_ADDRESS);
    }

    // === Test helpers ===

    fun setup_upgradeable(resource_address: address, admin: address) {
        let resource_acct_signer = &create_signer_for_test(resource_address);
        let resource_acct_signer_cap = create_test_signer_cap(resource_address);

        manageable::new(resource_acct_signer, admin);
        upgradable::new(resource_acct_signer, resource_acct_signer_cap);
    }
}
