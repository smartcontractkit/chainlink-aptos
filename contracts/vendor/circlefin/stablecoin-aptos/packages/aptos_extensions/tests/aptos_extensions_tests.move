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
module aptos_extensions::aptos_extensions_tests {
    use aptos_framework::account;
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::resource_account;

    const ZERO_AUTH_KEY: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const SEED: vector<u8> = b"1234";
    const SEED_2: vector<u8> = b"5678";

    /// error::not_found(resource_account::ECONTAINER_NOT_PUBLISHED)
    const ECONTAINER_NOT_PUBLISHED: u64 = 393217;
    /// error::invalid_argument(EUNAUTHORIZED_NOT_OWNER)
    const EUNAUTHORIZED_NOT_OWNER: u64 = 65538;

    #[test, expected_failure(abort_code = ECONTAINER_NOT_PUBLISHED, location = aptos_framework::resource_account)]
    fun init_module__should_consume_the_resource_account_signer_cap() {
        account::create_account_for_test(@deployer);
        resource_account::create_resource_account(&create_signer_for_test(@deployer), SEED, ZERO_AUTH_KEY);
        let resource_account_address = account::create_resource_address(&@deployer, SEED);
        let resource_account_signer = &create_signer_for_test(resource_account_address);

        aptos_extensions::aptos_extensions::test_init_module(resource_account_signer);

        resource_account::retrieve_resource_account_cap(resource_account_signer, @deployer);
    }

    #[test, expected_failure(abort_code = EUNAUTHORIZED_NOT_OWNER, location = aptos_framework::resource_account)]
    fun init_module__should_prevent_signer_cap_from_being_extracted_more_than_once() {
        account::create_account_for_test(@deployer);
        resource_account::create_resource_account(&create_signer_for_test(@deployer), SEED, ZERO_AUTH_KEY);
        resource_account::create_resource_account(&create_signer_for_test(@deployer), SEED_2, ZERO_AUTH_KEY);
        let resource_account_address = account::create_resource_address(&@deployer, SEED);
        let resource_account_signer = &create_signer_for_test(resource_account_address);

        aptos_extensions::aptos_extensions::test_init_module(resource_account_signer);

        resource_account::retrieve_resource_account_cap(resource_account_signer, @deployer);
    }
}
