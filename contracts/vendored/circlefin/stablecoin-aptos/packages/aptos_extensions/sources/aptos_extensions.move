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

/// This module contains initialization logic where the aptos_extensions resource account signer capability is retrieved and dropped.
module aptos_extensions::aptos_extensions {
    use aptos_framework::resource_account;

    // === Write functions ===

    /// This function consumes the signer capability and drops it because the package is deployed to a resource account
    /// and we want to prevent future changes to the account after the deployment.
    fun init_module(resource_signer: &signer) {
        resource_account::retrieve_resource_account_cap(resource_signer, @deployer);
    }

    // === Test-only ===

    #[test_only]
    public fun test_init_module(resource_acct: &signer) {
        init_module(resource_acct);
    }
}
