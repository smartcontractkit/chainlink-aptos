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

spec aptos_extensions::upgradable {
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Abort condition: The signer_cap is not the caller's signer cap.
    /// Abort condition: The SignerCapStore resource already exists at the caller's address.
    /// Post condition: The SignerCapStore resource is created properly.
    spec new {
        aborts_if !exists<manageable::AdminRole>(signer::address_of(caller));
        aborts_if account::get_signer_capability_address(signer_cap) != signer::address_of(caller);
        aborts_if exists<SignerCapStore>(signer::address_of(caller));
        ensures global<SignerCapStore>(signer::address_of(caller)).signer_cap == signer_cap;
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Abort condition: The caller is not the resource_acct admin.
    /// Abort condition: The SignerCapStore resource is missing.
    /// [NOT PROVEN] Abort condition: The code::publish_package_txn fails.
    spec upgrade_package {
        pragma aborts_if_is_partial;
        aborts_if !exists<manageable::AdminRole>(resource_acct);
        aborts_if signer::address_of(caller) != global<manageable::AdminRole>(resource_acct).admin;
        aborts_if !exists<SignerCapStore>(resource_acct);
    }

    /// Abort condition: The AdminRole is missing.
    /// Abort condition: The caller is not the resource_acct admin.
    /// Abort condition: The SignerCapStore resource is missing.
    /// Post condition: The SignerCapStore resource is removed.
    /// Post condition: The extracted signer_cap is returned.
    spec extract_signer_cap {
        aborts_if !exists<manageable::AdminRole>(resource_acct);
        aborts_if signer::address_of(caller) != global<manageable::AdminRole>(resource_acct).admin;
        aborts_if !exists<SignerCapStore>(resource_acct);
        ensures !exists<SignerCapStore>(resource_acct);
        ensures result == old(global<SignerCapStore>(resource_acct).signer_cap);
    }
}
