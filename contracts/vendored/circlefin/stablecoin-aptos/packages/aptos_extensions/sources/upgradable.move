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

/// This module defines logic to perform a package upgrade on a resource account.
/// The module depends on the manageable module for admin role management.
module aptos_extensions::upgradable {
    use std::signer;
    use aptos_framework::account::{Self, SignerCapability};
    use aptos_framework::code;
    use aptos_framework::event;

    use aptos_extensions::manageable;

    // === Errors ===

    /// The SignerCapability is not the caller's signer cap.
    const EMISMATCHED_SIGNER_CAP: u64 = 1;

    // === Structs ===

    struct SignerCapStore has key {
        signer_cap: SignerCapability
    }

    // === Events ===

    #[event]
    /// Emitted when a package is upgraded.
    struct PackageUpgraded has drop, store {
        resource_acct: address
    }

    #[event]
    /// Emitted when the SignerCapability is extracted.
    struct SignerCapExtracted has drop, store {
        resource_acct: address
    }

    // === Write functions ===

    /// Creates and inits a new SignerCapStore resource.
    /// Requires an AdminRole resource to exist.
    public fun new(caller: &signer, signer_cap: SignerCapability) {
        manageable::assert_admin_exists(signer::address_of(caller));
        assert!(
            account::get_signer_capability_address(&signer_cap) == signer::address_of(caller),
            EMISMATCHED_SIGNER_CAP
        );
        move_to(caller, SignerCapStore { signer_cap });
    }

    /// Upgrades the package code at the resource account address.
    entry fun upgrade_package(
        caller: &signer,
        resource_acct: address,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>
    ) acquires SignerCapStore {
        manageable::assert_is_admin(caller, resource_acct);
        let signer_cap = &borrow_global<SignerCapStore>(resource_acct).signer_cap;

        let resource_signer = account::create_signer_with_capability(signer_cap);

        code::publish_package_txn(&resource_signer, metadata_serialized, code);

        event::emit(PackageUpgraded { resource_acct });
    }

    /// Extracts the SignerCapability from the SignerCapStore and removes the SignerCapStore resource.
    public fun extract_signer_cap(caller: &signer, resource_acct: address): SignerCapability acquires SignerCapStore {
        manageable::assert_is_admin(caller, resource_acct);

        let SignerCapStore { signer_cap } = move_from<SignerCapStore>(resource_acct);

        event::emit(SignerCapExtracted { resource_acct });

        signer_cap
    }

    // === Test-only ===

    #[test_only]
    public fun test_PackageUpgraded_event(resource_acct: address): PackageUpgraded {
        PackageUpgraded { resource_acct }
    }

    #[test_only]
    public fun test_SignerCapExtracted_event(resource_acct: address): SignerCapExtracted {
        SignerCapExtracted { resource_acct }
    }

    #[test_only]
    public fun extract_signer_cap_for_testing(resource_acct: address): SignerCapability acquires SignerCapStore {
        let SignerCapStore { signer_cap } = move_from<SignerCapStore>(resource_acct);
        signer_cap
    }

    #[test_only]
    public fun set_signer_cap_for_testing(caller: &signer, signer_cap: SignerCapability) {
        move_to(caller, SignerCapStore { signer_cap });
    }

    #[test_only]
    public fun test_upgrade_package(
        caller: &signer,
        resource_acct: address,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>
    ) acquires SignerCapStore {
        upgrade_package(caller, resource_acct, metadata_serialized, code);
    }

    #[test_only]
    public fun signer_cap_store_exists_for_testing(resource_acct: address): bool {
        exists<SignerCapStore>(resource_acct)
    }
}
