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

/// This module defines logic for managing an admin role privilege with two-step role transfer restrictions.
/// The two-step transfer process ensures the role is never transferred to an
/// inaccesible address.
///
/// Inspired by OpenZeppelin's Ownable2Step in Solidity:
/// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol.
module aptos_extensions::manageable {
    use std::option;
    use std::option::Option;
    use std::signer;
    use aptos_framework::event;

    // === Errors ===

    /// Address is not the admin.
    const ENOT_ADMIN: u64 = 1;
    /// Address is not the pending admin.
    const ENOT_PENDING_ADMIN: u64 = 2;
    /// Pending admin is not set.
    const EPENDING_ADMIN_NOT_SET: u64 = 3;
    /// AdminRole resource is missing.
    const EMISSING_ADMIN_RESOURCE: u64 = 4;

    // === Structs ===

    /// The admin and pending admin addresses state.
    struct AdminRole has key {
        admin: address,
        pending_admin: Option<address>
    }

    // === Events ===

    #[event]
    /// Emitted when the admin change is started.
    struct AdminChangeStarted has drop, store {
        resource_address: address,
        old_admin: address,
        new_admin: address
    }

    #[event]
    /// Emitted when the admin is changed to a new address.
    struct AdminChanged has drop, store {
        resource_address: address,
        old_admin: address,
        new_admin: address
    }

    #[event]
    /// Emitted when the AdminRole resource is destroyed.
    struct AdminRoleDestroyed has drop, store {
        resource_address: address
    }

    // === View-only functions ===

    #[view]
    /// Returns the active admin address.
    public fun admin(resource_address: address): address acquires AdminRole {
        borrow_global<AdminRole>(resource_address).admin
    }

    #[view]
    /// Returns the pending admin address.
    public fun pending_admin(resource_address: address): Option<address> acquires AdminRole {
        borrow_global<AdminRole>(resource_address).pending_admin
    }

    /// Aborts if the caller is not the admin of the input object
    public fun assert_is_admin(caller: &signer, resource_address: address) acquires AdminRole {
        assert!(admin(resource_address) == signer::address_of(caller), ENOT_ADMIN);
    }

    /// Aborts if the AdminRole resource doesn't exist at the resource address.
    public fun assert_admin_exists(resource_address: address) {
        assert!(exists<AdminRole>(resource_address), EMISSING_ADMIN_RESOURCE);
    }

    // === Write functions ===

    /// Creates and inits a new AdminRole resource.
    public fun new(caller: &signer, admin: address) {
        move_to(caller, AdminRole { admin, pending_admin: option::none() });
    }

    /// Starts the admin role change by setting the pending admin to the new_admin address.
    entry fun change_admin(caller: &signer, resource_address: address, new_admin: address) acquires AdminRole {
        let admin_role = borrow_global_mut<AdminRole>(resource_address);
        assert!(admin_role.admin == signer::address_of(caller), ENOT_ADMIN);

        admin_role.pending_admin = option::some(new_admin);

        event::emit(AdminChangeStarted { resource_address, old_admin: admin_role.admin, new_admin });
    }

    /// Changes the admin address to the pending admin address.
    entry fun accept_admin(caller: &signer, resource_address: address) acquires AdminRole {
        let admin_role = borrow_global_mut<AdminRole>(resource_address);
        assert!(option::is_some(&admin_role.pending_admin), EPENDING_ADMIN_NOT_SET);
        assert!(
            option::contains(&admin_role.pending_admin, &signer::address_of(caller)),
            ENOT_PENDING_ADMIN
        );

        let old_admin = admin_role.admin;
        let new_admin = option::extract(&mut admin_role.pending_admin);

        admin_role.admin = new_admin;

        event::emit(AdminChanged { resource_address, old_admin, new_admin });
    }

    /// Removes the AdminRole resource from the caller.
    public fun destroy(caller: &signer) acquires AdminRole {
        let AdminRole { admin: _, pending_admin: _ } = move_from<AdminRole>(signer::address_of(caller));

        event::emit(AdminRoleDestroyed { resource_address: signer::address_of(caller) });
    }

    // === Test-only ===

    #[test_only]
    public fun test_AdminChangeStarted_event(
        resource_address: address, old_admin: address, new_admin: address
    ): AdminChangeStarted {
        AdminChangeStarted { resource_address, old_admin, new_admin }
    }

    #[test_only]
    public fun test_AdminChanged_event(
        resource_address: address, old_admin: address, new_admin: address
    ): AdminChanged {
        AdminChanged { resource_address, old_admin, new_admin }
    }

    #[test_only]
    public fun test_AdminRoleDestroyed_event(resource_address: address): AdminRoleDestroyed {
        AdminRoleDestroyed { resource_address }
    }

    #[test_only]
    public fun test_change_admin(caller: &signer, resource_address: address, new_admin: address) acquires AdminRole {
        change_admin(caller, resource_address, new_admin);
    }

    #[test_only]
    public fun test_accept_admin(caller: &signer, resource_address: address) acquires AdminRole {
        accept_admin(caller, resource_address);
    }

    #[test_only]
    public fun set_admin_for_testing(resource_address: address, admin: address) acquires AdminRole {
        let role = borrow_global_mut<AdminRole>(resource_address);
        role.admin = admin;
    }

    #[test_only]
    public fun set_pending_admin_for_testing(resource_address: address, pending_admin: address) acquires AdminRole {
        let role = borrow_global_mut<AdminRole>(resource_address);
        role.pending_admin = option::some(pending_admin);
    }

    #[test_only]
    public fun admin_role_exists_for_testing(resource_address: address): bool {
        exists<AdminRole>(resource_address)
    }
}
