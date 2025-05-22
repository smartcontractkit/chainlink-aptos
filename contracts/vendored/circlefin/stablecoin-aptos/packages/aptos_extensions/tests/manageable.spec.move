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

spec aptos_extensions::manageable {
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Post condition: There are no changes to the AdminRole state.
    /// Post condition: The admin address is always returned.
    spec admin {
        aborts_if !exists<AdminRole>(resource_address);
        ensures global<AdminRole>(resource_address) == old(global<AdminRole>(resource_address));
        ensures result == global<AdminRole>(resource_address).admin;
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Post condition: There are no changes to the AdminRole state.
    /// Post condition: The pending admin address is always returned.
    spec pending_admin {
        aborts_if !exists<AdminRole>(resource_address);
        ensures global<AdminRole>(resource_address) == old(global<AdminRole>(resource_address));
        ensures result == global<AdminRole>(resource_address).pending_admin;
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Post condition: The caller is not the admin of the resource address.
    /// Post condition: There are no changes to the AdminRole state.
    spec assert_is_admin {
        aborts_if !exists<AdminRole>(resource_address);
        aborts_if signer::address_of(caller) != global<AdminRole>(resource_address).admin;
        ensures global<AdminRole>(resource_address) == old(global<AdminRole>(resource_address));
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Post condition: There are no changes to the AdminRole state.
    spec assert_admin_exists {
        aborts_if !exists<AdminRole>(resource_address);
        ensures global<AdminRole>(resource_address) == old(global<AdminRole>(resource_address));
    }

    /// Abort condition: The AdminRole resource already exists at the resource address.
    /// Post condition: The AdminRole resource is created properly.
    spec new {
        aborts_if exists<AdminRole>(signer::address_of(caller));
        ensures global<AdminRole>(signer::address_of(caller)) == AdminRole { admin, pending_admin: option::spec_none() };
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Abort condition: The caller is not the admin.
    /// Post condition: The pending admin is always updated to new_admin.
    /// Post condition: The admin does not change.
    spec change_admin {
        aborts_if !exists<AdminRole>(resource_address);
        aborts_if signer::address_of(caller) != global<AdminRole>(resource_address).admin;
        ensures global<AdminRole>(resource_address).admin == old(global<AdminRole>(resource_address).admin);
        ensures option::spec_contains(global<AdminRole>(resource_address).pending_admin, new_admin);
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Abort condition: The pending admin is not set.
    /// Post condition: The caller is not the pending admin.
    /// Post condition: The admin address is always set to the pending admin.
    /// Post condition: The pending admin is set to option::none.
    spec accept_admin {
        aborts_if !exists<AdminRole>(resource_address);
        aborts_if option::is_none(global<AdminRole>(resource_address).pending_admin);
        aborts_if !option::spec_contains(
            global<AdminRole>(resource_address).pending_admin, signer::address_of(caller)
        );
        ensures global<AdminRole>(resource_address).admin == signer::address_of(caller);
        ensures global<AdminRole>(resource_address).pending_admin == option::spec_none();
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Post condition: The AdminRole resource is always removed.
    spec destroy {
        aborts_if !exists<AdminRole>(signer::address_of(caller));
        ensures !exists<AdminRole>(signer::address_of(caller));
    }
}
