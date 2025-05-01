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

spec aptos_extensions::ownable {
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: The OwnerRole resource is missing.
    /// Post condition: There are no changes to the OwnerRole state.
    /// Post condition: The owner address is always returned.
    spec owner {
        let obj_address = object::object_address(obj);
        aborts_if !exists<OwnerRole>(obj_address);
        ensures global<OwnerRole>(obj_address) == old(global<OwnerRole>(obj_address));
        ensures result == global<OwnerRole>(obj_address).owner;
    }

    /// Abort condition: The OwnerRole resource is missing.
    /// Post condition: There are no changes to the OwnerRole state.
    /// Post condition: The pending owner address is always returned.
    spec pending_owner {
        let obj_address = object::object_address(obj);
        aborts_if !exists<OwnerRole>(obj_address);
        ensures global<OwnerRole>(obj_address) == old(global<OwnerRole>(obj_address));
        ensures result == global<OwnerRole>(obj_address).pending_owner;
    }

    /// Abort condition: The address is not a valid object address.
    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The caller is not the owner.
    /// Post condition: There are no changes to the OwnerRole state.
    spec assert_is_owner {
        aborts_if !exists<object::ObjectCore>(obj_address);
        aborts_if !exists<OwnerRole>(obj_address) || !object::spec_exists_at<OwnerRole>(obj_address);
        aborts_if signer::address_of(caller) != global<OwnerRole>(obj_address).owner;
        ensures global<OwnerRole>(obj_address) == old(global<OwnerRole>(obj_address));
    }

    /// Abort condition: No object exists at the object address.
    /// Abort condition: The OwnerRole resource already exists at the object address.
    /// Post condition: The OwnerRole resource is created properly.
    spec new {
        let obj_address = signer::address_of(obj_signer);
        aborts_if !exists<object::ObjectCore>(obj_address);
        aborts_if exists<OwnerRole>(obj_address);
        ensures global<OwnerRole>(obj_address) == OwnerRole { owner, pending_owner: option::spec_none() };
    }

    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The caller is not the owner address.
    /// Post condition: The pending owner address is always updated to the new_owner.
    /// Post condition: The owner address does not change.
    spec transfer_ownership {
        let obj_address = object::object_address(obj);
        aborts_if !exists<OwnerRole>(obj_address);
        aborts_if signer::address_of(caller) != global<OwnerRole>(obj_address).owner;
        ensures global<OwnerRole>(obj_address).owner == old(global<OwnerRole>(obj_address).owner);
        ensures option::spec_contains(global<OwnerRole>(obj_address).pending_owner, new_owner);
    }

    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The pending owner address is not set.
    /// Abort condition: The caller is not the pending owner.
    /// Post condition: The owner address is always set to the previous pending owner.
    /// Post condition: The pending owner is set to option::none.
    spec accept_ownership {
        let obj_address = object::object_address(obj);
        aborts_if !exists<OwnerRole>(obj_address);
        aborts_if option::is_none(global<OwnerRole>(obj_address).pending_owner);
        aborts_if !option::spec_contains(
            global<OwnerRole>(obj_address).pending_owner, signer::address_of(caller)
        );
        ensures global<OwnerRole>(obj_address).owner == signer::address_of(caller);
        ensures global<OwnerRole>(obj_address).pending_owner == option::spec_none();
    }

    /// Abort condition: The OwnerRole resource is missing.
    /// Post condition: The OwnerRole resource is always removed.
    spec destroy {
        aborts_if !exists<OwnerRole>(signer::address_of(caller));
        ensures !exists<OwnerRole>(signer::address_of(caller));
    }
}
