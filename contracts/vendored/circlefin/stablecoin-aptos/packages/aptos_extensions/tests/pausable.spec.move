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

spec aptos_extensions::pausable {
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: The PauseState resource is missing.
    /// Post condition: There are no changes to the PauseState.
    /// Post condition: The pauser address is always returned.
    spec pauser {
        let obj_address = object::object_address(obj);
        aborts_if !exists<PauseState>(obj_address);
        ensures global<PauseState>(obj_address) == old(global<PauseState>(obj_address));
        ensures result == global<PauseState>(obj_address).pauser;
    }

    /// Abort condition: The PauseState resource is missing.
    /// Post condition: There are no changes to the PauseState.
    /// Post condition: The paused state is always returned.
    spec is_paused {
        let obj_address = object::object_address(obj);
        aborts_if !exists<PauseState>(obj_address);
        ensures global<PauseState>(obj_address) == old(global<PauseState>(obj_address));
        ensures result == global<PauseState>(obj_address).paused;
    }

    /// Abort condition: The address is not a valid object address.
    /// Abort condition: The PauseState resource is missing
    /// Abort condition: The PauseState paused is true.
    /// Post condition: There are no changes to the PauseState.
    spec assert_not_paused {
        aborts_if !exists<object::ObjectCore>(obj_address);
        aborts_if !exists<PauseState>(obj_address) || !object::spec_exists_at<PauseState>(obj_address);
        aborts_if global<PauseState>(obj_address).paused;
        ensures global<PauseState>(obj_address) == old(global<PauseState>(obj_address));
    }

    /// Abort condition: Object does not exist at the object address.
    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The PauseState resource already exists at the object address.
    /// Post condition: The PauseState resource is created properly.
    spec new {
        let obj_address = signer::address_of(obj_signer);
        aborts_if !exists<object::ObjectCore>(obj_address);
        aborts_if !object::spec_exists_at<OwnerRole>(obj_address);
        aborts_if exists<PauseState>(obj_address);
        ensures global<PauseState>(obj_address) == PauseState { paused: false, pauser: pauser };
    }

    /// Abort condition: The PauseState resource is missing.
    /// Abort condition: The caller is not the pauser address.
    /// Post condition: The paused state is always set to true.
    /// Post condition: The pauser address does not change.
    spec pause {
        let obj_address = object::object_address(obj);
        aborts_if !exists<PauseState>(obj_address);
        aborts_if global<PauseState>(obj_address).pauser != signer::address_of(caller);
        ensures global<PauseState>(obj_address).paused;
        ensures global<PauseState>(obj_address).pauser == old(global<PauseState>(obj_address).pauser);
    }

    /// Abort condition: The PauseState resource is missing.
    /// Abort condition: The caller is not the pauser address.
    /// Post condition: The paused state is always set to false
    /// Post condition: The pauser address does not change
    spec unpause {
        let obj_address = object::object_address(obj);
        aborts_if !exists<PauseState>(obj_address);
        aborts_if global<PauseState>(obj_address).pauser != signer::address_of(caller);
        ensures !global<PauseState>(obj_address).paused;
        ensures global<PauseState>(obj_address).pauser == old(global<PauseState>(obj_address).pauser);
    }

    /// Abort condition: The input object does not contain a valid object address.
    /// Abort condition: The PauseState resource is missing.
    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The caller is not the owner address.
    /// Post condition: The pauser is always updated to new_pauser.
    /// Post condition: The paused state does not change.
    spec update_pauser {
        let obj_address = object::object_address(obj);
        aborts_if !exists<object::ObjectCore>(obj_address);
        aborts_if !exists<PauseState>(obj_address);
        aborts_if !exists<OwnerRole>(obj_address) || !object::spec_exists_at<OwnerRole>(obj_address);
        aborts_if global<OwnerRole>(obj_address).owner != signer::address_of(caller);
        ensures global<PauseState>(obj_address).pauser == new_pauser;
        ensures global<PauseState>(obj_address).paused == old(global<PauseState>(obj_address).paused);
    }

    /// Abort condition: The PauseState resource is missing.
    /// Post condition: The PauseState resource is always removed.
    spec destroy {
        aborts_if !exists<PauseState>(signer::address_of(caller));
        ensures !exists<PauseState>(signer::address_of(caller));
    }
}
