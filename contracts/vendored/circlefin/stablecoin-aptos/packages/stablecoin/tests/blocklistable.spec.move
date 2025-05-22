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

spec stablecoin::blocklistable {
    use aptos_framework::object::ObjectCore;
    use aptos_extensions::ownable::OwnerRole;
    use stablecoin::stablecoin_utils::spec_stablecoin_address;

    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;

        invariant forall addr: address where exists<BlocklistState>(addr):
            object::object_address(global<BlocklistState>(addr).transfer_ref.metadata) == addr;
    }

    /// Abort condition: The BlocklistState resource is missing.
    /// Post condition: Return whether address is blocklisted.
    /// Post condition: The BlocklistState resource is unchanged.
    spec is_blocklisted {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<BlocklistState>(stablecoin_address);
        ensures result
            == table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, addr);
        ensures global<BlocklistState>(stablecoin_address) == old(global<BlocklistState>(stablecoin_address));
    }

    /// Abort condition: The BlocklistState resource is missing.
    /// Post condition: The blocklister address is always returned.
    /// Post condition: The BlocklistState resource is unchanged.
    spec blocklister {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<BlocklistState>(stablecoin_address);
        ensures result == global<BlocklistState>(stablecoin_address).blocklister;
        ensures global<BlocklistState>(stablecoin_address) == old(global<BlocklistState>(stablecoin_address));
    }

    /// Abort condition: The BlocklistState resource is missing.
    /// Abort condition: The input address is blocklisted.
    /// Post condition: The BlocklistState resource is unchanged.
    spec assert_not_blocklisted {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, addr);
        ensures global<BlocklistState>(stablecoin_address) == old(global<BlocklistState>(stablecoin_address));
    }

    /// Abort condition: The stablecoin_obj_constructor_ref does not refer to a valid object.
    /// Abort condition: The BlocklistState resource already exists at the object address.
    /// Abort condition: The fungible asset Metadata resource is missing.
    /// Post condition: The BlocklistState resource is created properly.
    spec new {
        let stablecoin_address = object::address_from_constructor_ref(stablecoin_obj_constructor_ref);
        aborts_if !exists<object::ObjectCore>(stablecoin_address);
        aborts_if !object::spec_exists_at<aptos_framework::fungible_asset::Metadata>(stablecoin_address);
        aborts_if exists<BlocklistState>(stablecoin_address);
        ensures table_with_length::spec_len(global<BlocklistState>(stablecoin_address).blocklist) == 0;
        ensures global<BlocklistState>(stablecoin_address).blocklister == blocklister;
        ensures global<BlocklistState>(stablecoin_address).transfer_ref
            == TransferRef {
                metadata: object::address_to_object<aptos_framework::fungible_asset::Metadata>(stablecoin_address)
            };
    }

    /// Abort condition: The BlocklistState resource is missing.
    /// Abort condition: The caller is not the blocklister address.
    /// Post condition: The address is always added to the blocklist if not already blocklisted.
    /// Post condition: The BlocklistState resource is unchanged if address is already blocklisted.
    /// Post condition: The blocklist should be updated with the input address, while all other addresses stay the same.
    spec blocklist {
        let stablecoin_address = spec_stablecoin_address();

        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if signer::address_of(caller) != global<BlocklistState>(stablecoin_address).blocklister;

        ensures table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, addr_to_block)
            == true;
        ensures table_with_length::spec_contains(
            old(global<BlocklistState>(stablecoin_address)).blocklist, addr_to_block
        ) == true ==>
            global<BlocklistState>(stablecoin_address).blocklist
                == old(global<BlocklistState>(stablecoin_address).blocklist);
        ensures table_with_length::spec_contains(
            old(global<BlocklistState>(stablecoin_address)).blocklist, addr_to_block
        ) == false ==>
            global<BlocklistState>(stablecoin_address).blocklist
                == table_with_length::spec_set(
                    old(global<BlocklistState>(stablecoin_address).blocklist), addr_to_block, true
                );
    }

    /// Abort condition: The BlocklistState resource is missing.
    /// Abort condition: The caller is not blocklister address.
    /// Post condition: The address is always removed from the blocklist.
    /// Post condition: The BlocklistState resource is unchanged if address is not blocklisted.
    /// Post condition: The blocklist should be updated to remove the input address, while all other addresses stay the same.
    spec unblocklist {
        let stablecoin_address = spec_stablecoin_address();

        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if signer::address_of(caller) != global<BlocklistState>(stablecoin_address).blocklister;

        ensures table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, addr_to_unblock)
            == false;
        ensures table_with_length::spec_contains(
            old(global<BlocklistState>(stablecoin_address)).blocklist, addr_to_unblock
        ) == true ==>
            global<BlocklistState>(stablecoin_address).blocklist
                == table_with_length::spec_remove(
                    old(global<BlocklistState>(stablecoin_address).blocklist), addr_to_unblock
                );
        ensures table_with_length::spec_contains(
            old(global<BlocklistState>(stablecoin_address)).blocklist, addr_to_unblock
        ) == false ==>
            global<BlocklistState>(stablecoin_address).blocklist
                == old(global<BlocklistState>(stablecoin_address).blocklist);
    }

    /// Abort condition: The object does not exist at the stablecoin address.
    /// Abort condition: The OwnerRole resource is missing.
    /// Abort condition: The BlocklistState resource is missing.
    /// Abort condition: The caller is not owner address.
    /// Post condition: The blocklister address is always updated to new_blocklister.
    /// Post condition: The blocklist remains unchanged.
    spec update_blocklister {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<OwnerRole>(stablecoin_address) || !object::spec_exists_at<OwnerRole>(stablecoin_address);
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if signer::address_of(caller) != global<OwnerRole>(stablecoin_address).owner;
        ensures global<BlocklistState>(stablecoin_address).blocklister == new_blocklister;
        ensures global<BlocklistState>(stablecoin_address).blocklist
            == old(global<BlocklistState>(stablecoin_address).blocklist);
    }
}
