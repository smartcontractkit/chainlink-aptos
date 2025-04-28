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

/// This module defines logic to blocklist/unblocklist accounts from interacting with a stablecoin.
module stablecoin::blocklistable {
    use std::event;
    use std::signer;
    use std::table_with_length::{Self, TableWithLength};
    use aptos_framework::fungible_asset::{Self, TransferRef};
    use aptos_framework::object::{Self, ConstructorRef};

    use aptos_extensions::ownable;
    use stablecoin::stablecoin_utils::stablecoin_address;

    friend stablecoin::stablecoin;

    // === Errors ===

    /// Address is blocklisted.
    const EBLOCKLISTED: u64 = 1;
    /// Address is not the blocklister.
    const ENOT_BLOCKLISTER: u64 = 2;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct BlocklistState has key {
        /// Mapping containing blocked addresses.
        blocklist: TableWithLength<address, bool>,
        /// The address of the stablecoin's blocklister.
        blocklister: address,
        /// The capability to transfer and freeze units of a stablecoin.
        transfer_ref: TransferRef
    }

    // === Events ===

    #[event]
    struct Blocklisted has drop, store {
        address: address
    }

    #[event]
    struct Unblocklisted has drop, store {
        address: address
    }

    #[event]
    struct BlocklisterChanged has drop, store {
        old_blocklister: address,
        new_blocklister: address
    }

    // === View-only functions ===

    #[view]
    /// Returns whether an address is blocklisted
    public fun is_blocklisted(addr: address): bool acquires BlocklistState {
        internal_is_blocklisted(borrow_global<BlocklistState>(stablecoin_address()), addr)
    }

    #[view]
    /// Gets the blocklister address of a stablecoin.
    public fun blocklister(): address acquires BlocklistState {
        borrow_global<BlocklistState>(stablecoin_address()).blocklister
    }

    /// Aborts if the address is blocklisted.
    public fun assert_not_blocklisted(addr: address) acquires BlocklistState {
        assert!(!is_blocklisted(addr), EBLOCKLISTED);
    }

    // === Write functions ===

    /// Creates new blocklist state.
    public(friend) fun new(
        stablecoin_obj_constructor_ref: &ConstructorRef, blocklister: address
    ) {
        let stablecoin_obj_signer = &object::generate_signer(stablecoin_obj_constructor_ref);
        move_to(
            stablecoin_obj_signer,
            BlocklistState {
                blocklist: table_with_length::new(),
                blocklister,
                transfer_ref: fungible_asset::generate_transfer_ref(stablecoin_obj_constructor_ref)
            }
        );
    }

    /// Adds an account to the blocklist.
    entry fun blocklist(caller: &signer, addr_to_block: address) acquires BlocklistState {
        let blocklist_state = borrow_global_mut<BlocklistState>(stablecoin_address());
        assert!(signer::address_of(caller) == blocklist_state.blocklister, ENOT_BLOCKLISTER);
        if (!internal_is_blocklisted(blocklist_state, addr_to_block)) {
            table_with_length::add(&mut blocklist_state.blocklist, addr_to_block, true);
        };
        event::emit(Blocklisted { address: addr_to_block })
    }

    /// Removes an account from the blocklist.
    entry fun unblocklist(caller: &signer, addr_to_unblock: address) acquires BlocklistState {
        let blocklist_state = borrow_global_mut<BlocklistState>(stablecoin_address());
        assert!(signer::address_of(caller) == blocklist_state.blocklister, ENOT_BLOCKLISTER);
        if (internal_is_blocklisted(blocklist_state, addr_to_unblock)) {
            table_with_length::remove(&mut blocklist_state.blocklist, addr_to_unblock);
        };
        event::emit(Unblocklisted { address: addr_to_unblock })
    }

    /// Update blocklister role
    entry fun update_blocklister(caller: &signer, new_blocklister: address) acquires BlocklistState {
        let stablecoin_address = stablecoin_address();
        ownable::assert_is_owner(caller, stablecoin_address);

        let blocklist_state = borrow_global_mut<BlocklistState>(stablecoin_address);
        let old_blocklister = blocklist_state.blocklister;
        blocklist_state.blocklister = new_blocklister;

        event::emit(BlocklisterChanged { old_blocklister, new_blocklister });
    }

    // === Aliases ===

    inline fun internal_is_blocklisted(blocklist_state: &BlocklistState, addr: address): bool {
        table_with_length::contains(&blocklist_state.blocklist, addr)
    }

    // === Test Only ===

    #[test_only]
    use aptos_framework::fungible_asset::Metadata;
    #[test_only]
    use aptos_framework::object::Object;

    #[test_only]
    public fun new_for_testing(
        stablecoin_obj_constructor_ref: &ConstructorRef, blocklister: address
    ) {
        new(stablecoin_obj_constructor_ref, blocklister);
    }

    #[test_only]
    public fun transfer_ref_metadata_for_testing(): Object<Metadata> acquires BlocklistState {
        fungible_asset::transfer_ref_metadata(
            &borrow_global<BlocklistState>(stablecoin_address()).transfer_ref
        )
    }

    #[test_only]
    public fun num_blocklisted_for_testing(): u64 acquires BlocklistState {
        table_with_length::length(&borrow_global<BlocklistState>(stablecoin_address()).blocklist)
    }

    #[test_only]
    public fun set_blocklister_for_testing(blocklister: address) acquires BlocklistState {
        borrow_global_mut<BlocklistState>(stablecoin_address()).blocklister = blocklister;
    }

    #[test_only]
    public fun set_blocklisted_for_testing(addr: address, blocklisted: bool) acquires BlocklistState {
        let blocklist = &mut borrow_global_mut<BlocklistState>(stablecoin_address()).blocklist;
        if (blocklisted) {
            table_with_length::add(blocklist, addr, true);
        } else if (table_with_length::contains(blocklist, addr)) {
            table_with_length::remove(blocklist, addr);
        }
    }

    #[test_only]
    public fun test_blocklist(caller: &signer, addr_to_block: address) acquires BlocklistState {
        blocklist(caller, addr_to_block);
    }

    #[test_only]
    public fun test_unblocklist(caller: &signer, addr_to_unblock: address) acquires BlocklistState {
        unblocklist(caller, addr_to_unblock);
    }

    #[test_only]
    public fun test_Blocklisted_event(addr_to_block: address): Blocklisted {
        Blocklisted { address: addr_to_block }
    }

    #[test_only]
    public fun test_Unblocklisted_event(addr_to_unblock: address): Unblocklisted {
        Unblocklisted { address: addr_to_unblock }
    }

    #[test_only]
    public fun test_update_blocklister(caller: &signer, new_blocklister: address) acquires BlocklistState {
        update_blocklister(caller, new_blocklister);
    }

    #[test_only]
    public fun test_BlocklisterChanged_event(old_blocklister: address, new_blocklister: address): BlocklisterChanged {
        BlocklisterChanged { old_blocklister, new_blocklister }
    }
}
