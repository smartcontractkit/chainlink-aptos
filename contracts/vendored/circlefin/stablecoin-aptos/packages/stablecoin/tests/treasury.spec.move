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

spec stablecoin::treasury {
    use std::table_with_length;
    use aptos_framework::object::ObjectCore;
    use aptos_framework::fungible_asset::{ConcurrentSupply, Supply};
    use aptos_extensions::ownable::OwnerRole;
    use aptos_extensions::pausable::PauseState;
    use stablecoin::blocklistable::BlocklistState;

    /// Invariant: All addresses that owns a TreasuryState resource only stores a MintRef
    /// and a BurnRef that belong to itself.
    /// Invariant: Once a TreasuryState is initialized, the MintRef and the BurnRef stored in
    /// it is not updated.
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;

        invariant forall addr: address where exists<TreasuryState>(addr):
            object::object_address(global<TreasuryState>(addr).mint_ref.metadata) == addr
                && object::object_address(global<TreasuryState>(addr).burn_ref.metadata) == addr;

        invariant update forall addr: address where old(exists<TreasuryState>(addr)) && exists<TreasuryState>(addr):
            global<TreasuryState>(addr).mint_ref == old(global<TreasuryState>(addr).mint_ref)
                && global<TreasuryState>(addr).burn_ref == old(global<TreasuryState>(addr).burn_ref);
    }

    /// Invariant: The max allowance of a minter does not exceed MAX_U64.
    spec TreasuryState {
        invariant forall minter: address where smart_table::spec_contains(mint_allowances, minter):
            smart_table::spec_get(mint_allowances, minter) <= MAX_U64;
    }

    /// Abort condition: The required resources are missing.
    /// Post condition: There are no changes to TreasuryState.
    /// Post condition: The master minter address is always returned.
    spec master_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();

        aborts_if !exists<TreasuryState>(stablecoin_address);

        ensures global<TreasuryState>(stablecoin_address) == old(global<TreasuryState>(stablecoin_address));
        ensures result == global<TreasuryState>(stablecoin_address).master_minter;
    }

    /// Abort condition: The required resources are missing.
    /// Post condition: There are no changes to TreasuryState.
    /// Post condition: If the input address is a controller, then return an Option with the minter's address in it.
    /// Else return an empty Option.
    spec get_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();

        aborts_if !exists<TreasuryState>(stablecoin_address);

        ensures global<TreasuryState>(stablecoin_address) == old(global<TreasuryState>(stablecoin_address));

        let is_controller = smart_table::spec_contains(
            global<TreasuryState>(stablecoin_address).controllers, controller
        );
        ensures is_controller ==>
            result
                == option::spec_some(
                    smart_table::spec_get(global<TreasuryState>(stablecoin_address).controllers, controller)
                );
        ensures !is_controller ==>
            result == option::spec_none();
    }

    /// Abort condition: The required resources are missing.
    /// Post condition: There are no changes to TreasuryState.
    /// Post condition: Returns true if the input address is a minter, false otherwise.
    spec is_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();

        aborts_if !exists<TreasuryState>(stablecoin_address);

        ensures global<TreasuryState>(stablecoin_address) == old(global<TreasuryState>(stablecoin_address));
        ensures result
            == smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);
    }

    /// Abort condition: The required resources are missing.
    /// Post condition: There are no changes to TreasuryState.
    /// Post condition: If the input address is a minter, then return the minter's mint allowance.
    /// Else return zero.
    spec mint_allowance {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();

        aborts_if !exists<TreasuryState>(stablecoin_address);

        ensures global<TreasuryState>(stablecoin_address) == old(global<TreasuryState>(stablecoin_address));

        let is_minter = smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);
        ensures is_minter ==>
            result == smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter);
        ensures !is_minter ==> result == 0;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: A TreasuryState resource already exist at the address.
    /// Post condition: A TreasuryState resource is created at the address.
    spec new {
        let address_to_instantiate = object::address_from_constructor_ref(stablecoin_obj_constructor_ref);

        aborts_if !exists<ObjectCore>(address_to_instantiate);
        aborts_if !object::spec_exists_at<fungible_asset::Metadata>(address_to_instantiate);

        aborts_if exists<TreasuryState>(address_to_instantiate);

        ensures exists<TreasuryState>(address_to_instantiate);
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The caller is not the master minter.
    /// Post condition: If the controller did not exist, then only one controller is added.
    /// Post condition: If the controller already exists, then no controllers are added.
    /// Post condition: The TreasuryState's controllers table contain the (controller, minter) pair.
    /// Post condition: All irrelevant states are unchanged.
    spec configure_controller {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);

        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if caller != global<TreasuryState>(stablecoin_address).master_minter;

        ensures !old(smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, controller)) ==>
            smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers)
                == old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers)) + 1;

        ensures old(smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, controller)) ==>
            smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers)
                == old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers));

        ensures smart_table::spec_get(global<TreasuryState>(stablecoin_address).controllers, controller) == minter;

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).mint_allowances
            == old(global<TreasuryState>(stablecoin_address)).mint_allowances;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The caller is not the master minter.
    /// Abort condition: The controller address is not a controller.
    /// Post condition: Only one controller is removed.
    /// Post condition: The controller address specified in the input is removed.
    /// Post condition: All irrelevant states are unchanged.
    spec remove_controller {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);

        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if caller != global<TreasuryState>(stablecoin_address).master_minter;

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, controller);

        ensures old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers))
            - smart_table::spec_len(global<TreasuryState>(stablecoin_address).controllers) == 1;

        ensures !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, controller);

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).mint_allowances
            == old(global<TreasuryState>(stablecoin_address)).mint_allowances;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The caller is not a controller.
    /// Abort condition: The asset is paused.
    /// Post condition: If the minter did not exist, then only one minter is added.
    /// Post condition: If the minter already exists, then no minters are added.
    /// Post condition: The minter has the expected allowance.
    /// Post condition: All irrelevant states are unchanged.
    spec configure_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);
        let minter = smart_table::spec_get(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if global<PauseState>(stablecoin_address).paused;

        ensures !old(smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter)) ==>
            smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances)
                == old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances)) + 1;

        ensures old(smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter)) ==>
            smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances)
                == old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances));

        ensures smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter) == allowance;

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).controllers
            == old(global<TreasuryState>(stablecoin_address)).controllers;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The increment is zero.
    /// Abort condition: The caller is not a controller.
    /// Abort condition: The controller does not control a minter.
    /// Abort condition: The allowance increment will cause an overflow.
    /// Abort condition: The asset is paused.
    /// Post condition: The list of minters remains unchanged.
    /// Post condition: The minter's allowance is correctly updated.
    /// Post condition: All irrelevant states are unchanged.
    spec increment_minter_allowance {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);
        let minter = smart_table::spec_get(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if allowance_increment == 0;

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);

        aborts_if smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter)
            + allowance_increment > MAX_U64;

        aborts_if global<PauseState>(stablecoin_address).paused;

        ensures smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances)
            == old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances));

        ensures smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter)
            == old(smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter))
                + allowance_increment;

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).controllers
            == old(global<TreasuryState>(stablecoin_address)).controllers;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The caller is not a controller.
    /// Abort condition: The controller does not control a minter.
    /// Post condition: Only one minter is removed.
    /// Post condition: The minter address is removed.
    /// Post condition: All irrelevant states are unchanged.
    spec remove_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);
        let minter = smart_table::spec_get(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).controllers, caller);

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);

        ensures old(smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances))
            - smart_table::spec_len(global<TreasuryState>(stablecoin_address).mint_allowances) == 1;

        ensures !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).controllers
            == old(global<TreasuryState>(stablecoin_address)).controllers;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The asset is paused.
    /// Abort condition: The caller is not a minter.
    /// Abort condition: The caller is blocklisted.
    /// Abort condition: Amount is not between [0, min(<caller's mint allowance>, MAX_U64)].
    /// [NOT PROVEN] Abort condition: The ConcurrentSupply feature is enabled, and aggregator_v2::try_add fails (overflow).
    /// Abort condition: The ConcurrentSupply feature is disabled, there is no max supply, and minting causes integer overflow.
    /// Abort condition: The ConcurrentSupply feature is disabled, there is a max supply, and minting exceeds the max supply.
    /// Post condition: A FungibleAsset with the correct data is returned.
    /// [PARTIAL] Post condition: Supply increases.
    /// Post condition: The minter's allowance decreased by the mint amount.
    /// Post condition: All other minters' allowances did not change.
    /// Post condition: All irrelevant states are unchanged.
    spec mint {
        // There are some abort conditions that are unspecified due to technical
        // limitations.
        pragma aborts_if_is_partial;

        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let minter = signer::address_of(caller);

        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if !exists<TreasuryState>(stablecoin_address);
        aborts_if !exists<ConcurrentSupply>(stablecoin_address) && !exists<Supply>(stablecoin_address);

        aborts_if global<PauseState>(stablecoin_address).paused;

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, minter);

        aborts_if table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, minter);

        aborts_if amount <= 0;
        aborts_if amount > smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter)
            || amount > MAX_U64;

        // This abort condition cannot be specified due to technical limitations, but
        // supply overflows have been generally unit tested.
        // aborts_if exists<ConcurrentSupply>(stablecoin_address) && aggregator_v2::try_add() == false;

        aborts_if !exists<ConcurrentSupply>(stablecoin_address)
            && exists<Supply>(stablecoin_address)
            && option::spec_is_none(global<Supply>(stablecoin_address).maximum)
            && (amount + global<Supply>(stablecoin_address).current) > MAX_U128;

        aborts_if !exists<ConcurrentSupply>(stablecoin_address)
            && exists<Supply>(stablecoin_address)
            && option::spec_is_some(global<Supply>(stablecoin_address).maximum)
            && (amount + global<Supply>(stablecoin_address).current)
                > option::spec_borrow(global<Supply>(stablecoin_address).maximum);

        ensures result
            == FungibleAsset {
                metadata: object::address_to_object<fungible_asset::Metadata>(stablecoin_address),
                amount
            };

        // This does not work, but supply updates have been generally unit tested.
        // ensures exists<ConcurrentSupply>(stablecoin_address) ==> aggregator_v2::read(global<ConcurrentSupply>(stablecoin_address).current)
        //     == old(aggregator_v2::read(global<ConcurrentSupply>(stablecoin_address).current)) + amount;
        ensures !exists<ConcurrentSupply>(stablecoin_address) && exists<Supply>(stablecoin_address) ==>
            global<Supply>(stablecoin_address).current == old(global<Supply>(stablecoin_address).current) + amount;

        ensures old(smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter))
            - smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, minter) == amount;

        ensures forall addr: address where addr != minter
            && smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, addr):
            old(smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, addr))
                == smart_table::spec_get(global<TreasuryState>(stablecoin_address).mint_allowances, addr);

        ensures global<TreasuryState>(stablecoin_address).master_minter
            == old(global<TreasuryState>(stablecoin_address)).master_minter;
        ensures global<TreasuryState>(stablecoin_address).controllers
            == old(global<TreasuryState>(stablecoin_address)).controllers;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The asset is paused.
    /// Abort condition: The caller is not a burner.
    /// Abort condition: The caller is blocklisted.
    /// Abort condition: The amount to burn is <= 0.
    /// Abort condition: The ConcurrentSupply feature is disabled, and the amount to burn exceed the current supply.
    /// [NOT PROVEN] Abort condition: The ConcurrentSupply feature is enabled, and aggregator_v2::try_sub fails (underflow).
    /// Abort condition: The BurnRef's metadata does not match the metadata of the FungibleAsset to burn.
    /// Post condition: There are no changes to TreasuryState.
    /// [PARTIAL] Post condition: Supply decreases.
    spec burn {
        // There are some abort conditions that are unspecified due to technical
        // limitations.
        pragma aborts_if_is_partial;

        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let burner = signer::address_of(caller);
        let amount = fungible_asset::amount(asset);

        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if !exists<TreasuryState>(stablecoin_address);
        aborts_if !exists<ConcurrentSupply>(stablecoin_address) && !exists<Supply>(stablecoin_address);

        aborts_if global<PauseState>(stablecoin_address).paused;

        aborts_if !smart_table::spec_contains(global<TreasuryState>(stablecoin_address).mint_allowances, burner);

        aborts_if table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, burner);

        aborts_if amount <= 0;
        aborts_if !exists<ConcurrentSupply>(stablecoin_address)
            && exists<Supply>(stablecoin_address)
            && amount > global<Supply>(stablecoin_address).current;

        // This abort condition cannot be specified due to technical limitations, but
        // supply underflows have been generally unit tested.
        // aborts_if exists<ConcurrentSupply>(stablecoin_address) && aggregator_v2::try_sub() == false;

        aborts_if fungible_asset::burn_ref_metadata(global<TreasuryState>(stablecoin_address).burn_ref)
            != fungible_asset::metadata_from_asset(asset);

        ensures global<TreasuryState>(stablecoin_address) == old(global<TreasuryState>(stablecoin_address));

        // This does not work, but supply updates have been generally unit tested.
        // ensures exists<ConcurrentSupply>(stablecoin_address) ==> aggregator_v2::read(global<ConcurrentSupply>(stablecoin_address).current)
        //     == old(aggregator_v2::read(global<ConcurrentSupply>(stablecoin_address).current)) - amount;
        ensures !exists<ConcurrentSupply>(stablecoin_address) && exists<Supply>(stablecoin_address) ==>
            global<Supply>(stablecoin_address).current == old(global<Supply>(stablecoin_address).current) - amount;
    }

    /// Abort condition: The required resources are missing.
    /// Abort condition: The caller is not the owner.
    /// Post condition: The master minter is updated.
    /// Post condition: All irrelevant states are unchanged.
    spec update_master_minter {
        let stablecoin_address = stablecoin::stablecoin_utils::spec_stablecoin_address();
        let caller = signer::address_of(caller);

        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<OwnerRole>(stablecoin_address) || !object::spec_exists_at<OwnerRole>(stablecoin_address);
        aborts_if !exists<TreasuryState>(stablecoin_address);

        aborts_if caller != global<OwnerRole>(stablecoin_address).owner;

        ensures global<TreasuryState>(stablecoin_address).master_minter == new_master_minter;

        ensures global<TreasuryState>(stablecoin_address).controllers
            == old(global<TreasuryState>(stablecoin_address)).controllers;
        ensures global<TreasuryState>(stablecoin_address).mint_allowances
            == old(global<TreasuryState>(stablecoin_address)).mint_allowances;
    }
}
