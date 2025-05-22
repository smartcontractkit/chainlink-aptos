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

/// This module defines logic related to minting and burning units of a stablecoin,
/// as well as all role management and allowance configuration for privileged minters.
module stablecoin::treasury {
    use std::event;
    use std::option::{Self, Option};
    use std::signer;
    use std::smart_table::{Self, SmartTable};
    use aptos_framework::fungible_asset::{Self, BurnRef, FungibleAsset, MintRef};
    use aptos_framework::object::{Self, ConstructorRef};

    use aptos_extensions::ownable;
    use aptos_extensions::pausable;
    use stablecoin::blocklistable;
    use stablecoin::stablecoin_utils::stablecoin_address;

    friend stablecoin::stablecoin;

    // === Errors ===

    /// Address is not the master minter.
    const ENOT_MASTER_MINTER: u64 = 1;
    /// Address is not the controller.
    const ENOT_CONTROLLER: u64 = 2;
    /// Address is not a minter.
    const ENOT_MINTER: u64 = 3;
    /// Amount is zero.
    const EZERO_AMOUNT: u64 = 4;
    /// Insufficient minter allowance.
    const EINSUFFICIENT_ALLOWANCE: u64 = 5;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TreasuryState has key {
        /// The capability to mint units of a stablecoin.
        mint_ref: MintRef,
        /// The capability to burn units of a stablecoin.
        burn_ref: BurnRef,
        /// The address of the stablecoin's master minter.
        master_minter: address,
        /// Mapping containing controllers and the minter addresses they control.
        controllers: SmartTable<address, address>,
        /// Mapping containing minters and their mint allowance.
        mint_allowances: SmartTable<address, u64>
    }

    // === Events ===

    #[event]
    struct ControllerConfigured has drop, store {
        controller: address,
        minter: address
    }

    #[event]
    struct ControllerRemoved has drop, store {
        controller: address
    }

    #[event]
    struct MinterConfigured has drop, store {
        controller: address,
        minter: address,
        allowance: u64
    }

    #[event]
    struct MinterAllowanceIncremented has drop, store {
        controller: address,
        minter: address,
        allowance_increment: u64,
        new_allowance: u64
    }

    #[event]
    struct MinterRemoved has drop, store {
        controller: address,
        minter: address
    }

    #[event]
    struct Mint has drop, store {
        minter: address,
        amount: u64
    }

    #[event]
    struct Burn has drop, store {
        burner: address,
        amount: u64
    }

    #[event]
    struct MasterMinterChanged has drop, store {
        old_master_minter: address,
        new_master_minter: address
    }

    // === View-only functions ===

    #[view]
    /// Gets the master minter address of a stablecoin.
    public fun master_minter(): address acquires TreasuryState {
        borrow_global<TreasuryState>(stablecoin_address()).master_minter
    }

    #[view]
    /// Gets the minter address that a controller manages.
    /// Defaults to none if the address is not a controller.
    public fun get_minter(controller: address): Option<address> acquires TreasuryState {
        let treasury_state = borrow_global<TreasuryState>(stablecoin_address());
        if (!internal_is_controller(treasury_state, controller)) return option::none();
        option::some(internal_get_minter(treasury_state, controller))
    }

    #[view]
    /// Returns whether an address is a minter.
    public fun is_minter(minter: address): bool acquires TreasuryState {
        internal_is_minter(borrow_global<TreasuryState>(stablecoin_address()), minter)
    }

    #[view]
    /// Gets the mint allowance of a minter address.
    /// Defaults to zero if the address is not a minter.
    public fun mint_allowance(minter: address): u64 acquires TreasuryState {
        let treasury_state = borrow_global<TreasuryState>(stablecoin_address());
        if (!internal_is_minter(treasury_state, minter)) return 0;
        internal_get_mint_allowance(treasury_state, minter)
    }

    // === Write functions ===

    /// Creates new treasury state.
    public(friend) fun new(
        stablecoin_obj_constructor_ref: &ConstructorRef, master_minter: address
    ) {
        let stablecoin_obj_signer = &object::generate_signer(stablecoin_obj_constructor_ref);
        move_to(
            stablecoin_obj_signer,
            TreasuryState {
                mint_ref: fungible_asset::generate_mint_ref(stablecoin_obj_constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(stablecoin_obj_constructor_ref),
                master_minter,
                controllers: smart_table::new(),
                mint_allowances: smart_table::new()
            }
        );
    }

    /// Configures the controller for a minter.
    /// Each unique controller may only control one minter,
    /// but each minter may be controlled by multiple controllers.
    entry fun configure_controller(caller: &signer, controller: address, minter: address) acquires TreasuryState {
        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address());
        assert!(
            signer::address_of(caller) == treasury_state.master_minter,
            ENOT_MASTER_MINTER
        );

        smart_table::upsert(&mut treasury_state.controllers, controller, minter);

        event::emit(ControllerConfigured { controller, minter })
    }

    /// Removes a controller.
    entry fun remove_controller(caller: &signer, controller: address) acquires TreasuryState {
        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address());
        assert!(
            signer::address_of(caller) == treasury_state.master_minter,
            ENOT_MASTER_MINTER
        );
        assert!(internal_is_controller(treasury_state, controller), ENOT_CONTROLLER);

        smart_table::remove(&mut treasury_state.controllers, controller);

        event::emit(ControllerRemoved { controller })
    }

    /// Authorizes a minter address to mint and burn, and sets its allowance.
    /// Only callable by the minter's controller.
    entry fun configure_minter(caller: &signer, allowance: u64) acquires TreasuryState {
        let stablecoin_address = stablecoin_address();
        pausable::assert_not_paused(stablecoin_address);

        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address);

        let controller = signer::address_of(caller);
        assert!(internal_is_controller(treasury_state, controller), ENOT_CONTROLLER);

        let minter = internal_get_minter(treasury_state, controller);
        internal_set_mint_allowance(treasury_state, minter, allowance);

        event::emit(MinterConfigured { controller, minter, allowance })
    }

    /// Increment the mint allowance for a minter.
    /// Only callable by the minter's controller.
    entry fun increment_minter_allowance(caller: &signer, allowance_increment: u64) acquires TreasuryState {
        let stablecoin_address = stablecoin_address();
        pausable::assert_not_paused(stablecoin_address);
        assert!(allowance_increment != 0, EZERO_AMOUNT);

        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address);

        let controller = signer::address_of(caller);
        assert!(internal_is_controller(treasury_state, controller), ENOT_CONTROLLER);

        let minter = internal_get_minter(treasury_state, controller);
        assert!(internal_is_minter(treasury_state, minter), ENOT_MINTER);

        let new_allowance = internal_get_mint_allowance(treasury_state, minter) + allowance_increment;
        internal_set_mint_allowance(treasury_state, minter, new_allowance);

        event::emit(
            MinterAllowanceIncremented { controller, minter, allowance_increment, new_allowance }
        )
    }

    /// Removes a minter.
    /// Only callable by the minter's controller.
    entry fun remove_minter(caller: &signer) acquires TreasuryState {
        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address());

        let controller = signer::address_of(caller);
        assert!(internal_is_controller(treasury_state, controller), ENOT_CONTROLLER);

        let minter = internal_get_minter(treasury_state, controller);
        assert!(internal_is_minter(treasury_state, minter), ENOT_MINTER);

        smart_table::remove(&mut treasury_state.mint_allowances, minter);

        event::emit(MinterRemoved { controller, minter })
    }

    /// Mints an amount of Fungible Asset (limited to the minter's allowance)
    /// and returns the minted asset, increasing the total supply
    /// and decreasing the minter's allowance.
    public fun mint(caller: &signer, amount: u64): FungibleAsset acquires TreasuryState {
        let stablecoin_address = stablecoin_address();
        assert!(amount != 0, EZERO_AMOUNT);
        pausable::assert_not_paused(stablecoin_address);

        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address);

        let minter = signer::address_of(caller);
        assert!(internal_is_minter(treasury_state, minter), ENOT_MINTER);
        blocklistable::assert_not_blocklisted(minter);

        let mint_allowance = internal_get_mint_allowance(treasury_state, minter);
        assert!(mint_allowance >= amount, EINSUFFICIENT_ALLOWANCE);

        let asset = fungible_asset::mint(&treasury_state.mint_ref, amount);
        internal_set_mint_allowance(treasury_state, minter, mint_allowance - amount);

        event::emit(Mint { minter, amount });

        asset
    }

    /// Burns an amount of Fungible Asset, decreasing the total supply.
    public fun burn(caller: &signer, asset: FungibleAsset) acquires TreasuryState {
        let stablecoin_address = stablecoin_address();
        let amount = fungible_asset::amount(&asset);
        assert!(amount != 0, EZERO_AMOUNT);
        pausable::assert_not_paused(stablecoin_address);

        let treasury_state = borrow_global<TreasuryState>(stablecoin_address);

        let burner = signer::address_of(caller);
        assert!(internal_is_minter(treasury_state, burner), ENOT_MINTER);
        blocklistable::assert_not_blocklisted(burner);

        fungible_asset::burn(&treasury_state.burn_ref, asset);

        event::emit(Burn { burner, amount })
    }

    /// Update master minter role
    entry fun update_master_minter(caller: &signer, new_master_minter: address) acquires TreasuryState {
        let stablecoin_address = stablecoin_address();
        ownable::assert_is_owner(caller, stablecoin_address);

        let treasury_state = borrow_global_mut<TreasuryState>(stablecoin_address);
        let old_master_minter = treasury_state.master_minter;
        treasury_state.master_minter = new_master_minter;

        event::emit(MasterMinterChanged { old_master_minter, new_master_minter });
    }

    // === Aliases ===

    inline fun internal_get_minter(treasury_state: &TreasuryState, controller: address): address {
        *smart_table::borrow(&treasury_state.controllers, controller)
    }

    inline fun internal_is_controller(treasury_state: &TreasuryState, controller: address): bool {
        smart_table::contains(&treasury_state.controllers, controller)
    }

    inline fun internal_is_minter(treasury_state: &TreasuryState, minter: address): bool {
        smart_table::contains(&treasury_state.mint_allowances, minter)
    }

    inline fun internal_get_mint_allowance(treasury_state: &TreasuryState, minter: address): u64 {
        *smart_table::borrow(&treasury_state.mint_allowances, minter)
    }

    inline fun internal_set_mint_allowance(
        treasury_state: &mut TreasuryState, minter: address, mint_allowance: u64
    ) {
        smart_table::upsert(&mut treasury_state.mint_allowances, minter, mint_allowance);
    }

    // === Test Only ===

    #[test_only]
    use aptos_framework::object::Object;

    #[test_only]
    use aptos_framework::fungible_asset::Metadata;

    #[test_only]
    public fun new_for_testing(
        stablecoin_obj_constructor_ref: &ConstructorRef, master_minter: address
    ) {
        new(stablecoin_obj_constructor_ref, master_minter);
    }

    #[test_only]
    public fun mint_ref_metadata_for_testing(): Object<Metadata> acquires TreasuryState {
        fungible_asset::mint_ref_metadata(
            &borrow_global<TreasuryState>(stablecoin_address()).mint_ref
        )
    }

    #[test_only]
    public fun test_mint(amount: u64): FungibleAsset acquires TreasuryState {
        fungible_asset::mint(&borrow_global<TreasuryState>(stablecoin_address()).mint_ref, amount)
    }

    #[test_only]
    public fun burn_ref_metadata_for_testing(): Object<Metadata> acquires TreasuryState {
        fungible_asset::burn_ref_metadata(
            &borrow_global<TreasuryState>(stablecoin_address()).burn_ref
        )
    }

    #[test_only]
    public fun test_burn(asset: FungibleAsset) acquires TreasuryState {
        fungible_asset::burn(&borrow_global<TreasuryState>(stablecoin_address()).burn_ref, asset)
    }

    #[test_only]
    public fun num_controllers_for_testing(): u64 acquires TreasuryState {
        smart_table::length(&borrow_global<TreasuryState>(stablecoin_address()).controllers)
    }

    #[test_only]
    public fun num_mint_allowances_for_testing(): u64 acquires TreasuryState {
        smart_table::length(&borrow_global<TreasuryState>(stablecoin_address()).mint_allowances)
    }

    #[test_only]
    public fun set_master_minter_for_testing(master_minter: address) acquires TreasuryState {
        borrow_global_mut<TreasuryState>(stablecoin_address()).master_minter = master_minter;
    }

    #[test_only]
    public fun is_controller_for_testing(controller: address): bool acquires TreasuryState {
        internal_is_controller(borrow_global<TreasuryState>(stablecoin_address()), controller)
    }

    #[test_only]
    public fun force_configure_controller_for_testing(controller: address, minter: address) acquires TreasuryState {
        let controllers = &mut borrow_global_mut<TreasuryState>(stablecoin_address()).controllers;
        smart_table::upsert(controllers, controller, minter);
    }

    #[test_only]
    public fun force_remove_controller_for_testing(controller: address) acquires TreasuryState {
        let controllers = &mut borrow_global_mut<TreasuryState>(stablecoin_address()).controllers;
        if (smart_table::contains(controllers, controller)) {
            smart_table::remove(controllers, controller);
        }
    }

    #[test_only]
    public fun force_configure_minter_for_testing(minter: address, mint_allowance: u64) acquires TreasuryState {
        let mint_allowances = &mut borrow_global_mut<TreasuryState>(stablecoin_address()).mint_allowances;
        smart_table::upsert(mint_allowances, minter, mint_allowance);
    }

    #[test_only]
    public fun force_remove_minter_for_testing(minter: address) acquires TreasuryState {
        let mint_allowances = &mut borrow_global_mut<TreasuryState>(stablecoin_address()).mint_allowances;
        if (smart_table::contains(mint_allowances, minter)) {
            smart_table::remove(mint_allowances, minter);
        }
    }

    #[test_only]
    public fun test_configure_controller(caller: &signer, controller: address, minter: address) acquires TreasuryState {
        configure_controller(caller, controller, minter)
    }

    #[test_only]
    public fun test_remove_controller(caller: &signer, controller: address) acquires TreasuryState {
        remove_controller(caller, controller)
    }

    #[test_only]
    public fun test_configure_minter(caller: &signer, allowance: u64) acquires TreasuryState {
        configure_minter(caller, allowance)
    }

    #[test_only]
    public fun test_increment_minter_allowance(caller: &signer, allowance_increment: u64) acquires TreasuryState {
        increment_minter_allowance(caller, allowance_increment)
    }

    #[test_only]
    public fun test_remove_minter(caller: &signer) acquires TreasuryState {
        remove_minter(caller)
    }

    #[test_only]
    public fun test_ControllerConfigured_event(controller: address, minter: address): ControllerConfigured {
        ControllerConfigured { controller, minter }
    }

    #[test_only]
    public fun test_ControllerRemoved_event(controller: address): ControllerRemoved {
        ControllerRemoved { controller }
    }

    #[test_only]
    public fun test_MinterConfigured_event(controller: address, minter: address, allowance: u64): MinterConfigured {
        MinterConfigured { controller, minter, allowance }
    }

    #[test_only]
    public fun test_MinterAllowanceIncremented_event(
        controller: address,
        minter: address,
        allowance_increment: u64,
        new_allowance: u64
    ): MinterAllowanceIncremented {
        MinterAllowanceIncremented { controller, minter, allowance_increment, new_allowance }
    }

    #[test_only]
    public fun test_MinterRemoved_event(controller: address, minter: address): MinterRemoved {
        MinterRemoved { controller, minter }
    }

    #[test_only]
    public fun test_Mint_event(minter: address, amount: u64): Mint {
        Mint { minter, amount }
    }

    #[test_only]
    public fun test_Burn_event(burner: address, amount: u64): Burn {
        Burn { burner, amount }
    }

    #[test_only]
    public fun test_update_master_minter(caller: &signer, new_master_minter: address) acquires TreasuryState {
        update_master_minter(caller, new_master_minter);
    }

    #[test_only]
    public fun test_MasterMinterChanged_event(
        old_master_minter: address, new_master_minter: address
    ): MasterMinterChanged {
        MasterMinterChanged { old_master_minter, new_master_minter }
    }
}
