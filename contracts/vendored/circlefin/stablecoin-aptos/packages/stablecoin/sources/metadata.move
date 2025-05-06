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

/// This module defines logic for managing the metadata of a stablecoin.
module stablecoin::metadata {
    use std::event;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::String;
    use aptos_framework::fungible_asset::{Self, Metadata, MutateMetadataRef};
    use aptos_framework::object::{Self, ConstructorRef};

    use aptos_extensions::ownable;
    use stablecoin::stablecoin_utils::stablecoin_address;

    friend stablecoin::stablecoin;

    // === Errors ===

    /// Address is not the metadata_updater.
    const ENOT_METADATA_UPDATER: u64 = 1;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct MetadataState has key {
        /// The capability to mutate the metadata of a stablecoin.
        mutate_metadata_ref: MutateMetadataRef,
        /// The address of the stablecoin's metadata updater.
        metadata_updater: address
    }

    // === Events ===

    #[event]
    struct MetadataUpdated has drop, store {
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    }

    #[event]
    struct MetadataUpdaterChanged has drop, store {
        old_metadata_updater: address,
        new_metadata_updater: address
    }

    // === View-only functions ===

    #[view]
    /// Gets the metadata updater address of a stablecoin.
    public fun metadata_updater(): address acquires MetadataState {
        borrow_global<MetadataState>(stablecoin_address()).metadata_updater
    }

    // === Write functions ===

    /// Creates new metadata state.
    public(friend) fun new(
        stablecoin_obj_constructor_ref: &ConstructorRef, metadata_updater: address
    ) {
        let stablecoin_obj_signer = &object::generate_signer(stablecoin_obj_constructor_ref);
        move_to(
            stablecoin_obj_signer,
            MetadataState {
                mutate_metadata_ref: fungible_asset::generate_mutate_metadata_ref(stablecoin_obj_constructor_ref),
                metadata_updater
            }
        );
    }

    /// Updates the FungibleAsset metadata
    entry fun update_metadata(
        caller: &signer,
        name: Option<String>,
        symbol: Option<String>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) acquires MetadataState {
        let metadata_state = borrow_global<MetadataState>(stablecoin_address());
        assert!(
            signer::address_of(caller) == metadata_state.metadata_updater,
            ENOT_METADATA_UPDATER
        );
        mutate_asset_metadata(name, symbol, option::none(), icon_uri, project_uri);
    }

    /// Mutates the FungibleAsset metadata
    public(friend) fun mutate_asset_metadata(
        name: Option<String>,
        symbol: Option<String>,
        decimals: Option<u8>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) acquires MetadataState {
        let stablecoin_address = stablecoin_address();
        let metadata_state = borrow_global<MetadataState>(stablecoin_address);
        fungible_asset::mutate_metadata(
            &metadata_state.mutate_metadata_ref,
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );
        let metadata = object::address_to_object<Metadata>(stablecoin_address);
        event::emit(
            MetadataUpdated {
                name: fungible_asset::name(metadata),
                symbol: fungible_asset::symbol(metadata),
                decimals: fungible_asset::decimals(metadata),
                icon_uri: fungible_asset::icon_uri(metadata),
                project_uri: fungible_asset::project_uri(metadata)
            }
        );
    }

    /// Update metadata updater role
    entry fun update_metadata_updater(caller: &signer, new_metadata_updater: address) acquires MetadataState {
        let stablecoin_address = stablecoin_address();
        ownable::assert_is_owner(caller, stablecoin_address);

        let metadata_state = borrow_global_mut<MetadataState>(stablecoin_address);
        let old_metadata_updater = metadata_state.metadata_updater;
        metadata_state.metadata_updater = new_metadata_updater;

        event::emit(MetadataUpdaterChanged { old_metadata_updater, new_metadata_updater });
    }

    // === Test Only ===

    #[test_only]
    use aptos_framework::object::Object;

    #[test_only]
    public fun new_for_testing(
        stablecoin_obj_constructor_ref: &ConstructorRef, metadata_updater: address
    ) {
        new(stablecoin_obj_constructor_ref, metadata_updater);
    }

    #[test_only]
    public fun mutate_metadata_ref_metadata_for_testing(): Object<Metadata> acquires MetadataState {
        fungible_asset::object_from_metadata_ref(
            &borrow_global<MetadataState>(stablecoin_address()).mutate_metadata_ref
        )
    }

    #[test_only]
    public fun set_metadata_updater_for_testing(metadata_updater: address) acquires MetadataState {
        borrow_global_mut<MetadataState>(stablecoin_address()).metadata_updater = metadata_updater;
    }

    #[test_only]
    public fun test_update_metadata(
        caller: &signer,
        name: Option<String>,
        symbol: Option<String>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) acquires MetadataState {
        update_metadata(caller, name, symbol, icon_uri, project_uri);
    }

    #[test_only]
    public fun test_mutate_asset_metadata(
        name: Option<String>,
        symbol: Option<String>,
        decimals: Option<u8>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) acquires MetadataState {
        mutate_asset_metadata(name, symbol, decimals, icon_uri, project_uri);
    }

    #[test_only]
    public fun test_MetadataUpdated_event(
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    ): MetadataUpdated {
        MetadataUpdated { name, symbol, decimals, icon_uri, project_uri }
    }

    #[test_only]
    public fun test_update_metadata_updater(caller: &signer, new_metadata_updater: address) acquires MetadataState {
        update_metadata_updater(caller, new_metadata_updater);
    }

    #[test_only]
    public fun test_MetadataUpdaterChanged_event(
        old_metadata_updater: address, new_metadata_updater: address
    ): MetadataUpdaterChanged {
        MetadataUpdaterChanged { old_metadata_updater, new_metadata_updater }
    }
}
