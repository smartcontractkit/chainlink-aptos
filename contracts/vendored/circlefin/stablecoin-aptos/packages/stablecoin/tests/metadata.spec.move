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

spec stablecoin::metadata {
    use std::string;
    use aptos_framework::object::ObjectCore;
    use aptos_extensions::ownable::OwnerRole;
    use stablecoin::stablecoin_utils::spec_stablecoin_address;

    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;

        invariant forall addr: address where exists<MetadataState>(addr):
            object::object_address(global<MetadataState>(addr).mutate_metadata_ref.metadata) == addr;
    }

    /// Abort condition: The MetadataState resource is missing.
    /// Post condition: The metadata updater address is always returned.
    /// Post condition: The MetadataState resource is unchanged.
    spec metadata_updater {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<MetadataState>(stablecoin_address);
        ensures result == global<MetadataState>(stablecoin_address).metadata_updater;
        ensures global<MetadataState>(stablecoin_address) == old(global<MetadataState>(stablecoin_address));
    }

    /// Abort condition: The object does not exist at the stablecoin address.
    /// Abort condition: The Metadata resource is missing.
    /// Abort condition: The MetadataState resource already exists at the stablecoin address.
    /// Post condition: The MetadataState resource is created properly.
    spec new {
        let stablecoin_address = object::address_from_constructor_ref(stablecoin_obj_constructor_ref);
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !object::spec_exists_at<Metadata>(stablecoin_address);
        aborts_if exists<MetadataState>(stablecoin_address);
        ensures exists<MetadataState>(stablecoin_address);
        ensures global<MetadataState>(stablecoin_address).metadata_updater == metadata_updater;
        ensures global<MetadataState>(stablecoin_address).mutate_metadata_ref
            == MutateMetadataRef {
                metadata: object::address_to_object<Metadata>(stablecoin_address)
            };
    }

    /// Abort condition: The object does not exist at the stablecoin address.
    /// Abort condition: The MetadataState resource is missing.
    /// Abort condition: The fungible asset Metadata resource is missing.
    /// Abort condition: The caller is not metadata updater address.
    /// Abort condition: The metadata fields are invalid.
    /// Post condition: Metadata fields are updated for specified fields.
    spec update_metadata {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<MetadataState>(stablecoin_address);
        aborts_if !exists<Metadata>(stablecoin_address) || !object::spec_exists_at<Metadata>(stablecoin_address);
        aborts_if signer::address_of(caller) != global<MetadataState>(stablecoin_address).metadata_updater;
        include ValidateMetadataMutation { name, symbol, decimals: option::none(), icon_uri, project_uri };
    }

    /// Abort condition: The object does not exist at the stablecoin address.
    /// Abort condition: The MetadataState resource is missing.
    /// Abort condition: The fungible asset Metadata resource is missing.
    /// Abort condition: The metadata fields are invalid.
    /// Post condition: The metadata fields are always updated for specified fields.
    spec mutate_asset_metadata {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<MetadataState>(stablecoin_address);
        aborts_if !exists<Metadata>(stablecoin_address) || !object::spec_exists_at<Metadata>(stablecoin_address);
        include ValidateMetadataMutation;
    }

    /// Abort condition: The object does not exist at the stablecoin address.
    /// Abort condition: The OwnerRole resources is missing.
    /// Abort condition: The MetadataState resources is missing.
    /// Abort condition: The caller is not the owner address.
    /// Post condition: The metadata updater is always updated.
    /// Post condition: The MetadataState mutate_metadata_ref is unchanged.
    spec update_metadata_updater {
        let stablecoin_address = spec_stablecoin_address();
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<OwnerRole>(stablecoin_address) || !object::spec_exists_at<OwnerRole>(stablecoin_address);
        aborts_if !exists<MetadataState>(stablecoin_address);
        aborts_if signer::address_of(caller) != global<OwnerRole>(stablecoin_address).owner;
        ensures global<MetadataState>(stablecoin_address).metadata_updater == new_metadata_updater;
        ensures global<MetadataState>(stablecoin_address).mutate_metadata_ref
            == old(global<MetadataState>(stablecoin_address).mutate_metadata_ref);
    }

    /// Helper function to check metadata fields
    spec schema ValidateMetadataMutation {
        name: Option<String>;
        symbol: Option<String>;
        decimals: Option<u8>;
        icon_uri: Option<String>;
        project_uri: Option<String>;

        let max_name_length = 32;
        let max_symbol_length = 10;
        let max_decimals = 32;
        let max_uri_length = 512;

        aborts_if name != option::spec_none() && string::length(option::borrow(name)) > max_name_length;
        aborts_if symbol != option::spec_none() && string::length(option::borrow(symbol)) > max_symbol_length;
        aborts_if decimals != option::spec_none() && option::borrow(decimals) > max_decimals;
        aborts_if icon_uri != option::spec_none() && string::length(option::borrow(icon_uri)) > max_uri_length;
        aborts_if project_uri != option::spec_none() && string::length(option::borrow(project_uri)) > max_uri_length;

        let stablecoin_address = spec_stablecoin_address();

        // Ensures metadata fields that are specified are updated

        ensures option::spec_is_some(name) ==>
            global<Metadata>(stablecoin_address).name == option::borrow(name);
        ensures option::spec_is_none(name) ==>
            global<Metadata>(stablecoin_address).name == old(global<Metadata>(stablecoin_address).name);
        ensures option::spec_is_some(symbol) ==>
            global<Metadata>(stablecoin_address).symbol == option::borrow(symbol);
        ensures option::spec_is_none(symbol) ==>
            global<Metadata>(stablecoin_address).symbol == old(global<Metadata>(stablecoin_address).symbol);
        ensures option::spec_is_some(decimals) ==>
            global<Metadata>(stablecoin_address).decimals == option::borrow(decimals);
        ensures option::spec_is_none(decimals) ==>
            global<Metadata>(stablecoin_address).decimals == old(global<Metadata>(stablecoin_address).decimals);
        ensures option::spec_is_some(icon_uri) ==>
            global<Metadata>(stablecoin_address).icon_uri == option::borrow(icon_uri);
        ensures option::spec_is_none(icon_uri) ==>
            global<Metadata>(stablecoin_address).icon_uri == old(global<Metadata>(stablecoin_address).icon_uri);
        ensures option::spec_is_some(project_uri) ==>
            global<Metadata>(stablecoin_address).project_uri == option::borrow(project_uri);
        ensures option::spec_is_none(project_uri) ==>
            global<Metadata>(stablecoin_address).project_uri == old(global<Metadata>(stablecoin_address).project_uri);
    }
}
