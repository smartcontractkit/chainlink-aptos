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

spec stablecoin::stablecoin {
    use std::signer;
    use std::table_with_length;
    use aptos_framework::object::ObjectCore;
    use aptos_framework::fungible_asset::{ConcurrentFungibleBalance, FungibleStore, Metadata, Untransferable};
    use aptos_framework::primary_fungible_store::DeriveRefPod;
    use aptos_extensions::ownable::OwnerRole;
    use aptos_extensions::pausable::PauseState;
    use aptos_extensions::manageable::AdminRole;
    use stablecoin::blocklistable::BlocklistState;
    use stablecoin::metadata::{MetadataState, ValidateMetadataMutation};
    use stablecoin::stablecoin_utils::spec_stablecoin_address;
    use stablecoin::treasury::TreasuryState;

    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: Never aborts.
    /// Post condition: The stablecoin address is returned as defined by the stablecoin_utils module.
    spec stablecoin_address(): address {
        aborts_if false;
        ensures result == spec_stablecoin_address();
    }

    /// Abort condition: Any of the resources to initialize already exists at the stablecoin address.
    /// Abort condition: Any of the resources to initialize already exists at the package address.
    /// Post condition: The stablecoin address is always initialized with the expected resources.
    /// Post condition: The package address is always initialized with the expected resources.
    spec init_module {
        /// The list of abort conditions here intentionally does not enumerate through the 
        /// abort conditions that happens from calling the underlying framework functions
        /// to avoid an unnecessary long proof. Only the key conditions are proved here.
        pragma aborts_if_is_partial;

        requires signer::address_of(resource_acct_signer) == @stablecoin;

        let stablecoin_address = spec_stablecoin_address();
        aborts_if exists<ObjectCore>(stablecoin_address);
        aborts_if exists<Metadata>(stablecoin_address);
        aborts_if exists<Untransferable>(stablecoin_address);
        aborts_if exists<OwnerRole>(stablecoin_address);
        aborts_if exists<PauseState>(stablecoin_address);
        aborts_if exists<MetadataState>(stablecoin_address);
        aborts_if exists<BlocklistState>(stablecoin_address);
        aborts_if exists<TreasuryState>(stablecoin_address);
        aborts_if exists<StablecoinState>(stablecoin_address);
        aborts_if exists<DeriveRefPod>(stablecoin_address);
        aborts_if exists<manageable::AdminRole>(@stablecoin);
        aborts_if exists<upgradable::SignerCapStore>(@stablecoin);

        ensures exists<ObjectCore>(stablecoin_address);
        ensures exists<Metadata>(stablecoin_address);
        ensures exists<Untransferable>(stablecoin_address);
        ensures exists<OwnerRole>(stablecoin_address);
        ensures exists<PauseState>(stablecoin_address);
        ensures exists<MetadataState>(stablecoin_address);
        ensures exists<BlocklistState>(stablecoin_address);
        ensures exists<TreasuryState>(stablecoin_address);
        ensures exists<StablecoinState>(stablecoin_address);
        ensures exists<DeriveRefPod>(stablecoin_address);
        ensures exists<manageable::AdminRole>(@stablecoin);
        ensures exists<upgradable::SignerCapStore>(@stablecoin);
    }

    /// Abort condition: The AdminRole resource is missing.
    /// Abort condition: The caller is not the stablecoin admin address.
    /// Abort condition: The stablecoin address is not a valid object address.
    /// Abort condition: The StablecoinState resource is missing.
    /// Abort condition: The StablecoinState resource has already been initialized.
    /// Abort condition: The MetadataState resource is missing.
    /// Abort condition: The Metadata resource is missing.
    /// Abort condition: The metadata inputs are invalid.
    /// Post condition: The Metadata resource is always updated with the expected fields.
    /// Post condition: The StablecoinState resource is always initialized with the expected version.
    spec initialize_v1 {
        let stablecoin_address = spec_stablecoin_address();

        aborts_if !exists<AdminRole>(@stablecoin);
        aborts_if signer::address_of(caller) != global<AdminRole>(@stablecoin).admin;
        aborts_if !exists<ObjectCore>(stablecoin_address);
        aborts_if !exists<StablecoinState>(stablecoin_address);
        aborts_if global<StablecoinState>(stablecoin_address).initialized_version != 0;
        aborts_if !exists<MetadataState>(stablecoin_address);
        aborts_if !exists<Metadata>(stablecoin_address) || !object::spec_exists_at<Metadata>(stablecoin_address);

        include ValidateMetadataMutation {
            name: option::spec_some(name),
            symbol: option::spec_some(symbol),
            decimals: option::spec_some(decimals),
            icon_uri: option::spec_some(icon_uri),
            project_uri: option::spec_some(project_uri)
        };

        ensures global<StablecoinState>(stablecoin_address).initialized_version == 1;
    }

    /// Pre-condition: The stablecoin address is a valid object address.
    /// Pre-condition: FungibleStore already exists at the stablecoin address.
    /// Abort condition: The PauseState resource is missing.
    /// Abort condition: The BlocklistState is missing.
    /// Abort condition: The asset is paused.
    /// Abort condition: The fungible store's owner is blocklisted.
    /// Abort condition: The transfer ref metadata does not match store metadata.
    /// Abort condition: The transfer ref metadata does not match fungible asset metadata.
    /// Abort condition: The concurrent balance is not used, and balance + deposit amount exceeds u64 max.
    /// [NOT PROVEN] Abort condition: The concurrent balance is used, and balance + deposit amount exceeds u64 max.
    /// Post condition: The fungible store balance is always increased by the deposit amount if the concurrent balance feature is not used by the store.
    /// [NOT PROVEN] Post condition: The fungible store balance is always increased by the deposit amount if the concurrent balance feature is used by the store.
    spec override_deposit {
        /// There are some abort conditions that are unspecified due to technical
        /// limitations.
        pragma aborts_if_is_partial;

        let store_address = object::object_address(store);
        let metadata = fungible_asset::store_metadata(store);
        let stablecoin_address = spec_stablecoin_address();
        let deposit_amount = fungible_asset::amount(fa);

        requires exists<ObjectCore>(store_address);
        requires exists<FungibleStore>(store_address);
        
        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if global<PauseState>(stablecoin_address).paused == true;
        aborts_if table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, object::owner(store));
        aborts_if transfer_ref.metadata != fungible_asset::store_metadata(store);
        aborts_if transfer_ref.metadata != fungible_asset::asset_metadata(fa);
        aborts_if global<FungibleStore>(store_address).balance > MAX_U64 - deposit_amount;

        // Cannot be proved - If the concurrent balance feature is enabled, balance is always increased by the deposit amount.

        // If store balance is not zero and the concurrent balance feature is not enabled, balance is always increased by the deposit amount.
        ensures (global<FungibleStore>(store_address).balance != 0
            || !exists<ConcurrentFungibleBalance>(store_address)) ==>
            global<FungibleStore>(store_address).balance
                == old(global<FungibleStore>(store_address).balance) + deposit_amount;
    }

    /// Pre-condition: The stablecoin address is a valid object address.
    /// Pre-condition: FungibleStore already exists at the stablecoin address.
    /// Abort condition: The PauseState resource is missing.
    /// Abort condition: The BlocklistState resource is missing.
    /// Abort condition: The asset is paused.
    /// Abort condition: The fungible store's owner is blocklisted.
    /// Abort condition: The transfer ref metadata does not match store metadata.
    /// Abort condition: The concurrent balance is not used, amount to withdraw exceeds store balance.
    /// [NOT PROVEN] Abort condition: The concurrent balance is used, amount to withdraw exceeds store balance.
    /// Post condition: The fungible store balance is always decreased by the withdrawal amount if the concurrent balance feature is not used by the store.
    /// [NOT PROVEN]: The fungible store balance is always decreased by the withdrawal amount if the concurrent balance feature is used by the store.
    /// Post condition: The fungible asset is always returned with the expected metadata and amount.
    spec override_withdraw {
        /// There are some abort conditions that are unspecified due to technical
        /// limitations.
        pragma aborts_if_is_partial;

        let store_address = object::object_address(store);
        let metadata = fungible_asset::store_metadata(store);
        let stablecoin_address = spec_stablecoin_address();

        requires exists<ObjectCore>(store_address);
        requires exists<FungibleStore>(store_address);

        aborts_if !exists<PauseState>(stablecoin_address) || !object::spec_exists_at<PauseState>(stablecoin_address);
        aborts_if !exists<BlocklistState>(stablecoin_address);
        aborts_if global<PauseState>(stablecoin_address).paused == true;
        aborts_if table_with_length::spec_contains(global<BlocklistState>(stablecoin_address).blocklist, object::owner(store));
        aborts_if transfer_ref.metadata != fungible_asset::store_metadata(store);
        aborts_if (
            global<FungibleStore>(store_address).balance != 0 || !exists<ConcurrentFungibleBalance>(store_address)
        ) && global<FungibleStore>(store_address).balance < amount;

        // Cannot be proved - if the concurrent balance feature is enabled, amount that exceeds current balance will trigger abort due to underflow.
        // Cannot be proved - if the concurrent balance feature is enabled, balance is always decreased by the amount.

        // If store balance is not zero and the concurrent balance feature is not enabled, balance is always decreased by the amount.
        ensures (global<FungibleStore>(store_address).balance == 0
            && exists<ConcurrentFungibleBalance>(store_address))
            || global<FungibleStore>(store_address).balance
                == old(global<FungibleStore>(store_address).balance) - amount;

        ensures result == FungibleAsset { metadata: transfer_ref.metadata, amount };
    }
}
