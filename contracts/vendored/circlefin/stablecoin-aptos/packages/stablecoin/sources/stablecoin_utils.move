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

/// This module defines common utilities for the stablecoin module.
module stablecoin::stablecoin_utils {
    use aptos_framework::object;

    friend stablecoin::blocklistable;
    friend stablecoin::metadata;
    friend stablecoin::stablecoin;
    friend stablecoin::treasury;

    const STABLECOIN_OBJ_SEED: vector<u8> = b"stablecoin";

    /// Returns the stablecoin's named object seed value.
    public(friend) fun stablecoin_obj_seed(): vector<u8> {
        STABLECOIN_OBJ_SEED
    }

    /// Returns the stablecoin's object address.
    public(friend) fun stablecoin_address(): address {
        object::create_object_address(&@stablecoin, STABLECOIN_OBJ_SEED)
    }

    // === Test Only ===

    #[test_only]
    friend stablecoin::stablecoin_utils_tests;
    #[test_only]
    friend stablecoin::stablecoin_tests;
    #[test_only]
    friend stablecoin::stablecoin_e2e_tests;
    #[test_only]
    friend stablecoin::blocklistable_tests;
    #[test_only]
    friend stablecoin::treasury_tests;
    #[test_only]
    friend stablecoin::metadata_tests;
    #[test_only]
    friend stablecoin::fungible_asset_tests;
}
