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

spec stablecoin::stablecoin_utils {
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    /// Abort condition: Never aborts.
    spec stablecoin_obj_seed(): vector<u8> {
        aborts_if false;
        ensures result == b"stablecoin";
    }

    /// Abort condition: Never aborts.
    spec stablecoin_address(): address {
        aborts_if false;
        ensures result == spec_stablecoin_address();
    }

    /// Helper function to calculate stablecoin object address
    spec fun spec_stablecoin_address(): address {
        object::spec_create_object_address(@stablecoin, stablecoin_obj_seed())
    }
}
