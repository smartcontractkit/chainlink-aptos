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

#[test_only]
module stablecoin::stablecoin_utils_tests {
    use aptos_framework::object;

    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::stablecoin_utils;

    const EXPECTED_STABLECOIN_OBJ_SEED: vector<u8> = b"stablecoin";

    #[test]
    fun stablecoin_obj_seed__should_return_expected_seed_value() {
        assert_eq(stablecoin_utils::stablecoin_obj_seed(), EXPECTED_STABLECOIN_OBJ_SEED);
    }

    #[test]
    fun stablecoin_address__should_return_expected_stablecoin_object_address() {
        // first verify that the configured stablecoin package address is the expected value (configured in the move.toml file)
        assert_eq(@stablecoin, @0x94ae22c4ecec81b458095a7ae2a5de2ac81d2bff9c8633e029194424e422db3b);

        // then compare the expected stablecoin object address with a pre-computed value.
        let expected_address = object::create_object_address(&@stablecoin, EXPECTED_STABLECOIN_OBJ_SEED);
        assert_eq(expected_address, @0xc6a3f2ea3a7abd98aebd8c2290648a4973ab6022cad2e88efd64fd3fb3bda245);

        // lastly, compare the expected stablecoin object address with the stablecoin_address function return value.
        assert_eq(stablecoin_utils::stablecoin_address(), expected_address);
    }
}
