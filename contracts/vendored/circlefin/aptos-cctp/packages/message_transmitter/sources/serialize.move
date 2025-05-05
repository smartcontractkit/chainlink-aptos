/// Copyright (c) 2024, Circle Internet Group, Inc.
/// All rights reserved.
///
/// SPDX-License-Identifier: Apache-2.0
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
/// http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

/// Module for implementing serialization based on big-endian encoding (to be compatible with other CCTP contracts).
/// std::bcs use little-endian encoding
module message_transmitter::serialize {
    // Built-in Modules
    use std::bcs;
    use std::vector;

    public fun serialize_u32(num: u32): vector<u8> {
        let serialized = bcs::to_bytes(&num);
        vector::reverse(&mut serialized);
        serialized
    }

    public fun serialize_u64(num: u64): vector<u8> {
        let serialized = bcs::to_bytes(&num);
        vector::reverse(&mut serialized);
        serialized
    }

    public fun serialize_u256(num: u256): vector<u8> {
        let serialized = bcs::to_bytes(&num);
        vector::reverse(&mut serialized);
        serialized
    }

    public fun serialize_address(address: address): vector<u8> {
        bcs::to_bytes(&address)
    }

    #[test]
    fun test_serialize_u32() {
        let num: u32 = 1234;
        let expected = bcs::to_bytes(&num);
        vector::reverse(&mut expected);

        let result = serialize_u32(num);
        assert!(expected == result, 0);
    }

    #[test]
    fun test_serialize_u64() {
        let num: u64 = 123456789;
        let expected = bcs::to_bytes(&num);
        vector::reverse(&mut expected);

        let result = serialize_u64(num);
        assert!(expected == result, 0);
    }

    #[test]
    fun test_serialize_u256() {
        let num: u256 = 123456789123456789123456789;
        let expected = bcs::to_bytes(&num);
        vector::reverse(&mut expected);

        let result = serialize_u256(num);
        assert!(expected == result, 0);
    }

    #[test]
    fun test_serialize_address() {
        let address: address = @0xa9fb1b3009dcb79e2fe346c16a604b8fa8ae0a79;
        let expected = bcs::to_bytes(&address);

        let result = serialize_address(address);
        assert!(expected == result, 0);
    }
}
