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
module aptos_extensions::test_utils {
    use std::string;
    use aptos_std::debug;
    use aptos_std::string_utils::format2;
    use aptos_framework::object;

    /// Error thrown when assertion fails.
    const ERROR_FAILED_ASSERTION: u64 = 0;

    const RANDOM_ADDRESS: address = @0x10;

    struct CustomResource has key {}

    public fun assert_eq<T: drop>(a: T, b: T) {
        internal_assert_eq(a, b, true /* debug */)
    }

    public fun assert_neq<T: drop>(a: T, b: T) {
        internal_assert_neq(a, b, true /* debug */)
    }

    public fun create_and_move_custom_resource(): (signer, address) {
        let constructor_ref = object::create_sticky_object(RANDOM_ADDRESS);
        let obj_address = object::address_from_constructor_ref(&constructor_ref);
        let signer = object::generate_signer(&constructor_ref);
        move_to(&signer, CustomResource {});
        (signer, obj_address)
    }

    fun internal_assert_eq<T: drop>(a: T, b: T, debug: bool) {
        if (&a == &b) {
            return
        };
        if (debug) {
            debug::print(&format2(&b"[FAILED_ASSERTION] assert_eq({}, {})", a, b));
        };
        abort ERROR_FAILED_ASSERTION
    }

    fun internal_assert_neq<T: drop>(a: T, b: T, debug: bool) {
        if (&a != &b) {
            return
        };
        if (debug) {
            debug::print(&format2(&b"[FAILED_ASSERTION] assert_neq({}, {})", a, b));
        };
        abort ERROR_FAILED_ASSERTION
    }

    #[test]
    fun assert_eq__should_succeed_with_matching_values() {
        assert_eq(1, 1);
        assert_eq(true, true);
        assert_eq(@0x123, @0x123);
        assert_eq(vector[1, 2, 3], vector[1, 2, 3]);
        assert_eq(string::utf8(b"string"), string::utf8(b"string"));

        let (_, object_address) = create_and_move_custom_resource();
        assert_eq(
            object::address_to_object<CustomResource>(object_address),
            object::address_to_object<CustomResource>(object_address)
        );
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_integer() {
        internal_assert_eq(1, 2, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_bool() {
        internal_assert_eq(true, false, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_address() {
        internal_assert_eq(@0x123, @0x234, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_vector() {
        internal_assert_eq(vector[1, 2, 3], vector[2, 3, 4], false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_string() {
        internal_assert_eq(string::utf8(b"string"), string::utf8(b"other"), false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_eq__should_fail_with_mismatched_object_address() {
        let (_, object_address) = create_and_move_custom_resource();
        let (_, object_address2) = create_and_move_custom_resource();
        internal_assert_eq(
            object::address_to_object<CustomResource>(object_address),
            object::address_to_object<CustomResource>(object_address2),
            false /* debug */
        );
    }

    #[test]
    fun assert_neq__should_succeed_with_mismatched_values() {
        assert_neq(1, 2);
        assert_neq(true, false);
        assert_neq(@0x123, @0x234);
        assert_neq(vector[1, 2, 3], vector[2, 3, 4]);
        assert_neq(string::utf8(b"string"), string::utf8(b"other"));

        let (_, object_address) = create_and_move_custom_resource();
        let (_, object_address2) = create_and_move_custom_resource();
        assert_neq(
            object::address_to_object<CustomResource>(object_address),
            object::address_to_object<CustomResource>(object_address2)
        );
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_integer() {
        internal_assert_neq(1, 1, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_bool() {
        internal_assert_neq(true, true, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_address() {
        internal_assert_neq(@0x123, @0x123, false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_vector() {
        internal_assert_neq(vector[1, 2, 3], vector[1, 2, 3], false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_string() {
        internal_assert_neq(string::utf8(b"string"), string::utf8(b"string"), false /* debug */);
    }

    #[test, expected_failure(abort_code = ERROR_FAILED_ASSERTION)]
    fun internal_assert_neq__should_fail_with_matching_object_address() {
        let (_, object_address) = create_and_move_custom_resource();
        internal_assert_neq(
            object::address_to_object<CustomResource>(object_address),
            object::address_to_object<CustomResource>(object_address),
            false /* debug */
        );
    }
}
