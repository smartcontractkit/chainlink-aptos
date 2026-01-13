#[test_only]
module mcms::bcs_stream_test {
    use std::bcs;
    use std::string;
    use std::vector;

    use aptos_std::aptos_hash;
    use mcms::bcs_stream::{Self};

    #[test]
    public fun test_deserialize_primitive_types() {
        let data = vector<u8>[];

        // u8, u16, u32, u64, u128, u256, bool
        vector::append(&mut data, bcs::to_bytes(&123u8));
        vector::append(&mut data, bcs::to_bytes(&12345u16));
        vector::append(&mut data, bcs::to_bytes(&1234567u32));
        vector::append(&mut data, bcs::to_bytes(&12345678901u64));
        vector::append(&mut data, bcs::to_bytes(&1234567890123456789u128));
        vector::append(
            &mut data,
            bcs::to_bytes(&340282366920938463463374607431768211455u256)
        );
        vector::append(&mut data, bcs::to_bytes(&true));

        // Create stream and deserialize in the same order
        let stream = bcs_stream::new(data);

        assert!(bcs_stream::deserialize_u8(&mut stream) == 123u8, 1);
        assert!(bcs_stream::deserialize_u16(&mut stream) == 12345u16, 2);
        assert!(bcs_stream::deserialize_u32(&mut stream) == 1234567u32, 3);
        assert!(bcs_stream::deserialize_u64(&mut stream) == 12345678901u64, 4);
        assert!(bcs_stream::deserialize_u128(&mut stream) == 1234567890123456789u128, 5);
        assert!(
            bcs_stream::deserialize_u256(&mut stream)
                == 340282366920938463463374607431768211455u256,
            6
        );
        assert!(bcs_stream::deserialize_bool(&mut stream) == true, 7);

        // Verify stream is fully consumed
        bcs_stream::assert_is_consumed(&stream);
    }

    #[test]
    public fun test_deserialize_vector() {
        let data = vector<u8>[];

        // Vector of u8
        let vec_u8 = vector[1u8, 2u8, 3u8];
        vector::append(&mut data, bcs::to_bytes(&vec_u8));

        // Vector of addresses
        let vec_addr = vector[@0x1, @0x2, @0x3];
        vector::append(&mut data, bcs::to_bytes(&vec_addr));

        // Create stream and deserialize
        let stream = bcs_stream::new(data);

        // Deserialize vector of u8
        let result_vec_u8 = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_vec_u8 == vec_u8, 1);

        // Deserialize vector of addresses
        let result_vec_addr =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_address(stream)
            );
        assert!(result_vec_addr == vec_addr, 2);

        // Verify stream is fully consumed
        bcs_stream::assert_is_consumed(&stream);
    }

    // Test serializing and deserializing strings
    #[test]
    public fun test_deserialize_string() {
        let data = vector<u8>[];

        // Serialize a string
        let str = string::utf8(b"Hello, BCS Stream!");
        vector::append(&mut data, bcs::to_bytes(&str));

        // Create stream and deserialize
        let stream = bcs_stream::new(data);
        let result_str = bcs_stream::deserialize_string(&mut stream);

        assert!(result_str == str, 1);
        bcs_stream::assert_is_consumed(&stream);
    }

    // Test serializing and deserializing option types
    #[test]
    public fun test_deserialize_option() {
        let data = vector<u8>[];

        // Some value
        vector::append(&mut data, bcs::to_bytes(&std::option::some(42u64)));
        // None value
        vector::append(
            &mut data,
            bcs::to_bytes(&std::option::none<u64>())
        );

        // Create stream and deserialize
        let stream = bcs_stream::new(data);

        // Deserialize Some
        let some_result =
            bcs_stream::deserialize_option(
                &mut stream, |stream| bcs_stream::deserialize_u64(stream)
            );
        assert!(std::option::is_some(&some_result), 1);
        assert!(*std::option::borrow(&some_result) == 42u64, 2);

        // Deserialize None
        let none_result =
            bcs_stream::deserialize_option(
                &mut stream, |stream| bcs_stream::deserialize_u64(stream)
            );
        assert!(std::option::is_none(&none_result), 3);

        // Verify stream is fully consumed
        bcs_stream::assert_is_consumed(&stream);
    }

    // Test serializing complex nested data structures
    #[test]
    public fun test_complex_data_structure() {
        // This test simulates the `timelock_schedule_batch` data format
        let data = vector<u8>[];

        // Parameters to serialize
        let targets = vector[@0x1, @0x2];
        let module_names = vector[string::utf8(b"module1"), string::utf8(b"module2")];
        let function_names = vector[string::utf8(b"func1"), string::utf8(b"func2")];
        let datas = vector[vector[1u8, 2u8], vector[3u8, 4u8]];
        let predecessor = aptos_hash::keccak256(b"predecessor");
        let salt = vector[1u8, 2u8, 3u8];
        let delay = 100u64;

        // Serialize in the expected order
        vector::append(&mut data, bcs::to_bytes(&targets));
        vector::append(&mut data, bcs::to_bytes(&module_names));
        vector::append(&mut data, bcs::to_bytes(&function_names));
        vector::append(&mut data, bcs::to_bytes(&datas));
        vector::append(&mut data, bcs::to_bytes(&predecessor));
        vector::append(&mut data, bcs::to_bytes(&salt));
        vector::append(&mut data, bcs::to_bytes(&delay));

        // Create stream and deserialize
        let stream = bcs_stream::new(data);

        // Deserialize and verify each component
        let result_targets =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_address(stream)
            );
        assert!(result_targets == targets, 1);

        let result_module_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        assert!(result_module_names == module_names, 2);

        let result_function_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        assert!(result_function_names == function_names, 3);

        let result_datas =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        assert!(result_datas == datas, 4);

        let result_predecessor = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_predecessor == predecessor, 5);

        let result_salt = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_salt == salt, 6);

        let result_delay = bcs_stream::deserialize_u64(&mut stream);
        assert!(result_delay == delay, 7);

        // Verify stream is fully consumed
        bcs_stream::assert_is_consumed(&stream);
    }

    // Test the wrong way of serializing (nested serialization) that causes errors
    #[test]
    #[expected_failure(abort_code = 196611, location = mcms::bcs_stream)]
    public fun test_incorrect_nested_serialization() {
        // Create a very simple example that will fail to deserialize correctly
        let data = vector<u8>[0x01]; // This is not a valid u8 serialization (BCS would add length prefix for vector)
        data.append(bcs::to_bytes(&true));

        let stream = bcs_stream::new(data);
        let _val = bcs_stream::deserialize_u8(&mut stream);

        bcs_stream::assert_is_consumed(&stream);
    }

    // Test the correct way to serialize multiple values
    #[test]
    public fun test_correct_multi_value_serialization() {
        // Correct pattern - directly serialize into a single byte stream
        let data = vector<u8>[];

        // Serialize values directly
        vector::append(&mut data, bcs::to_bytes(&123u8));
        vector::append(&mut data, bcs::to_bytes(&true));

        // Deserialize correctly
        let stream = bcs_stream::new(data);
        assert!(bcs_stream::deserialize_u8(&mut stream) == 123u8, 1);
        assert!(bcs_stream::deserialize_bool(&mut stream) == true, 2);

        bcs_stream::assert_is_consumed(&stream);
    }

    // Test set_config serialization (which caused the issue in the test)
    #[test]
    public fun test_set_config_serialization() {
        // Create a sample set_config data structure
        let data = vector<u8>[];

        // Role
        vector::append(&mut data, bcs::to_bytes(&2u8)); // proposer_role

        // Signer addresses - vector of 20-byte EVM addresses
        let signer_addresses = vector[
            x"1111111111111111111111111111111111111111",
            x"2222222222222222222222222222222222222222",
            x"3333333333333333333333333333333333333333"
        ];
        vector::append(&mut data, bcs::to_bytes(&signer_addresses));

        // Signer groups
        let signer_groups = vector[0u8, 1u8, 1u8];
        vector::append(&mut data, bcs::to_bytes(&signer_groups));

        // Group quorums
        let group_quorums = vector[
            1u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
        ];
        vector::append(&mut data, bcs::to_bytes(&group_quorums));

        // Group parents
        let group_parents = vector[
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
        ];
        vector::append(&mut data, bcs::to_bytes(&group_parents));

        // Clear root
        vector::append(&mut data, bcs::to_bytes(&false));

        // Create stream and attempt to deserialize
        let stream = bcs_stream::new(data);

        // Now deserialize and verify each field
        let role = bcs_stream::deserialize_u8(&mut stream);
        assert!(role == 2u8, 1);

        let result_signer_addresses =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        assert!(result_signer_addresses == signer_addresses, 2);

        let result_signer_groups = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_signer_groups == signer_groups, 3);

        let result_group_quorums = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_group_quorums == group_quorums, 4);

        let result_group_parents = bcs_stream::deserialize_vector_u8(&mut stream);
        assert!(result_group_parents == group_parents, 5);

        let result_clear_root = bcs_stream::deserialize_bool(&mut stream);
        assert!(result_clear_root == false, 6);

        // Verify stream is fully consumed
        bcs_stream::assert_is_consumed(&stream);
    }
}
