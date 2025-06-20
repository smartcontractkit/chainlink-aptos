#[test_only]
module ccip::client_test {
    use ccip::client;
    use std::bcs;
    use mcms::bcs_stream;

    #[test]
    fun test_encode_decode_vector_u8() {
        let input = vector[1, 2, 3, 4, 5];
        let encoded = bcs::to_bytes(&input);

        let decode_stream = bcs_stream::new(encoded);
        let decoded = bcs_stream::deserialize_vector_u8(&mut decode_stream);
        assert!(input == decoded, 0);
    }

    #[test]
    fun test_generic_extra_args_v2_encoding() {
        // Test basic encoding
        let gas_limit = 500000u256;
        let allow_ooo = true;
        let encoded = client::encode_generic_extra_args_v2(gas_limit, allow_ooo);

        // Verify structure: tag (4 bytes) + u256 (32 bytes) + bool (1 byte) = 37 bytes
        assert!(encoded.length() == 37, 0);

        // Verify tag
        let tag = encoded.slice(0, 4);
        assert!(tag == client::generic_extra_args_v2_tag(), 1);

        // Test with different values
        let gas_limit2 = 0u256;
        let allow_ooo2 = false;
        let encoded2 = client::encode_generic_extra_args_v2(gas_limit2, allow_ooo2);
        assert!(encoded2.length() == 37, 2);

        // Verify they're different (except for tag)
        let data1 = encoded.slice(4, encoded.length());
        let data2 = encoded2.slice(4, encoded2.length());
        assert!(data1 != data2, 3);
    }

    #[test]
    fun test_svm_extra_args_v1_encoding() {
        let compute_units = 100000u32;
        let bitmap = 255u64;
        let allow_ooo = true;
        let token_receiver =
            x"1234567890123456789012345678901234567890123456789012345678901234";
        let accounts = vector[
            x"0000000000000000000000000000000000000000000000000000000000000001", // 32 bytes
            x"0000000000000000000000000000000000000000000000000000000000000002"  // 32 bytes
        ];

        let encoded =
            client::encode_svm_extra_args_v1(
                compute_units,
                bitmap,
                allow_ooo,
                token_receiver,
                accounts
            );

        // Verify tag
        let tag = encoded.slice(0, 4);
        assert!(tag == client::svm_extra_args_v1_tag());

        // Verify minimum size (tag + u32 + u64 + bool + token_receiver + accounts)
        assert!(encoded.length() >= 4 + 4 + 8 + 1 + 32);
    }

    #[test]
    #[
        expected_failure(
            abort_code = client::E_INVALID_SVM_TOKEN_RECEIVER_LENGTH,
            location = ccip::client
        )
    ]
    fun test_svm_token_receiver_padding() {
        // Test with short token receiver - should be padded to 32 bytes
        let short_receiver = vector[1, 2, 3];
        let encoded =
            client::encode_svm_extra_args_v1(
                100u32, 0u64, false, short_receiver, vector[]
            );
    }

    #[test]
    fun test_bcs_u256_consistency() {
        // Test that large u256 values encode/decode correctly
        let large_values = vector[
            100000u256,
            1000000u256,
            18446744073709551615u256, // Max u64
            115792089237316195423570985008687907853269984665640564039457584007913129639935u256 // Max u256
        ];

        large_values.for_each_ref(
            |value| {
                let encoded = client::encode_generic_extra_args_v2(*value, true);
                assert!(encoded.length() == 37);

                // Extract the encoded u256 bytes (skip tag, take 32 bytes)
                let u256_bytes = encoded.slice(4, 36);
                assert!(u256_bytes.length() == 32);
            }
        );
    }

    #[test]
    fun test_bcs_boolean_consistency() {
        // Test that boolean values encode consistently
        let encoded_true = client::encode_generic_extra_args_v2(100u256, true);
        let encoded_false = client::encode_generic_extra_args_v2(100u256, false);

        // Should be same length
        assert!(encoded_true.length() == encoded_false.length());

        // Should differ only in the last byte (the boolean)
        let true_bool_byte = encoded_true[encoded_true.length() - 1];
        let false_bool_byte = encoded_false[encoded_false.length() - 1];

        assert!(true_bool_byte != false_bool_byte);
        assert!(true_bool_byte == 1); // BCS encodes true as 0x01
        assert!(false_bool_byte == 0); // BCS encodes false as 0x00
    }

    #[test]
    fun test_empty_accounts_svm_args() {
        let compute_units = 50000u32;
        let bitmap = 0u64;
        let allow_ooo = false;
        let token_receiver =
            x"0000000000000000000000000000000000000000000000000000000000000000";
        let empty_accounts = vector[];

        let encoded =
            client::encode_svm_extra_args_v1(
                compute_units,
                bitmap,
                allow_ooo,
                token_receiver,
                empty_accounts
            );

        // Should encode successfully
        assert!(encoded.length() >= 4 + 4 + 8 + 1 + 32);

        // Test with single account - update to use 32-byte account
        let single_account = vector[x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]; // 32 bytes
        let encoded_with_account =
            client::encode_svm_extra_args_v1(
                compute_units,
                bitmap,
                allow_ooo,
                token_receiver,
                single_account
            );

        // Should be larger than empty accounts version
        assert!(encoded_with_account.length() > encoded.length());
    }

    #[test]
    #[
        expected_failure(
            abort_code = client::E_INVALID_SVM_TOKEN_RECEIVER_LENGTH,
            location = ccip::client
        )
    ]
    fun test_svm_args_rejects_long_token_receiver() {
        // Test that token receivers longer than 32 bytes are rejected
        let long_receiver =
            x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // 50 bytes
        // E_INVALID_SVM_TOKEN_RECEIVER_LENGTH
        client::encode_svm_extra_args_v1(100, 0, false, long_receiver, vector[]);
    }

    #[test]
    fun test_svm_args_with_valid_32_byte_accounts() {
        // Test that accounts with exactly 32 bytes are accepted
        let compute_units = 100000u32;
        let bitmap = 0u64;
        let allow_ooo = true;
        let token_receiver =
            x"1234567890123456789012345678901234567890123456789012345678901234";
        
        // Create accounts with exactly 32 bytes each
        let account1 = x"0000000000000000000000000000000000000000000000000000000000000001";
        let account2 = x"0000000000000000000000000000000000000000000000000000000000000002";
        let account3 = x"0000000000000000000000000000000000000000000000000000000000000003";
        let valid_accounts = vector[account1, account2, account3];

        // This should succeed
        let encoded =
            client::encode_svm_extra_args_v1(
                compute_units,
                bitmap,
                allow_ooo,
                token_receiver,
                valid_accounts
            );

        // Verify encoding was successful
        assert!(encoded.length() > 0);
        let tag = encoded.slice(0, 4);
        assert!(tag == client::svm_extra_args_v1_tag());
    }

    #[test]
    #[
        expected_failure(
            abort_code = client::E_INVALID_SVM_ACCOUNT_LENGTH,
            location = ccip::client
        )
    ]
    fun test_svm_args_rejects_invalid_account_length() {
        // Test that accounts with non-32-byte length are rejected
        let compute_units = 100000u32;
        let bitmap = 0u64;
        let allow_ooo = true;
        let token_receiver =
            x"1234567890123456789012345678901234567890123456789012345678901234";
        
        // Create accounts with invalid lengths
        let short_account = x"123456"; // 3 bytes - too short
        let long_account = x"000000000000000000000000000000000000000000000000000000000000000000000000"; // 34 bytes - too long
        let invalid_accounts = vector[short_account, long_account];

        // This should fail with E_INVALID_SVM_ACCOUNT_LENGTH
        client::encode_svm_extra_args_v1(
            compute_units,
            bitmap,
            allow_ooo,
            token_receiver,
            invalid_accounts
        );
    }

    #[test]
    #[
        expected_failure(
            abort_code = client::E_INVALID_SVM_ACCOUNT_LENGTH,
            location = ccip::client
        )
    ]
    fun test_svm_args_rejects_single_invalid_account_among_valid() {
        // Test that even one invalid account among valid ones causes failure
        let compute_units = 100000u32;
        let bitmap = 0u64;
        let allow_ooo = true;
        let token_receiver =
            x"1234567890123456789012345678901234567890123456789012345678901234";
        
        // Mix of valid and invalid accounts
        let valid_account = x"0000000000000000000000000000000000000000000000000000000000000001"; // 32 bytes - valid
        let invalid_account = x"123456789"; // 5 bytes - invalid
        let mixed_accounts = vector[valid_account, invalid_account];

        // This should fail with E_INVALID_SVM_ACCOUNT_LENGTH
        client::encode_svm_extra_args_v1(
            compute_units,
            bitmap,
            allow_ooo,
            token_receiver,
            mixed_accounts
        );
    }
}
