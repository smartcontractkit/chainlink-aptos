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
        let accounts = vector[vector[1, 2, 3], vector[4, 5, 6, 7, 8]];

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
    fun test_svm_token_receiver_padding() {
        // Test with short token receiver - should be padded to 32 bytes
        let short_receiver = vector[1, 2, 3];
        let encoded =
            client::encode_svm_extra_args_v1(
                100u32, 0u64, false, short_receiver, vector[]
            );

        // Should not fail and should include the padded receiver
        assert!(encoded.length() >= 4 + 4 + 8 + 1 + 32);
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

        // Test with single account
        let single_account = vector[vector[0xaa, 0xbb, 0xcc]];
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
    #[expected_failure(abort_code = 65537, location = ccip::client)]
    // E_INVALID_SVM_TOKEN_RECEIVER_LENGTH
    fun test_svm_args_rejects_long_token_receiver() {
        // Test that token receivers longer than 32 bytes are rejected
        let long_receiver =
            x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // 50 bytes
        // E_INVALID_SVM_TOKEN_RECEIVER_LENGTH
        client::encode_svm_extra_args_v1(100, 0, false, long_receiver, vector[]);
    }

    #[test]
    fun test_pad_svm_address_empty() {
        let addr = vector[];
        client::test_pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // Verify all bytes are zeros
        for (i in 0..32) {
            assert!(*addr.borrow(i) == 0, 1);
        };
    }

    #[test]
    fun test_pad_svm_address_single_byte() {
        let addr = vector[0x42];
        client::test_pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First 31 bytes should be zero, last byte should be 0x42
        for (i in 0..31) {
            assert!(*addr.borrow(i) == 0, 1);
        };
        assert!(*addr.borrow(31) == 0x42, 2);
    }

    #[test]
    fun test_pad_svm_address_partial() {
        let addr = vector[0x01, 0x02, 0x03, 0x04];
        client::test_pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First 28 bytes should be zero, last 4 bytes should be the original data
        for (i in 0..28) {
            assert!(*addr.borrow(i) == 0, 1);
        };
        assert!(*addr.borrow(28) == 0x01, 2);
        assert!(*addr.borrow(29) == 0x02, 3);
        assert!(*addr.borrow(30) == 0x03, 4);
        assert!(*addr.borrow(31) == 0x04, 5);
    }

    #[test]
    fun test_pad_svm_address_exact_32_bytes() {
        let addr = vector[];
        for (i in 0..32) {
            addr.push_back((i as u8));
        };
        let original_addr = addr;
        client::test_pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // Should remain unchanged since it's already 32 bytes
        assert!(addr == original_addr, 1);
    }

    #[test]
    fun test_pad_svm_address_31_bytes() {
        let addr = vector[];
        for (i in 0..31) {
            addr.push_back((i as u8));
        };
        client::test_pad_svm_address(&mut addr);
        assert!(addr.length() == 32, 0);
        // First byte should be 0 (padding), rest should be the original data
        assert!(*addr.borrow(0) == 0, 1);
        for (i in 1..32) {
            assert!(*addr.borrow(i) == ((i - 1) as u8), 2);
        };
    }

    #[test]
    fun test_encode_svm_extra_args_v1_basic() {
        let token_receiver = vector[0x01, 0x02, 0x03];
        let accounts = vector[vector[0x04, 0x05], vector[0x06, 0x07, 0x08]];

        let result =
            client::encode_svm_extra_args_v1(
                1000u32, 0u64, true, token_receiver, accounts
            );

        // Verify the result starts with the correct tag
        let tag_len = client::svm_extra_args_v1_tag().length();
        for (i in 0..tag_len) {
            assert!(
                *result.borrow(i) == *client::svm_extra_args_v1_tag().borrow(i),
                0
            );
        };

        // Result should be non-empty and contain the tag
        assert!(result.length() > tag_len, 1);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_empty_accounts() {
        let token_receiver = vector[0xFF];
        let accounts = vector[];

        let result =
            client::encode_svm_extra_args_v1(
                500u32, 0u64, false, token_receiver, accounts
            );

        // Should not fail and should contain the tag
        let tag_len = client::svm_extra_args_v1_tag().length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_32_byte_addresses() {
        let token_receiver = vector[];
        let account1 = vector[];
        let account2 = vector[];

        // Create exactly 32-byte addresses
        for (i in 0..32) {
            token_receiver.push_back((i as u8));
            account1.push_back(((i + 100) as u8));
            account2.push_back(((i + 200) as u8));
        };

        let accounts = vector[account1, account2];

        let result =
            client::encode_svm_extra_args_v1(
                2000u32,
                0xFFFFFFFFFFFFFFFFu64,
                true,
                token_receiver,
                accounts
            );

        // Should succeed without padding since addresses are already 32 bytes
        let tag_len = client::svm_extra_args_v1_tag().length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    fun test_encode_svm_extra_args_v1_mixed_address_lengths() {
        let token_receiver = vector[0x11]; // 1 byte
        let accounts = vector[
            vector[0x22, 0x33], // 2 bytes
            vector[], // 0 bytes (empty)
            vector[0x44, 0x55, 0x66, 0x77, 0x88] // 5 bytes
        ];

        let result =
            client::encode_svm_extra_args_v1(
                750u32, 0u64, false, token_receiver, accounts
            );

        // All addresses should be padded to 32 bytes internally
        let tag_len = client::svm_extra_args_v1_tag().length();
        assert!(result.length() > tag_len, 0);
    }

    #[test]
    #[expected_failure(abort_code = 65537)]
    // E_INVALID_SVM_TOKEN_RECEIVER_LENGTH
    fun test_encode_svm_extra_args_v1_invalid_token_receiver_length() {
        // This test should fail because we're creating a token_receiver that's longer than 32 bytes
        let token_receiver = vector[];
        for (i in 0..33) { // 33 bytes - too long
            token_receiver.push_back((i as u8));
        };
        let accounts = vector[];
        client::encode_svm_extra_args_v1(1000u32, 0u64, true, token_receiver, accounts);
    }

    #[test]
    #[expected_failure(abort_code = 65538)]
    // E_INVALID_SVM_ACCOUNT_LENGTH
    fun test_encode_svm_extra_args_v1_invalid_account_length() {
        // This test should fail because we're creating an account that's longer than 32 bytes
        let token_receiver = vector[0x01];
        let long_account = vector[];
        for (i in 0..33) { // 33 bytes - too long
            long_account.push_back((i as u8));
        };
        let accounts = vector[long_account];

        client::encode_svm_extra_args_v1(1000u32, 0u64, true, token_receiver, accounts);
    }
}
