#[test_only]
module ccip::fee_quoter_bcs {
    use std::bcs;
    use ccip::client;
    use ccip::fee_quoter::{Self, DestChainConfig};
    use ccip::fee_quoter_setup;

    #[test]
    fun test_extra_args_bcs_encoding_decoding2() {
        // Test GenericExtraArgsV2
        let gas_limit_v2 = 123456u256;
        let allow_ooo_v2 = true;

        let encoded_v2 = client::encode_generic_extra_args_v2(
            gas_limit_v2, allow_ooo_v2
        );

        let extra_args_len = encoded_v2.length();
        let args_tag = encoded_v2.slice(0, 4);
        assert!(args_tag == client::generic_extra_args_v2_tag());
        let args_data = encoded_v2.slice(4, extra_args_len);
        let (decoded_gas_limit, decoded_allow_ooo) =
            fee_quoter::test_decode_generic_extra_args_v2(args_data);

        assert!(decoded_gas_limit == gas_limit_v2);
        assert!(decoded_allow_ooo == allow_ooo_v2);

        // Test SvmExtraArgsV1
        let compute_units = 100u32;
        let bitmap = 200u64;
        let allow_ooo_svm = false;
        let token_receiver = vector[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ];
        let accounts = vector[
            x"0000000000000000000000000000000000000000000000000000000000000001",
            x"0000000000000000000000000000000000000000000000000000000000000002"
        ];

        let encoded_svm =
            client::encode_svm_extra_args_v1(
                compute_units,
                bitmap,
                allow_ooo_svm,
                token_receiver,
                accounts
            );

        let extra_args_svm_len = encoded_svm.length();
        let args_svm_tag = encoded_svm.slice(0, 4);
        assert!(args_svm_tag == client::svm_extra_args_v1_tag());
        let args_svm_data = encoded_svm.slice(4, extra_args_svm_len);

        let (
            decoded_cu,
            decoded_bitmap,
            decoded_allow_ooo_svm,
            decoded_token_receiver,
            decoded_accounts
        ) = fee_quoter::test_decode_svm_extra_args_v1(args_svm_data);

        assert!(decoded_cu == compute_units);
        assert!(decoded_bitmap == bitmap);
        assert!(decoded_allow_ooo_svm == allow_ooo_svm);
        assert!(decoded_token_receiver == token_receiver);
        assert!(decoded_accounts == accounts);
    }

    #[test]
    fun test_bcs_encoding_edge_cases() {
        // Test with maximum u256 value
        let max_gas_limit =
            115792089237316195423570985008687907853269984665640564039457584007913129639935u256;
        let encoded_max = client::encode_generic_extra_args_v2(max_gas_limit, true);
        let args_data = encoded_max.slice(4, encoded_max.length());
        let (decoded_gas_limit, decoded_allow_ooo) =
            fee_quoter::test_decode_generic_extra_args_v2(args_data);
        assert!(decoded_gas_limit == max_gas_limit);
        assert!(decoded_allow_ooo == true);

        // Test with zero values
        let zero_gas_limit = 0u256;
        let encoded_zero = client::encode_generic_extra_args_v2(zero_gas_limit, false);
        let args_data_zero = encoded_zero.slice(4, encoded_zero.length());
        let (decoded_zero_gas, decoded_false_ooo) =
            fee_quoter::test_decode_generic_extra_args_v2(args_data_zero);
        assert!(decoded_zero_gas == zero_gas_limit);
        assert!(decoded_false_ooo == false);

        // Test SVM with maximum values
        let max_compute_units = 4294967295u32; // u32::MAX
        let max_bitmap = 18446744073709551615u64; // u64::MAX
        // Use simpler fixed vectors for test
        let token_receiver_max =
            x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let large_accounts = vector[
            x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            x"8080808080808080808080808080808080808080808080808080808080808080",
            x"0000000000000000000000000000000000000000000000000000000000000000"
        ];

        let encoded_svm_max =
            client::encode_svm_extra_args_v1(
                max_compute_units,
                max_bitmap,
                true,
                token_receiver_max,
                large_accounts
            );

        let (
            decoded_cu,
            decoded_bitmap,
            decoded_ooo,
            decoded_receiver,
            decoded_accounts
        ) = fee_quoter::test_decode_svm_extra_args(encoded_svm_max);

        assert!(decoded_cu == max_compute_units);
        assert!(decoded_bitmap == max_bitmap);
        assert!(decoded_ooo == true);
        assert!(decoded_receiver == token_receiver_max);
        assert!(decoded_accounts == large_accounts);
    }

    #[test]
    fun test_bcs_encoding_size_verification() {
        // Test that BCS encoding produces expected sizes
        let gas_limit = 1000000u256;
        let encoded = client::encode_generic_extra_args_v2(gas_limit, true);

        // Expected size: 4 bytes (tag) + 32 bytes (u256) + 1 byte (bool) = 37 bytes
        assert!(encoded.length() == 37);

        // Verify tag is first 4 bytes
        let tag = encoded.slice(0, 4);
        assert!(tag == client::generic_extra_args_v2_tag());

        // Test SVM encoding size
        let token_receiver =
            x"0000000000000000000000000000000000000000000000000000000000000000";
        let accounts = vector[
            x"0000000000000000000000000000000000000000000000000000000000000001",
            x"0000000000000000000000000000000000000000000000000000000000000002"
        ];
        let svm_encoded =
            client::encode_svm_extra_args_v1(
                100u32,
                200u64,
                false,
                token_receiver,
                accounts
            );

        // Expected size breakdown:
        // 4 bytes (SVM_EXTRA_ARGS_V1_TAG)
        // 4 bytes (u32 compute_units = 100)
        // 8 bytes (u64 bitmap = 200)
        // 1 byte (bool allow_ooo = false)
        // 33 bytes (BCS-encoded token_receiver: 1 byte length + 32 bytes data)
        // 65 bytes (BCS-encoded accounts: 1 byte outer length + 32 bytes first inner + 32 bytes second inner)
        //   where accounts = vector[32 bytes, 32 bytes]
        // Total: 4 + 4 + 8 + 1 + 33 + 65 = 117 bytes
        assert!(svm_encoded.length() == 117); // Exact expected size
    }

    #[test]
    fun test_bcs_decoding_integration_with_fee_quoter() {
        let gas_limit = 500000u256;
        let allow_ooo = true;

        let encoded_args = client::encode_generic_extra_args_v2(gas_limit, allow_ooo);
        let mock_config = create_test_dest_chain_config();

        let (decoded_gas_limit, decoded_allow_ooo) =
            fee_quoter::test_decode_generic_extra_args(&mock_config, encoded_args);

        assert!(decoded_gas_limit == gas_limit);
        assert!(decoded_allow_ooo == allow_ooo);
    }

    #[test]
    fun test_bcs_empty_extra_args_handling() {
        let default_tx_gas_limit = 50000;
        let mock_config = create_test_dest_chain_config();

        // Test empty extra args - should return default gas limit and OOO = true (always true)
        let empty_args = vector[];
        let (gas_limit, allow_ooo) =
            fee_quoter::test_decode_generic_extra_args(&mock_config, empty_args);

        assert!(gas_limit == (default_tx_gas_limit as u256));
        assert!(allow_ooo == true);
    }

    #[test]
    #[expected_failure(abort_code = 65556, location = ccip::fee_quoter)]
    fun test_invalid_tag_fails() {
        let invalid_args = vector[0x12, 0x34, 0x56, 0x78]; // Invalid tag
        invalid_args.append(bcs::to_bytes(&1000u256));
        invalid_args.append(bcs::to_bytes(&true));

        let mock_config = create_test_dest_chain_config();

        // E_INVALID_EXTRA_ARGS_TAG
        fee_quoter::test_decode_generic_extra_args(&mock_config, invalid_args);
    }

    #[test]
    #[expected_failure(abort_code = 131074, location = mcms::bcs_stream)]
    fun test_truncated_data_fails() {
        let truncated_args = client::generic_extra_args_v2_tag();
        truncated_args.append(bcs::to_bytes(&1000));
        // Missing boolean - should fail

        let args_data = truncated_args.slice(4, truncated_args.length());
        // E_OUT_OF_BYTES
        fee_quoter::test_decode_generic_extra_args_v2(args_data);
    }

    #[test]
    fun test_bcs_vs_expected_byte_patterns() {
        // Test specific byte patterns to ensure BCS encoding matches expectations

        // Test u256 encoding for common gas limit values
        let common_gas_limits = vector[100000u256, 500000u256, 1000000u256, 5000000u256];

        common_gas_limits.for_each_ref(
            |gas_limit| {
                let encoded = client::encode_generic_extra_args_v2(*gas_limit, true);
                let decoded_data = encoded.slice(4, encoded.length());
                let (decoded_gas, decoded_bool) =
                    fee_quoter::test_decode_generic_extra_args_v2(decoded_data);

                assert!(decoded_gas == *gas_limit);
                assert!(decoded_bool == true);
            }
        );

        // Test boolean encoding consistency
        let encoded_true = client::encode_generic_extra_args_v2(100000u256, true);
        let encoded_false = client::encode_generic_extra_args_v2(100000u256, false);

        // The boolean byte should be different
        let true_bool_byte = encoded_true[encoded_true.length() - 1];
        let false_bool_byte = encoded_false[encoded_false.length() - 1];
        assert!(true_bool_byte != false_bool_byte, 2);
        assert!(true_bool_byte == 1, 3); // BCS encodes true as 0x01
        assert!(false_bool_byte == 0, 4); // BCS encodes false as 0x00
    }

    #[test]
    fun test_svm_extra_args_comprehensive() {
        // Test case 1: Basic SVM args
        let compute_units1 = 100u32;
        let bitmap1 = 0u64;
        let allow_ooo1 = true;
        let token_receiver1 =
            x"0101010101010101010101010101010101010101010101010101010101010101";
        let accounts1 = vector[];

        let encoded1 =
            client::encode_svm_extra_args_v1(
                compute_units1,
                bitmap1,
                allow_ooo1,
                token_receiver1,
                accounts1
            );
        let (
            decoded_cu1,
            decoded_bitmap1,
            decoded_ooo1,
            decoded_receiver1,
            decoded_accounts1
        ) = fee_quoter::test_decode_svm_extra_args(encoded1);

        assert!(decoded_cu1 == compute_units1, 0);
        assert!(decoded_bitmap1 == bitmap1, 1);
        assert!(decoded_ooo1 == allow_ooo1, 2);
        assert!(decoded_receiver1 == token_receiver1, 3);
        assert!(decoded_accounts1 == accounts1, 4);

        // Test case 2: SVM args with accounts
        let compute_units2 = 200000u32;
        let bitmap2 = 255u64;
        let allow_ooo2 = false;
        let token_receiver2 =
            x"0202020202020202020202020202020202020202020202020202020202020202";
        let accounts2 = vector[
            x"0000000000000000000000000000000000000000000000000000000000000001",
            x"0000000000000000000000000000000000000000000000000000000000000002",
            x"0000000000000000000000000000000000000000000000000000000000000003"
        ];

        let encoded2 =
            client::encode_svm_extra_args_v1(
                compute_units2,
                bitmap2,
                allow_ooo2,
                token_receiver2,
                accounts2
            );
        let (
            decoded_cu2,
            decoded_bitmap2,
            decoded_ooo2,
            decoded_receiver2,
            decoded_accounts2
        ) = fee_quoter::test_decode_svm_extra_args(encoded2);

        assert!(decoded_cu2 == compute_units2, 5);
        assert!(decoded_bitmap2 == bitmap2, 6);
        assert!(decoded_ooo2 == allow_ooo2, 7);
        assert!(decoded_receiver2 == token_receiver2, 8);
        assert!(decoded_accounts2 == accounts2, 9);

        // Test case 3: Zero receiver case
        let compute_units3 = 1000000u32;
        let bitmap3 = 0u64;
        let allow_ooo3 = true;
        let token_receiver3 =
            x"0000000000000000000000000000000000000000000000000000000000000000"; // Zero receiver
        let accounts3 = vector[];

        let encoded3 =
            client::encode_svm_extra_args_v1(
                compute_units3,
                bitmap3,
                allow_ooo3,
                token_receiver3,
                accounts3
            );
        let (
            decoded_cu3,
            decoded_bitmap3,
            decoded_ooo3,
            decoded_receiver3,
            decoded_accounts3
        ) = fee_quoter::test_decode_svm_extra_args(encoded3);

        assert!(decoded_cu3 == compute_units3, 10);
        assert!(decoded_bitmap3 == bitmap3, 11);
        assert!(decoded_ooo3 == allow_ooo3, 12);
        assert!(decoded_receiver3 == token_receiver3, 13);
        assert!(decoded_accounts3 == accounts3, 14);
    }

    fun create_test_dest_chain_config(): DestChainConfig {
        fee_quoter::test_create_dest_chain_config(
            true, // is_enabled
            10, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            1000000, // max_per_msg_gas_limit
            1000, // dest_gas_overhead
            1, // dest_gas_per_payload_byte_base
            2, // dest_gas_per_payload_byte_high
            1000, // dest_gas_per_payload_byte_threshold
            500, // dest_data_availability_overhead_gas
            1, // dest_gas_per_data_availability_byte
            100, // dest_data_availability_multiplier_bps
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            false, // enforce_out_of_order
            100, // default_token_fee_usd_cents
            1000, // default_token_dest_gas_overhead
            50000, // default_tx_gas_limit
            1000000000000000000, // gas_multiplier_wei_per_eth
            3600, // gas_price_staleness_threshold
            50 // network_fee_usd_cents
        )
    }
}
