#[test_only]
module ccip_offramp::ocr3_base_test {
    use std::signer;
    use std::chain_id;
    use std::account;
    use std::object;

    use ccip::state_object;
    use ccip_offramp::ocr3_base;
    use ccip::auth;

    const CHAIN_ID: u8 = 100;
    const OCR_PLUGIN_TYPE_COMMIT: u8 = 0;
    const OCR_PLUGIN_TYPE_EXECUTION: u8 = 1;

    const OWNER: address = @0x1234;
    const TRANSMITTER1: address = @0x5678;
    const TRANSMITTER2: address = @0x9ABC;
    const TRANSMITTER3: address = @0xDEF0;
    const TRANSMITTER4: address = @0x1111;

    const SIGNER1: vector<u8> = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SIGNER2: vector<u8> = x"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const SIGNER3: vector<u8> = x"1122334455667788990011223344556677889900112233445566778899001122";
    const SIGNER4: vector<u8> = x"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    const VALID_CONFIG_DIGEST: vector<u8> = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_BIG_F: u8 = 1;
    const SIGNATURE_VERIFICATION_ENABLED: bool = true;
    const SIGNATURE_VERIFICATION_DISABLED: bool = false;

    fun setup(aptos_framework: &signer, owner: &signer, ccip: &signer)
        : ocr3_base::OCR3BaseState {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(ccip));
        chain_id::initialize_for_test(aptos_framework, CHAIN_ID);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);

        // Initialize auth module for testing
        auth::test_init_module(ccip);

        // Create new OCR3BaseState
        ocr3_base::new(owner)
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    fun test_ocr_plugin_types(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        // Verify plugin types match expected values
        assert!(ocr3_base::ocr_plugin_type_commit() == OCR_PLUGIN_TYPE_COMMIT, 0);
        assert!(ocr3_base::ocr_plugin_type_execution() == OCR_PLUGIN_TYPE_EXECUTION, 0);

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    fun test_set_ocr3_config(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let config_digest = VALID_CONFIG_DIGEST;
        let ocr_plugin_type = ocr3_base::ocr_plugin_type_commit();
        let big_f = VALID_BIG_F;
        let is_signature_verification_enabled = SIGNATURE_VERIFICATION_ENABLED;

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];
        let transmitters = vector[TRANSMITTER1, TRANSMITTER2, TRANSMITTER3, TRANSMITTER4];

        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            config_digest,
            ocr_plugin_type,
            big_f,
            is_signature_verification_enabled,
            signers,
            transmitters
        );

        let ocr_plugin_type = ocr3_base::ocr_plugin_type_execution();
        let is_signature_verification_enabled = SIGNATURE_VERIFICATION_ENABLED;

        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            config_digest,
            ocr_plugin_type,
            big_f,
            is_signature_verification_enabled,
            signers,
            transmitters
        );

        // Verify execution plugin config was set correctly
        let config = ocr3_base::latest_config_details(&state, ocr_plugin_type);
        assert!(ocr3_base::config_signers(&config) == signers);
        assert!(ocr3_base::config_transmitters(&config) == transmitters);

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    fun test_deserialize_sequence_bytes(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        // Test with sequence number 9
        let sequence_bytes =
            x"0000000000000000000000000000000000000000000000000000000000000009";
        let sequence_number = ocr3_base::deserialize_sequence_bytes(sequence_bytes);
        assert!(sequence_number == 9, 0);

        // Test with sequence number 12345
        let sequence_bytes =
            x"0000000000000000000000000000000000000000000000000000000000003039";
        let sequence_number = ocr3_base::deserialize_sequence_bytes(sequence_bytes);
        assert!(sequence_number == 12345, 0);

        // Test with max u64 value
        let sequence_bytes =
            x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let sequence_number = ocr3_base::deserialize_sequence_bytes(sequence_bytes);
        assert!(sequence_number == 18446744073709551615, 0); // max u64 value

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65539, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_too_many_signers(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        // Create more than MAX_NUM_ORACLES signers
        let signers = vector[];
        let i = 0;
        while (i < 257) { // MAX_NUM_ORACLES is 256
            signers.push_back(SIGNER1);
            i = i + 1;
        };

        let transmitters = vector[TRANSMITTER1];

        // This should fail with E_TOO_MANY_SIGNERS
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65551, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_invalid_config_digest_length(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];
        let transmitters = vector[TRANSMITTER1, TRANSMITTER2, TRANSMITTER3, TRANSMITTER4];

        // This should fail with E_INVALID_CONFIG_DIGEST_LENGTH because config_digest is not 32 bytes
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            x"00", // Only 1 byte instead of 32
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65541, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_too_many_transmitters(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        // Create more than MAX_NUM_ORACLES transmitters
        let transmitters = vector[];
        let i = 0;
        while (i < 257) { // MAX_NUM_ORACLES is 256
            transmitters.push_back(TRANSMITTER1);
            i = i + 1;
        };

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];

        // This should fail with MAX_NUM_ORACLES
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65542, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_no_transmitters(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];
        let transmitters = vector[];

        // This should fail with E_NO_TRANSMITTERS
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65537, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_zero_big_f(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];
        let transmitters = vector[TRANSMITTER1, TRANSMITTER2, TRANSMITTER3, TRANSMITTER4];

        // This should fail with E_BIG_F_MUST_BE_POSITIVE
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            0, // big_f = 0
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65540, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_big_f_too_high(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1]; // Only 1 signer
        let transmitters = vector[TRANSMITTER1];

        // This should fail with E_BIG_F_TOO_HIGH because signers.length() must be > 3 * big_f
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            1, // big_f = 1, so need at least 4 signers
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65543, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_repeated_signers(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        // Create signers with duplicates
        let signers = vector[SIGNER1, SIGNER1, SIGNER2, SIGNER3];
        let transmitters = vector[TRANSMITTER1, TRANSMITTER2, TRANSMITTER3, TRANSMITTER4];

        // This should fail with E_REPEATED_SIGNERS
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65544, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_repeated_transmitters(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1, SIGNER2, SIGNER3, SIGNER4];
        // Create transmitters with duplicates
        let transmitters = vector[TRANSMITTER1, TRANSMITTER1, TRANSMITTER2, TRANSMITTER3];

        // This should fail with E_REPEATED_TRANSMITTERS
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }

    #[test(aptos_framework = @aptos_framework, owner = @0x100, ccip = @ccip)]
    #[expected_failure(abort_code = 65540, location = ccip_offramp::ocr3_base)]
    fun test_set_ocr3_config_transmitters_exceed_signers(
        aptos_framework: &signer, owner: &signer, ccip: &signer
    ) {
        let state = setup(aptos_framework, owner, ccip);

        let signers = vector[SIGNER1, SIGNER2, SIGNER3]; // 3 signers
        let transmitters = vector[TRANSMITTER1, TRANSMITTER2, TRANSMITTER3, TRANSMITTER4]; // 4 transmitters

        // E_BIG_F_TOO_HIGH - too many signers
        ocr3_base::set_ocr3_config(
            owner,
            &mut state,
            VALID_CONFIG_DIGEST,
            ocr3_base::ocr_plugin_type_commit(),
            VALID_BIG_F,
            SIGNATURE_VERIFICATION_ENABLED,
            signers,
            transmitters
        );

        ocr3_base::destroy_ocr3_state(state);
    }
}
