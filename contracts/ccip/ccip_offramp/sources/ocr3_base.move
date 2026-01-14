module ccip_offramp::ocr3_base {
    use std::account;
    use std::aptos_hash;
    use std::bit_vector;
    use std::chain_id;
    use std::ed25519;
    use std::signer;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::table::{Self, Table};

    use ccip::address;
    use ccip::auth;

    const MAX_NUM_ORACLES: u64 = 256;

    const OCR_PLUGIN_TYPE_COMMIT: u8 = 0;
    const OCR_PLUGIN_TYPE_EXECUTION: u8 = 1;

    struct ConfigInfo has store, drop, copy {
        config_digest: vector<u8>,
        big_f: u8,
        n: u8,
        is_signature_verification_enabled: bool
    }

    struct OCRConfig has store, drop, copy {
        config_info: ConfigInfo,
        signers: vector<vector<u8>>,
        transmitters: vector<address>
    }

    struct Oracle has store, drop {
        index: u8,
        role: u8
    }

    struct OCR3BaseState has store {
        chain_id: u8,
        // ocr plugin type -> ocr config
        ocr3_configs: Table<u8, OCRConfig>,
        // ocr plugin type -> signers
        signer_oracles: Table<u8, vector<ed25519::UnvalidatedPublicKey>>,
        // ocr plugin type -> transmitters
        transmitter_oracles: Table<u8, vector<address>>,
        config_set_events: EventHandle<ConfigSet>,
        transmitted_events: EventHandle<Transmitted>
    }

    #[event]
    struct ConfigSet has store, drop {
        ocr_plugin_type: u8,
        config_digest: vector<u8>,
        signers: vector<vector<u8>>,
        transmitters: vector<address>,
        big_f: u8
    }

    #[event]
    struct Transmitted has store, drop {
        ocr_plugin_type: u8,
        config_digest: vector<u8>,
        sequence_number: u64
    }

    const E_BIG_F_MUST_BE_POSITIVE: u64 = 1;
    const E_STATIC_CONFIG_CANNOT_BE_CHANGED: u64 = 2;
    const E_TOO_MANY_SIGNERS: u64 = 3;
    const E_BIG_F_TOO_HIGH: u64 = 4;
    const E_TOO_MANY_TRANSMITTERS: u64 = 5;
    const E_NO_TRANSMITTERS: u64 = 6;
    const E_REPEATED_SIGNERS: u64 = 7;
    const E_REPEATED_TRANSMITTERS: u64 = 8;
    const E_FORKED_CHAIN: u64 = 9;
    const E_CONFIG_DIGEST_MISMATCH: u64 = 10;
    const E_UNAUTHORIZED_TRANSMITTER: u64 = 11;
    const E_WRONG_NUMBER_OF_SIGNATURES: u64 = 12;
    const E_COULD_NOT_VALIDATE_SIGNER_KEY: u64 = 13;
    const E_INVALID_REPORT_CONTEXT_LENGTH: u64 = 14;
    const E_INVALID_CONFIG_DIGEST_LENGTH: u64 = 15;
    const E_INVALID_SEQUENCE_LENGTH: u64 = 16;
    const E_UNAUTHORIZED_SIGNER: u64 = 17;
    const E_NON_UNIQUE_SIGNATURES: u64 = 18;
    const E_INVALID_SIGNATURE: u64 = 19;
    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 20;
    const E_INVALID_SIGNATURE_LENGTH: u64 = 21;

    public fun new(event_account: &signer): OCR3BaseState {
        OCR3BaseState {
            chain_id: chain_id::get(),
            ocr3_configs: table::new(),
            signer_oracles: table::new(),
            transmitter_oracles: table::new(),
            config_set_events: account::new_event_handle(event_account),
            transmitted_events: account::new_event_handle(event_account)
        }
    }

    public fun ocr_plugin_type_commit(): u8 {
        OCR_PLUGIN_TYPE_COMMIT
    }

    public fun ocr_plugin_type_execution(): u8 {
        OCR_PLUGIN_TYPE_EXECUTION
    }

    public fun set_ocr3_config(
        caller: &signer,
        ocr3_state: &mut OCR3BaseState,
        config_digest: vector<u8>,
        ocr_plugin_type: u8,
        big_f: u8,
        is_signature_verification_enabled: bool,
        signers: vector<vector<u8>>,
        transmitters: vector<address>
    ) {
        let caller_address = signer::address_of(caller);
        auth::assert_only_owner(caller_address);
        assert!(big_f != 0, error::invalid_argument(E_BIG_F_MUST_BE_POSITIVE));

        assert!(
            config_digest.length() == 32,
            error::invalid_argument(E_INVALID_CONFIG_DIGEST_LENGTH)
        );

        let ocr_config =
            ocr3_state.ocr3_configs.borrow_mut_with_default(
                ocr_plugin_type,
                OCRConfig {
                    config_info: ConfigInfo {
                        config_digest: vector[],
                        big_f: 0,
                        n: 0,
                        is_signature_verification_enabled: false
                    },
                    signers: vector[],
                    transmitters: vector[]
                }
            );

        let config_info = &mut ocr_config.config_info;

        // If F is 0, then the config is not yet set.
        if (config_info.big_f == 0) {
            config_info.is_signature_verification_enabled =
                is_signature_verification_enabled;
        } else {
            assert!(
                config_info.is_signature_verification_enabled
                    == is_signature_verification_enabled,
                error::invalid_argument(E_STATIC_CONFIG_CANNOT_BE_CHANGED)
            );
        };

        assert!(
            transmitters.length() <= MAX_NUM_ORACLES,
            error::invalid_argument(E_TOO_MANY_TRANSMITTERS)
        );
        assert!(transmitters.length() > 0, error::invalid_argument(E_NO_TRANSMITTERS));

        if (is_signature_verification_enabled) {
            assert!(
                signers.length() <= MAX_NUM_ORACLES,
                error::invalid_argument(E_TOO_MANY_SIGNERS)
            );
            assert!(
                signers.length() > 3 * (big_f as u64),
                error::invalid_argument(E_BIG_F_TOO_HIGH)
            );
            // NOTE: Transmitters cannot exceed signers. Transmitters do not have to be >= 3F + 1 because they can
            // match >= 3fChain + 1, where fChain <= F. fChain is not represented in MultiOCR3Base - so we skip this check.
            assert!(
                signers.length() >= transmitters.length(),
                error::invalid_argument(E_TOO_MANY_TRANSMITTERS)
            );

            config_info.n = signers.length() as u8;

            ocr_config.signers = signers;

            assign_signer_oracles(
                &mut ocr3_state.signer_oracles, ocr_plugin_type, &signers
            );
        };

        ocr_config.transmitters = transmitters;

        assign_transmitter_oracles(
            &mut ocr3_state.transmitter_oracles,
            ocr_plugin_type,
            &transmitters
        );

        config_info.big_f = big_f;
        config_info.config_digest = config_digest;

        event::emit_event(
            &mut ocr3_state.config_set_events,
            ConfigSet {
                ocr_plugin_type,
                config_digest,
                signers,
                transmitters,
                big_f
            }
        );
    }

    inline fun assign_signer_oracles(
        signer_oracles: &mut Table<u8, vector<ed25519::UnvalidatedPublicKey>>,
        ocr_plugin_type: u8,
        signers: &vector<vector<u8>>
    ) {
        signers.for_each_ref(
            |signer_key| {
                address::assert_non_zero_address_vector(signer_key);
            }
        );

        assert!(!has_duplicates(signers), error::invalid_argument(E_REPEATED_SIGNERS));

        let validated_signers =
            signers.map_ref(
                |signer| {
                    let maybe_validated_public_key =
                        ed25519::new_validated_public_key_from_bytes(*signer);
                    assert!(
                        maybe_validated_public_key.is_some(),
                        error::invalid_argument(E_COULD_NOT_VALIDATE_SIGNER_KEY)
                    );
                    ed25519::public_key_into_unvalidated(
                        maybe_validated_public_key.extract()
                    )
                }
            );

        signer_oracles.upsert(ocr_plugin_type, validated_signers);
    }

    inline fun assign_transmitter_oracles(
        transmitter_oracles: &mut Table<u8, vector<address>>,
        ocr_plugin_type: u8,
        transmitters: &vector<address>
    ) {
        transmitters.for_each_ref(
            |transmitter_addr| {
                address::assert_non_zero_address(*transmitter_addr);
            }
        );

        assert!(
            !has_duplicates(transmitters),
            error::invalid_argument(E_REPEATED_TRANSMITTERS)
        );

        transmitter_oracles.upsert(ocr_plugin_type, *transmitters);
    }

    public fun transmit(
        ocr3_state: &mut OCR3BaseState,
        transmitter: address,
        ocr_plugin_type: u8,
        report_context: vector<vector<u8>>,
        report: vector<u8>,
        signatures: vector<vector<u8>>
    ) {
        let ocr_config = ocr3_state.ocr3_configs.borrow(ocr_plugin_type);
        let config_info = &ocr_config.config_info;

        assert!(
            report_context.length() == 2,
            error::invalid_argument(E_INVALID_REPORT_CONTEXT_LENGTH)
        );

        let config_digest = report_context[0];
        assert!(
            config_digest.length() == 32,
            error::invalid_argument(E_INVALID_CONFIG_DIGEST_LENGTH)
        );

        let sequence_bytes = report_context[1];
        assert!(
            sequence_bytes.length() == 32,
            error::invalid_argument(E_INVALID_SEQUENCE_LENGTH)
        );

        assert!(
            config_digest == config_info.config_digest,
            error::invalid_argument(E_CONFIG_DIGEST_MISMATCH)
        );

        assert_chain_not_forked(ocr3_state);

        let plugin_transmitters = ocr3_state.transmitter_oracles.borrow(ocr_plugin_type);
        assert!(
            plugin_transmitters.contains(&transmitter),
            error::permission_denied(E_UNAUTHORIZED_TRANSMITTER)
        );

        if (config_info.is_signature_verification_enabled) {
            assert!(
                signatures.length() == (config_info.big_f as u64) + 1,
                error::invalid_argument(E_WRONG_NUMBER_OF_SIGNATURES)
            );

            let hashed_report = hash_report(report, config_digest, sequence_bytes);
            let plugin_signers = ocr3_state.signer_oracles.borrow(ocr_plugin_type);
            verify_signature(plugin_signers, hashed_report, signatures);
        };

        let sequence_number: u64 = deserialize_sequence_bytes(sequence_bytes);
        event::emit_event(
            &mut ocr3_state.transmitted_events,
            Transmitted { ocr_plugin_type, config_digest, sequence_number }
        );
    }

    public fun latest_config_details(
        ocr3_state: &OCR3BaseState, ocr_plugin_type: u8
    ): OCRConfig {
        let ocr_config = ocr3_state.ocr3_configs.borrow(ocr_plugin_type);
        *ocr_config
    }

    public fun assert_chain_not_forked(ocr3_state: &OCR3BaseState) {
        assert!(
            chain_id::get() == ocr3_state.chain_id,
            error::invalid_state(E_FORKED_CHAIN)
        );
    }

    // equivalent of uint64(uint256(reportContext[1]))
    public inline fun deserialize_sequence_bytes(
        sequence_bytes: vector<u8>
    ): u64 {
        let len = sequence_bytes.length();
        let result: u64 = 0;
        for (i in (len - 8)..len) {
            result = (result << 8) + (sequence_bytes[i] as u64);
        };
        result
    }

    // equivalent of keccak256(abi.encodePacked(keccak256(report), reportContext))
    inline fun hash_report(
        report: vector<u8>, config_digest: vector<u8>, sequence_bytes: vector<u8>
    ): vector<u8> {
        let combined = copy report;
        combined.append(config_digest);
        combined.append(sequence_bytes);
        aptos_hash::blake2b_256(combined)
    }

    inline fun verify_signature(
        signers: &vector<ed25519::UnvalidatedPublicKey>,
        hashed_report: vector<u8>,
        signatures: vector<vector<u8>>
    ) {
        let seen = bit_vector::new(signers.length());
        signatures.for_each_ref(
            |signature_bytes| {
                let signature_bytes: &vector<u8> = signature_bytes;
                assert!(
                    signature_bytes.length() == 96,
                    error::invalid_argument(E_INVALID_SIGNATURE_LENGTH)
                );

                let public_key =
                    ed25519::new_unvalidated_public_key_from_bytes(
                        signature_bytes.slice(0, 32)
                    );
                let (exists, index) = signers.index_of(&public_key);
                assert!(exists, error::invalid_argument(E_UNAUTHORIZED_SIGNER));
                assert!(
                    !seen.is_index_set(index),
                    error::invalid_argument(E_NON_UNIQUE_SIGNATURES)
                );
                seen.set(index);
                let signature =
                    ed25519::new_signature_from_bytes(signature_bytes.slice(32, 96));

                let verified =
                    ed25519::signature_verify_strict(
                        &signature, &public_key, hashed_report
                    );
                assert!(verified, error::invalid_argument(E_INVALID_SIGNATURE));
            }
        );
    }

    inline fun has_duplicates<T>(a: &vector<T>): bool {
        let len = a.length();
        let found = false;

        for (i in 0..len) {
            for (j in (i + 1)..len) {
                if (a[i] == a[j]) {
                    found = true;
                }
            }
        };
        found
    }

    public fun config_signers(ocr_config: &OCRConfig): vector<vector<u8>> {
        ocr_config.signers
    }

    public fun config_transmitters(ocr_config: &OCRConfig): vector<address> {
        ocr_config.transmitters
    }

    #[test]
    fun deserialize_sequence_number() {
        let report_context_one =
            x"0000000000000000000000000000000000000000000000000000000000000009";
        let ocr_sequence_number = deserialize_sequence_bytes(report_context_one);
        assert!(ocr_sequence_number == 9);
    }

    // ===================== Test functions =====================
    #[test_only]
    public fun destroy_ocr3_state(ocr3_state: OCR3BaseState) {
        let OCR3BaseState {
            chain_id: _,
            ocr3_configs,
            signer_oracles,
            transmitter_oracles,
            config_set_events,
            transmitted_events
        } = ocr3_state;

        table::drop_unchecked(ocr3_configs);
        table::drop_unchecked(signer_oracles);
        table::drop_unchecked(transmitter_oracles);
        event::destroy_handle(config_set_events);
        event::destroy_handle(transmitted_events);
    }
}
