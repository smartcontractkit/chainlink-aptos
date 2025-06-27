module ccip_offramp::ocr3_base;

use std::bit_vector;

use sui::ed25519;
use sui::event;
use sui::hash;
use sui::table::{Self, Table};

use ccip::address;

const MAX_NUM_ORACLES: u64 = 256;
const OCR_PLUGIN_TYPE_COMMIT: u8 = 0;
const OCR_PLUGIN_TYPE_EXECUTION: u8 = 1;
const PUBLIC_KEY_NUM_BYTES: u64 = 32;

public struct UnvalidatedPublicKey has copy, drop, store {
    bytes: vector<u8>
}

public struct ConfigInfo has store, drop, copy {
    config_digest: vector<u8>,
    big_f: u8,
    n: u8,
    is_signature_verification_enabled: bool
}

public struct OCRConfig has store, drop, copy {
    config_info: ConfigInfo,
    signers: vector<vector<u8>>,
    transmitters: vector<address>
}

// this struct is stored in offramp state object
public struct OCR3BaseState has key, store {
    id: UID,
    // ocr plugin type -> ocr config
    ocr3_configs: Table<u8, OCRConfig>,
    // ocr plugin type -> signers
    signer_oracles: Table<u8, vector<UnvalidatedPublicKey>>,
    // ocr plugin type -> transmitters
    transmitter_oracles: Table<u8, vector<address>>
}

public struct ConfigSet has copy, drop {
    ocr_plugin_type: u8,
    config_digest: vector<u8>,
    signers: vector<vector<u8>>,
    transmitters: vector<address>,
    big_f: u8
}

public struct Transmitted has copy, drop {
    ocr_plugin_type: u8,
    config_digest: vector<u8>,
    sequence_number: u64
}

const EWrongPubkeySize: u64 = 1;
const EBigFMustBePositive: u64 = 2;
const EStaticConfigCannotBeChanged: u64 = 3;
const ETooManySigners: u64 = 4;
const EBigFTooHigh: u64 = 5;
const ETooManyTransmitters: u64 = 6;
const ENoTransmitters: u64 = 7;
const ERepeatedSigners: u64 = 8;
const ERepeatedTransmitters: u64 = 9;
const EConfigDigestMismatch: u64 = 10;
const EUnauthorizedTransmitter: u64 = 11;
const EWrongNumberOfSignatures: u64 = 12;
const ECouldNotValidateSignerKey: u64 = 13;
const EInvalidReportContextLength: u64 = 14;
const EInvalidConfigDigestLength: u64 = 15;
const EInvalidSequenceLength: u64 = 16;
const EUnauthorizedSigner: u64 = 17;
const ENonUniqueSignatures: u64 = 18;
const EInvalidSignature: u64 = 19;
const EOutOfBytes: u64 = 20;
const EConfigNotSet: u64 = 21;
const EInvalidSignatureLength: u64 = 22;

// there is no init or initialize functions in ocr3 base
// ocr3 base state is only created and stored in offramp state
public fun new(ctx: &mut TxContext): OCR3BaseState {
    OCR3BaseState {
        id: object::new(ctx),
        ocr3_configs: table::new(ctx),
        signer_oracles: table::new(ctx),
        transmitter_oracles: table::new(ctx)
    }
}

public fun ocr_plugin_type_commit(): u8 {
    OCR_PLUGIN_TYPE_COMMIT
}

public fun ocr_plugin_type_execution(): u8 {
    OCR_PLUGIN_TYPE_EXECUTION
}

public fun set_ocr3_config(
    ocr3_state: &mut OCR3BaseState,
    config_digest: vector<u8>,
    ocr_plugin_type: u8,
    big_f: u8,
    is_signature_verification_enabled: bool,
    signers: vector<vector<u8>>,
    transmitters: vector<address>
) {
    assert!(big_f != 0, EBigFMustBePositive);
    assert!(
        config_digest.length() == 32,
        EInvalidConfigDigestLength
    );

    let ocr_config = if (ocr3_state.ocr3_configs.contains(ocr_plugin_type)) {
        ocr3_state.ocr3_configs.borrow_mut(ocr_plugin_type)
    } else {
        ocr3_state.ocr3_configs.add(
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
            ocr3_state.ocr3_configs.borrow_mut(ocr_plugin_type)
    };

    let config_info = &mut ocr_config.config_info;

    // If F is 0, then the config is not yet set.
    if (config_info.big_f == 0) {
        config_info.is_signature_verification_enabled = is_signature_verification_enabled;
    } else {
        assert!(
            config_info.is_signature_verification_enabled == is_signature_verification_enabled,
            EStaticConfigCannotBeChanged
        );
    };

    assert!(
        transmitters.length() <= MAX_NUM_ORACLES,
        ETooManyTransmitters
    );
    assert!(
        transmitters.length() > 0,
        ENoTransmitters
    );

    if (is_signature_verification_enabled) {
        assert!(
            signers.length() <= MAX_NUM_ORACLES,
            ETooManySigners
        );
        assert!(
            signers.length() > 3 * (big_f as u64),
            EBigFTooHigh
        );
        // NOTE: Transmitters cannot exceed signers. Transmitters do not have to be >= 3F + 1 because they can
        // match >= 3fChain + 1, where fChain <= F. fChain is not represented in MultiOCR3Base - so we skip this check.
        assert!(
            signers.length() >= transmitters.length(),
            ETooManyTransmitters
        );

        config_info.n = signers.length() as u8;

        ocr_config.signers = signers;

        assign_signer_oracles(
            &mut ocr3_state.signer_oracles, ocr_plugin_type, &signers
        );
    };

    ocr_config.transmitters = transmitters;

    assign_transmitter_oracles(
        &mut ocr3_state.transmitter_oracles, ocr_plugin_type, &transmitters
    );

    config_info.big_f = big_f;
    config_info.config_digest = config_digest;

    event::emit(
        ConfigSet { ocr_plugin_type, config_digest, signers, transmitters, big_f }
    );
}

fun assign_signer_oracles(
    signer_oracles: &mut Table<u8, vector<UnvalidatedPublicKey>>,
    ocr_plugin_type: u8,
    signers: &vector<vector<u8>>
) {
    signers.do_ref!(
        |signer| {
            address::assert_non_zero_address_vector(signer);
        }
    );
    assert!(!has_duplicates(signers), ERepeatedSigners);

    let validated_signers = signers.map_ref!(
        |signer| {
            assert!(
                validate_public_key(signer),
                ECouldNotValidateSignerKey
            );
            UnvalidatedPublicKey { bytes: *signer }
        }
    );

    if (signer_oracles.contains(ocr_plugin_type)) {
        let _old_value = signer_oracles.remove(ocr_plugin_type);
    };
    signer_oracles.add(ocr_plugin_type, validated_signers);
}

fun assign_transmitter_oracles(
    transmitter_oracles: &mut Table<u8, vector<address>>,
    ocr_plugin_type: u8,
    transmitters: &vector<address>
) {
    transmitters.do_ref!(
        |transmitter_addr| {
            address::assert_non_zero_address(*transmitter_addr);
        }
    );
    assert!(
        !has_duplicates(transmitters),
        ERepeatedTransmitters
    );

    if (transmitter_oracles.contains(ocr_plugin_type)) {
        let _old_value = transmitter_oracles.remove(ocr_plugin_type);
    };
    transmitter_oracles.add(ocr_plugin_type, *transmitters);
}

public(package) fun transmit(
    ocr3_state: &OCR3BaseState,
    transmitter: address,
    ocr_plugin_type: u8,
    report_context: vector<vector<u8>>,
    report: vector<u8>,
    signatures: vector<vector<u8>>,
    _ctx: &TxContext
) {
    let ocr_config = ocr3_state.ocr3_configs.borrow(ocr_plugin_type);
    let config_info = &ocr_config.config_info;

    assert!(
        report_context.length() == 2,
        EInvalidReportContextLength
    );

    let config_digest = report_context[0];
    assert!(
        config_digest.length() == 32,
        EInvalidConfigDigestLength
    );

    let sequence_bytes = report_context[1];
    assert!(
        sequence_bytes.length() == 32,
        EInvalidSequenceLength
    );

    assert!(
        config_digest == config_info.config_digest,
        EConfigDigestMismatch
    );

    let plugin_transmitters = ocr3_state.transmitter_oracles[ocr_plugin_type];
    assert!(
        plugin_transmitters.contains(&transmitter),
        EUnauthorizedTransmitter
    );

    if (config_info.is_signature_verification_enabled) {
        assert!(
            signatures.length() == (config_info.big_f as u64) + 1,
            EWrongNumberOfSignatures
        );

        let hashed_report = hash_report(report, config_digest, sequence_bytes);
        let plugin_signers = &ocr3_state.signer_oracles[ocr_plugin_type];
        verify_signature(plugin_signers, hashed_report, signatures);
    };

    let sequence_number: u64 = deserialize_sequence_bytes(sequence_bytes);
    event::emit(Transmitted { ocr_plugin_type, config_digest, sequence_number });
}

public fun latest_config_details(
    state: &OCR3BaseState, ocr_plugin_type: u8
): OCRConfig {
    assert!(
        state.ocr3_configs.contains(ocr_plugin_type),
        EConfigNotSet
    );
    let ocr_config = &state.ocr3_configs[ocr_plugin_type];
    *ocr_config
}

// equivalent of uint64(uint256(reportContext[1]))
public fun deserialize_sequence_bytes(
    sequence_bytes: vector<u8>
): u64 {
    let len = sequence_bytes.length();
    let mut result: u64 = 0;
    let mut i = len - 8;
    while (i < len) {
        result = (result << 8) + (sequence_bytes[i] as u64);
        i = i + 1;
    };
    result
}

fun hash_report(
    mut report: vector<u8>, config_digest: vector<u8>, sequence_bytes: vector<u8>
): vector<u8> {
    report.append(config_digest);
    report.append(sequence_bytes);
    hash::blake2b256(&report)
}

fun verify_signature(
    signers: &vector<UnvalidatedPublicKey>,
    hashed_report: vector<u8>,
    signatures: vector<vector<u8>>
) {
    let mut seen = bit_vector::new(signers.length());
    signatures.do_ref!(
        |signature_bytes| {
            assert!(
                signature_bytes.length() == 96,
                EInvalidSignatureLength
            );

            let public_key =
                new_unvalidated_public_key_from_bytes(slice(signature_bytes, 0, 32));
            let (exists, index) = signers.index_of(&public_key);
            assert!(exists, EUnauthorizedSigner);
            assert!(
                !seen.is_index_set(index),
                ENonUniqueSignatures
            );
            seen.set(index);
            let signature = slice(signature_bytes, 32, 64);

            let verified =
                ed25519::ed25519_verify(
                    &signature, &public_key.bytes, &hashed_report
                );
            assert!(verified, EInvalidSignature);
        }
    );
}

fun has_duplicates<T>(a: &vector<T>): bool {
    let len = a.length();
    let mut i = 0;

    while (i < len) {
        let mut j = i + 1;
        while (j < len) {
            if (&a[i] == &a[j]) {
                return true
            };
            j = j + 1;
        };
        i = i + 1;
    };
    false
}

public(package) fun config_signers(ocr_config: &OCRConfig): vector<vector<u8>> {
    ocr_config.signers
}

public(package) fun config_transmitters(ocr_config: &OCRConfig): vector<address> {
    ocr_config.transmitters
}

fun validate_public_key(pubkey: &vector<u8>): bool {
    pubkey.length() == 32
}

fun new_unvalidated_public_key_from_bytes(bytes: vector<u8>): UnvalidatedPublicKey {
    assert!(bytes.length() == PUBLIC_KEY_NUM_BYTES, EWrongPubkeySize);
    UnvalidatedPublicKey { bytes }
}

public fun latest_config_details_fields(
    ocr_config: OCRConfig
): (vector<u8>, u8, u8, bool, vector<vector<u8>>, vector<address>) {
    (
        ocr_config.config_info.config_digest,
        ocr_config.config_info.big_f,
        ocr_config.config_info.n,
        ocr_config.config_info.is_signature_verification_enabled,
        ocr_config.signers,
        ocr_config.transmitters
    )
}

/// Returns a new vector containing `len` elements from `vec`
/// starting at index `start`. Panics if `start + len` exceeds the vector length.
fun slice<T: copy>(vec: &vector<T>, start: u64, len: u64): vector<T> {
    let vec_len = vec.length();
    // Ensure we have enough elements for the slice.
    assert!(start + len <= vec_len, EOutOfBytes);
    let mut new_vec = vector::empty<T>();
    let mut i = start;
    while (i < start + len) {
        // Copy each element from the original vector into the new vector.
        new_vec.push_back(vec[i]);
        i = i + 1;
    };
    new_vec
}

#[test]
fun deserialize_sequence_number() {
    let report_context_one =
        x"0000000000000000000000000000000000000000000000000000000000000009";
    let ocr_sequence_number = deserialize_sequence_bytes(report_context_one);
    assert!(ocr_sequence_number == 9, 1);
}
