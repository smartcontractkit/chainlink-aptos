module ccip::rmn_remote;

use std::bcs;
use sui::ecdsa_k1;
use sui::event;
use sui::hash;
use std::string::{Self, String};
use sui::vec_map::{Self, VecMap};

use ccip::eth_abi;
use ccip::merkle_proof;
use ccip::state_object::{Self, CCIPObjectRef, OwnerCap};

public struct RMNRemoteState has key, store {
    id: UID,
    local_chain_selector: u64,
    config: Config,
    config_count: u32,
    // most operations are O(n) with vec map, but it's easy to retrieve all the keys
    signers: VecMap<vector<u8>, bool>,
    cursed_subjects: VecMap<vector<u8>, bool>
}

public struct Config has copy, drop, store {
    rmn_home_contract_config_digest: vector<u8>,
    signers: vector<Signer>,
    f_sign: u64
}

public struct Signer has copy, drop, store {
    onchain_public_key: vector<u8>,
    node_index: u64
}

// TODO: figure out what to do with chain_id. Cannot get it from Sui library.
public struct Report has drop {
    dest_chain_selector: u64,
    rmn_remote_contract_address: address,
    off_ramp_address: address,
    rmn_home_contract_config_digest: vector<u8>,
    merkle_roots: vector<MerkleRoot>
}

public struct MerkleRoot has drop {
    source_chain_selector: u64,
    on_ramp_address: vector<u8>,
    min_seq_nr: u64,
    max_seq_nr: u64,
    merkle_root: vector<u8>
}

public struct VersionedConfig has copy, drop {
    version: u32,
    config: Config
}

public struct ConfigSet has copy, drop {
    version: u32,
    config: Config
}

public struct Cursed has copy, drop {
    subjects: vector<vector<u8>>
}

public struct Uncursed has copy, drop {
    subjects: vector<vector<u8>>
}

const SIGNATURE_NUM_BYTES: u64 = 64;
const GLOBAL_CURSE_SUBJECT: vector<u8> = x"01000000000000000000000000000001";

const E_ALREADY_INITIALIZED: u64 = 1;
const E_ALREADY_CURSED: u64 = 2;
const E_CONFIG_NOT_SET: u64 = 3;
const E_DUPLICATE_SIGNER: u64 = 4;
const E_INVALID_SIGNATURE: u64 = 5;
const E_INVALID_SIGNER_ORDER: u64 = 6;
const E_NOT_ENOUGH_SIGNERS: u64 = 7;
const E_NOT_CURSED: u64 = 8;
const E_OUT_OF_ORDER_SIGNATURES: u64 = 9;
const E_THRESHOLD_NOT_MET: u64 = 10;
const E_UNEXPECTED_SIGNER: u64 = 11;
const E_ZERO_VALUE_NOT_ALLOWED: u64 = 12;
const E_MERKLE_ROOT_LENGTH_MISMATCH: u64 = 13;
const E_INVALID_DIGEST_LENGTH: u64 = 14;
const E_SIGNERS_MISMATCH: u64 = 15;
const E_INVALID_SUBJECT_LENGTH: u64 = 16;
const E_INVALID_PUBLIC_KEY_LENGTH: u64 = 17;

public fun type_and_version(): String {
    string::utf8(b"RMNRemote 1.6.0")
}

public fun initialize(
    ref: &mut CCIPObjectRef,
    _: &OwnerCap,
    local_chain_selector: u64,
    ctx: &mut TxContext
) {
    assert!(
        !state_object::contains<RMNRemoteState>(ref),
        E_ALREADY_INITIALIZED
    );
    assert!(
        local_chain_selector != 0,
        E_ZERO_VALUE_NOT_ALLOWED
    );

    let state = RMNRemoteState {
        id: object::new(ctx),
        local_chain_selector,
        config: Config {
            rmn_home_contract_config_digest: vector[],
            signers: vector[],
            f_sign: 0
        },
        config_count: 0,
        signers: vec_map::empty<vector<u8>, bool>(),
        cursed_subjects: vec_map::empty<vector<u8>, bool>()
    };

    state_object::add(ref, state, ctx);
}

fun calculate_report(report: &Report): vector<u8> {
    let mut digest = vector[];
    eth_abi::encode_right_padded_bytes32(&mut digest, get_report_digest_header());
    eth_abi::encode_u64(&mut digest, report.dest_chain_selector);
    eth_abi::encode_address(&mut digest, report.rmn_remote_contract_address);
    eth_abi::encode_address(&mut digest, report.off_ramp_address);
    eth_abi::encode_right_padded_bytes32(&mut digest, report.rmn_home_contract_config_digest);
    report.merkle_roots.do_ref!(
        |merkle_root| {
            let merkle_root: &MerkleRoot = merkle_root;
            eth_abi::encode_u64(&mut digest, merkle_root.source_chain_selector);
            eth_abi::encode_bytes(&mut digest, merkle_root.on_ramp_address);
            eth_abi::encode_u64(&mut digest, merkle_root.min_seq_nr);
            eth_abi::encode_u64(&mut digest, merkle_root.max_seq_nr);
            eth_abi::encode_right_padded_bytes32(&mut digest, merkle_root.merkle_root);
        }
    );
    digest
}

public fun verify(
    ref: &CCIPObjectRef,
    off_ramp_state_address: address,
    merkle_root_source_chain_selectors: vector<u64>,
    merkle_root_on_ramp_addresses: vector<vector<u8>>,
    merkle_root_min_seq_nrs: vector<u64>,
    merkle_root_max_seq_nrs: vector<u64>,
    merkle_root_values: vector<vector<u8>>,
    signatures: vector<vector<u8>>
): bool {
    let state = state_object::borrow<RMNRemoteState>(ref);

    assert!(state.config_count > 0, E_CONFIG_NOT_SET);

    let signatures_len = signatures.length();
    assert!(
        signatures_len >= (state.config.f_sign + 1),
        E_THRESHOLD_NOT_MET
    );

    let merkle_root_len = merkle_root_source_chain_selectors.length();
    assert!(
        merkle_root_len == merkle_root_on_ramp_addresses.length(),
        E_MERKLE_ROOT_LENGTH_MISMATCH
    );
    assert!(
        merkle_root_len == merkle_root_min_seq_nrs.length(),
        E_MERKLE_ROOT_LENGTH_MISMATCH
    );
    assert!(
        merkle_root_len == merkle_root_max_seq_nrs.length(),
        E_MERKLE_ROOT_LENGTH_MISMATCH
    );
    assert!(
        merkle_root_len == merkle_root_values.length(),
        E_MERKLE_ROOT_LENGTH_MISMATCH
    );

    // Since we cannot pass public structs, we need to reconpublic struct it from the individual components.
    let mut merkle_roots = vector[];
    let mut i = 0;
    while (i < merkle_root_len) {
        let source_chain_selector = merkle_root_source_chain_selectors[i];
        let on_ramp_address = merkle_root_on_ramp_addresses[i];
        let min_seq_nr = merkle_root_min_seq_nrs[i];
        let max_seq_nr = merkle_root_max_seq_nrs[i];
        let merkle_root = merkle_root_values[i];
        merkle_roots.push_back(
            MerkleRoot {
                source_chain_selector,
                on_ramp_address,
                min_seq_nr,
                max_seq_nr,
                merkle_root
            }
        );
        i = i + 1;
    };

    // TODO: verify this.
    // currently we use the CCIP state object id as rmn_remote_contract_address and offramp state address as off_ramp_address.
    let report = Report {
        dest_chain_selector: state.local_chain_selector,
        rmn_remote_contract_address: object::id_to_address(&object::id(ref)),
        off_ramp_address: off_ramp_state_address,
        rmn_home_contract_config_digest: state.config.rmn_home_contract_config_digest,
        merkle_roots
    };

    let digest = calculate_report(&report);

    let mut previous_eth_address = vector[];
    let mut i = 0;
    while (i < signatures_len) {
        let signature_bytes = signatures[i];

        assert!(signature_bytes.length() == SIGNATURE_NUM_BYTES, E_INVALID_SIGNATURE);

        let eth_address = ecrecover_to_eth_address(signature_bytes, digest);

        assert!(
            state.signers.contains(&eth_address),
            E_UNEXPECTED_SIGNER
        );
        if (i > 0) {
            assert!(
                merkle_proof::vector_u8_gt(&eth_address, &previous_eth_address),
                E_OUT_OF_ORDER_SIGNATURES
            );
        };
        previous_eth_address = eth_address;

        i = i + 1;
    };

    true
}

/// Recover the Ethereum address using the signature and message, assuming the signature was
/// produced over the Keccak256 hash of the message.
/// this implementation is based on the SUI example: https://github.com/MystenLabs/sui/blob/main/examples/move/crypto/ecdsa_k1/sources/example.move#L62
fun ecrecover_to_eth_address(
    mut signature: vector<u8>,
    msg: vector<u8>,
): vector<u8> {
    // no normalization is done bc the signature only includes 64 bytes.
    // add a 0 byte to the end of the signature to make it 65 bytes.
    signature.push_back(0);
    // Ethereum signature is produced with Keccak256 hash of the message, so the last param is
    // 0.
    let pubkey = ecdsa_k1::secp256k1_ecrecover(&signature, &msg, 0);
    let uncompressed = ecdsa_k1::decompress_pubkey(&pubkey);

    // Take the last 64 bytes of the uncompressed pubkey.
    let mut uncompressed_64 = vector[];
    let mut i = 1;
    while (i < 65) {
        uncompressed_64.push_back(uncompressed[i]);
        i = i + 1;
    };

    // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey.
    let hashed = sui::hash::keccak256(&uncompressed_64);
    let mut addr = vector[];
    let mut i = 12;
    while (i < 32) {
        addr.push_back(hashed[i]);
        i = i + 1;
    };
    addr
}

// TODO: figure out what this does bc this won't work here. caller needs to know ccip package id already
public fun get_arm(): address {
    @ccip
}

public fun set_config(
    ref: &mut CCIPObjectRef,
    _: &OwnerCap,
    rmn_home_contract_config_digest: vector<u8>,
    signer_onchain_public_keys: vector<vector<u8>>,
    node_indexes: vector<u64>,
    f_sign: u64,
) {
    let state = state_object::borrow_mut<RMNRemoteState>(ref);

    assert!(
        rmn_home_contract_config_digest.length() == 32,
        E_INVALID_DIGEST_LENGTH
    );

    assert!(
        eth_abi::decode_u256_value(rmn_home_contract_config_digest) != 0,
        E_ZERO_VALUE_NOT_ALLOWED
    );

    let signers_len = signer_onchain_public_keys.length();
    assert!(
        signers_len == node_indexes.length(),
        E_SIGNERS_MISMATCH
    );

    let mut i = 1;
    while (i < signers_len) {
        let previous_node_index = node_indexes[i - 1];
        let current_node_index = node_indexes[i];
        assert!(
            previous_node_index < current_node_index,
            E_INVALID_SIGNER_ORDER
        );
        i = i + 1;
    };

    assert!(
        signers_len >= (2 * f_sign + 1),
        E_NOT_ENOUGH_SIGNERS
    );

    let keys = state.signers.keys();
    let mut i = 0;
    let keys_len = keys.length();
    while (i < keys_len) {
        let key = keys[i];
        state.signers.remove(&key);
        i = i + 1;
    };

    let signers = signer_onchain_public_keys.zip_map_ref!(
        &node_indexes,
        |signer_public_key_bytes, node_indexes| {
            let signer_public_key_bytes: vector<u8> = *signer_public_key_bytes;
            let node_index: u64 = *node_indexes;
            // expect an ethereum address of 20 bytes.
            assert!(
                signer_public_key_bytes.length() == 20,
                E_INVALID_PUBLIC_KEY_LENGTH
            );
            assert!(
                !state.signers.contains(&signer_public_key_bytes),
                E_DUPLICATE_SIGNER
            );
            state.signers.insert(signer_public_key_bytes, true);
            Signer {
                onchain_public_key: signer_public_key_bytes,
                node_index
            }
        }
    );

    let new_config = Config {
        rmn_home_contract_config_digest,
        signers,
        f_sign
    };
    state.config = new_config;

    let new_config_count = state.config_count + 1;
    state.config_count = new_config_count;

    event::emit(ConfigSet { version: new_config_count, config: new_config });
}

public fun get_versioned_config(ref: &CCIPObjectRef): VersionedConfig {
    let state = state_object::borrow<RMNRemoteState>(ref);

    VersionedConfig { version: state.config_count, config: state.config }
}

public fun get_versioned_config_fields(vc: VersionedConfig): (u32, vector<u8>, vector<vector<u8>>, vector<u64>, u64) {
    let digest = vc.config.rmn_home_contract_config_digest;
    let signers = vc.config.signers;
    let f_sign = vc.config.f_sign;
    let mut pub_keys = vector[];
    let mut node_indexes = vector[];
    signers.do_ref!(
        |signer| {
            let signer: &Signer = signer;
            pub_keys.push_back(signer.onchain_public_key);
            node_indexes.push_back(signer.node_index);
        }
    );

    (vc.version, digest, pub_keys, node_indexes, f_sign)
}

public fun get_local_chain_selector(ref: &CCIPObjectRef): u64 {
    let state = state_object::borrow<RMNRemoteState>(ref);

    state.local_chain_selector
}

public fun get_report_digest_header(): vector<u8> {
    hash::keccak256(&b"RMN_V1_6_ANY2SUI_REPORT")
}

public fun curse(
    ref: &mut CCIPObjectRef,
    owner_cap: &OwnerCap,
    subject: vector<u8>,
) {
    curse_multiple(ref, owner_cap, vector[subject]);
}

public fun curse_multiple(
    ref: &mut CCIPObjectRef,
    _: &OwnerCap,
    subjects: vector<vector<u8>>,
) {
    let state = state_object::borrow_mut<RMNRemoteState>(ref);

    subjects.do_ref!(
        |subject| {
            let subject: vector<u8> = *subject;
            assert!(
                subject.length() == 16,
                E_INVALID_SUBJECT_LENGTH
            );
            assert!(
                !state.cursed_subjects.contains(&subject),
                E_ALREADY_CURSED
            );
            state.cursed_subjects.insert(subject, true);
        }
    );
    event::emit(Cursed { subjects });
}

public fun uncurse(
    ref: &mut CCIPObjectRef,
    owner_cap: &OwnerCap,
    subject: vector<u8>,
) {
    uncurse_multiple(ref, owner_cap, vector[subject]);
}

public fun uncurse_multiple(
    ref: &mut CCIPObjectRef,
    _: &OwnerCap,
    subjects: vector<vector<u8>>,
) {
    let state = state_object::borrow_mut<RMNRemoteState>(ref);

    subjects.do_ref!(
        |subject| {
            let subject: vector<u8> = *subject;
            assert!(
                state.cursed_subjects.contains(&subject),
                E_NOT_CURSED
            );
            state.cursed_subjects.remove(&subject);
        }
    );
    event::emit(Uncursed { subjects });
}

public fun get_cursed_subjects(ref: &CCIPObjectRef): vector<vector<u8>> {
    let state = state_object::borrow<RMNRemoteState>(ref);

    state.cursed_subjects.keys()
}

#[allow(implicit_const_copy)]
public fun is_cursed_global(ref: &CCIPObjectRef): bool {
    let state = state_object::borrow<RMNRemoteState>(ref);

    state.cursed_subjects.contains(&GLOBAL_CURSE_SUBJECT)
}

public fun is_cursed(ref: &CCIPObjectRef, subject: vector<u8>): bool {
    let state = state_object::borrow<RMNRemoteState>(ref);

    state.cursed_subjects.contains(&subject) || is_cursed_global(ref)
}

public fun is_cursed_u128(ref: &CCIPObjectRef, subject_value: u128): bool {
    let mut subject = bcs::to_bytes(&subject_value);
    subject.reverse();
    is_cursed(ref, subject)
}

public fun get_active_signers(ref: &CCIPObjectRef): vector<vector<u8>> {
    let state = state_object::borrow<RMNRemoteState>(ref);

    let mut active_signers = vector[];
    state.signers.keys().do_ref!(
        |signer| {
            let signer: vector<u8> = *signer;
            if (*state.signers.get(&signer)) {
                active_signers.push_back(signer);
            }
        }
    );
    active_signers
}

#[test_only]
public fun get_config(config: &Config): (vector<u8>, vector<Signer>, u64) {
    (config.rmn_home_contract_config_digest, config.signers, config.f_sign)
}

#[test_only]
public fun get_version(vc: &VersionedConfig): (u32, Config) {
    (vc.version, vc.config)
}
