module ccip::ocr3_base {
  use std::aptos_hash;
  use std::bit_vector;
  use std::chain_id;
  use std::ed25519;
  use std::error;
  use std::event;
  use std::option;
  use std::table::{Self, Table};
  use std::vector;

  use ccip::ownable;

  const MAX_NUM_ORACLES: u64 = 256;

  struct ConfigInfo has store, drop {
    config_digest: vector<u8>,
    big_f: u8,
    n: u8,
    is_signature_verification_enabled: bool,
  }

  struct OCRConfig has store, drop {
    config_info: ConfigInfo,
    signers: vector<vector<u8>>,
    transmitters: vector<address>,
  }

  struct Oracle has store, drop {
    index: u8,
    role: u8,
  }

  struct OCR3BaseState has store {
    chain_id: u8,
    // ocr plugin type -> ocr config
    ocr3_configs: Table<u8, OCRConfig>,
    // ocr plugin type -> signers
    signer_oracles: Table<u8, vector<ed25519::UnvalidatedPublicKey>>,
    // ocr plugin type -> transmitters
    transmitter_oracles: Table<u8, vector<address>>,
  }

  #[event]
  struct ConfigSet has store, drop {
    ocr_plugin_type: u8,
    config_digest: vector<u8>,
    signers: vector<vector<u8>>,
    transmitters: vector<address>,
    big_f: u8,
  }

  #[event]
  struct Transmitted has store, drop {
    ocr_plugin_type: u8,
    config_digest: vector<u8>,
    sequence_number: u64,
  }

  const E_BIG_F_MUST_BE_POSITIVE: u64 = 1;
  const E_STATIC_CONFIG_CANNOT_BE_CHANGED: u64 = 2;
  const E_TOO_MANY_SIGNERS: u64 = 3;
  const E_BIG_F_TOO_HIGH: u64 = 4;
  const E_TOO_MANY_TRANSMITTERS: u64 = 5;
  const E_NO_TRANSMITTERS: u64 = 6;
  const E_REPEATED_SIGNERS: u64 = 7;
  const E_REPEATED_TRANSMITTERS: u64 = 8;
  const E_ORACLE_CANNOT_BE_ZERO_ADDRESS: u64 = 9;
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
  const E_FORKED_CHAIN: u64 = 20;

  public fun new(): OCR3BaseState {
    OCR3BaseState {
      chain_id: chain_id::get(),
      ocr3_configs: table::new(),
      signer_oracles: table::new(),
      transmitter_oracles: table::new(),
    }
  }

  public fun set_ocr3_config(
    caller: address,
    ownable_state: &ownable::OwnableState,
    ocr3_state: &mut OCR3BaseState,
    config_digest: vector<u8>,
    ocr_plugin_type: u8,
    big_f: u8,
    is_signature_verification_enabled: bool,
    signers: vector<vector<u8>>,
    transmitters: vector<address>,
  ) {
    ownable::assert_only_owner(caller, ownable_state);
    assert!(big_f != 0, error::invalid_argument(E_BIG_F_MUST_BE_POSITIVE));

    let ocr_config = table::borrow_mut_with_default(
      &mut ocr3_state.ocr3_configs,
      ocr_plugin_type,
      OCRConfig {
        config_info: ConfigInfo {
          config_digest: vector[],
          big_f: 0,
          n: 0,
          is_signature_verification_enabled: false,
        },
        signers: vector[],
        transmitters: vector[],
      },
    );

    let config_info = &mut ocr_config.config_info;

    // If F is 0, then the config is not yet set.
    if (config_info.big_f == 0) {
      config_info.is_signature_verification_enabled = is_signature_verification_enabled;
    } else {
      assert!(config_info.is_signature_verification_enabled == is_signature_verification_enabled, error::invalid_argument(E_STATIC_CONFIG_CANNOT_BE_CHANGED));
    };

    assert!(vector::length(&transmitters) <= MAX_NUM_ORACLES, error::invalid_argument(E_TOO_MANY_TRANSMITTERS));
    assert!(vector::length(&transmitters) > 0, error::invalid_argument(E_NO_TRANSMITTERS));

    if (is_signature_verification_enabled) {
      assert!(vector::length(&signers) <= MAX_NUM_ORACLES, error::invalid_argument(E_TOO_MANY_SIGNERS));
      assert!(vector::length(&signers) > 3 * (big_f as u64), error::invalid_argument(E_BIG_F_TOO_HIGH));
      // NOTE: Transmitters cannot exceed signers. Transmitters do not have to be >= 3F + 1 because they can
      // match >= 3fChain + 1, where fChain <= F. fChain is not represented in MultiOCR3Base - so we skip this check.
      assert!(vector::length(&signers) >= vector::length(&transmitters), error::invalid_argument(E_TOO_MANY_TRANSMITTERS));

      config_info.n = vector::length(&signers) as u8;

      ocr_config.signers = signers;

      assign_signer_oracles(&mut ocr3_state.signer_oracles, ocr_plugin_type, &signers);
    };

    ocr_config.transmitters = transmitters;

    assign_transmitter_oracles(&mut ocr3_state.transmitter_oracles, ocr_plugin_type, &transmitters);

    config_info.big_f = big_f;
    config_info.config_digest = config_digest;

    event::emit(ConfigSet {
      ocr_plugin_type, config_digest, signers, transmitters, big_f
    });
  }

  inline fun assign_signer_oracles(signer_oracles: &mut Table<u8, vector<ed25519::UnvalidatedPublicKey>>, ocr_plugin_type: u8, signers: &vector<vector<u8>>) {
    assert!(!has_duplicates(signers), error::invalid_argument(E_REPEATED_SIGNERS));

    let validated_signers = vector::map_ref(signers, |signer| {
      let maybe_validated_public_key = ed25519::new_validated_public_key_from_bytes(*signer);
      assert!(option::is_some(&maybe_validated_public_key), error::invalid_argument(E_COULD_NOT_VALIDATE_SIGNER_KEY));
      ed25519::public_key_into_unvalidated(option::extract(&mut maybe_validated_public_key))
    });

    table::upsert(signer_oracles, ocr_plugin_type, validated_signers);
  }

  inline fun assign_transmitter_oracles(transmitter_oracles: &mut Table<u8, vector<address>>, ocr_plugin_type: u8, transmitters: &vector<address>) {
    assert!(!has_duplicates(transmitters), error::invalid_argument(E_REPEATED_TRANSMITTERS));

    table::upsert(transmitter_oracles, ocr_plugin_type, *transmitters);
  }

  public fun transmit(ocr3_state: &OCR3BaseState, transmitter: address, ocr_plugin_type: u8, report_context: vector<vector<u8>>, report: vector<u8>, signatures: vector<vector<u8>>) {
    let ocr_config = table::borrow(&ocr3_state.ocr3_configs, ocr_plugin_type);
    let config_info = &ocr_config.config_info;

    assert!(vector::length(&report_context) == 2, error::invalid_argument(E_INVALID_REPORT_CONTEXT_LENGTH));

    let config_digest = *vector::borrow(&report_context, 0);
    assert!(vector::length(&config_digest) == 32, error::invalid_argument(E_INVALID_CONFIG_DIGEST_LENGTH));

    let sequence_bytes = *vector::borrow(&report_context, 1);
    assert!(vector::length(&sequence_bytes) == 32, error::invalid_argument(E_INVALID_SEQUENCE_LENGTH));

    // TODO: EVM checks transaction data length here

    assert!(config_digest == config_info.config_digest, error::invalid_argument(E_CONFIG_DIGEST_MISMATCH));

    assert!(chain_id::get() == ocr3_state.chain_id, error::invalid_state(E_FORKED_CHAIN));

    let plugin_transmitters = table::borrow(&ocr3_state.transmitter_oracles, ocr_plugin_type);
    assert!(vector::contains(plugin_transmitters, &transmitter), error::permission_denied(E_UNAUTHORIZED_TRANSMITTER));

    if (config_info.is_signature_verification_enabled) {
      assert!(vector::length(&signatures) == (config_info.big_f as u64) + 1, error::invalid_argument(E_WRONG_NUMBER_OF_SIGNATURES));

      let hashed_report = hash_report(report, config_digest, sequence_bytes);
      let plugin_signers = table::borrow(&ocr3_state.signer_oracles, ocr_plugin_type);
      verify_signature(plugin_signers, hashed_report, signatures);
    };

    let sequence_number: u64 = deserialize_sequence_bytes(sequence_bytes);
    event::emit(Transmitted {
      ocr_plugin_type,
      config_digest,
      sequence_number
    });
  }

  public fun latest_config_details(ocr3_state: &OCR3BaseState, ocr_plugin_type: u8): (vector<u8>, u8, u8, bool, vector<vector<u8>>, vector<address>) {
    let ocr_config = table::borrow(&ocr3_state.ocr3_configs, ocr_plugin_type);
    let config_info = &ocr_config.config_info;
    (config_info.config_digest, config_info.big_f, config_info.n, config_info.is_signature_verification_enabled, ocr_config.signers, ocr_config.transmitters)
  }

  // equivalent of keccak256(abi.encodePacked(keccak256(report), reportContext))
  // TODO: consider switching to blake2b which is less costly
  inline fun hash_report(report: vector<u8>, config_digest: vector<u8>, sequence_bytes: vector<u8>): vector<u8> {
    let bytes = vector[];

    vector::append(&mut bytes, aptos_hash::keccak256(report));
    vector::append(&mut bytes, config_digest);
    vector::append(&mut bytes, sequence_bytes);

    aptos_hash::keccak256(bytes)
  }

  // equivalent of uint64(uint256(reportContext[1]))
  inline fun deserialize_sequence_bytes(sequence_bytes: vector<u8>): u64 {
    let len = vector::length(&sequence_bytes);
    let result: u64 = 0;
    let i = len - 8;
    while (i < len) {
      result = (result << 8) + (*vector::borrow(&sequence_bytes, i) as u64);
      i = i + 1;
    };
    result
  }

  inline fun verify_signature(signers: &vector<ed25519::UnvalidatedPublicKey>, hashed_report: vector<u8>, signatures: vector<vector<u8>>) {
    let seen = bit_vector::new(vector::length(signers));
    vector::for_each_ref(&signatures, |signature_bytes| {
      let public_key =
          ed25519::new_unvalidated_public_key_from_bytes(vector::slice(signature_bytes, 0, 32));
      let (exists, index) = vector::index_of(signers, &public_key);
      assert!(exists, error::invalid_argument(E_UNAUTHORIZED_SIGNER));
      assert!(!bit_vector::is_index_set(&seen, index), error::invalid_argument(E_NON_UNIQUE_SIGNATURES));
      bit_vector::set(&mut seen, index);
      let signature = ed25519::new_signature_from_bytes(vector::slice(signature_bytes, 32, 96));

      let verified = ed25519::signature_verify_strict(&signature, &public_key, hashed_report);
      assert!(verified, error::invalid_argument(E_INVALID_SIGNATURE));
    });
  }

  inline fun has_duplicates<T>(a: &vector<T>): bool {
    let len = vector::length(a);
    let found = false;

    for (i in 0..len) {
        for (j in (i + 1)..len) {
            if (vector::borrow(a, i) == vector::borrow(a, j)) {
              found = true;
            }
        }
    };
    found
  }
}
