module ccip::rmn_remote {
    use std::account;
    use std::aptos_hash;
    use std::bcs;
    use std::chain_id;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::object;
    use std::option;
    use std::secp256k1;
    use std::signer;
    use std::string::{Self, String};
    use std::smart_table::{Self, SmartTable};
    use std::ordered_map::{Self, OrderedMap};

    use ccip::auth;
    use ccip::eth_abi;
    use ccip::merkle_proof;
    use ccip::state_object;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const GLOBAL_CURSE_SUBJECT: vector<u8> = x"01000000000000000000000000000001";

    struct RMNRemoteState has key {
        local_chain_selector: u64,
        config: Config,
        config_count: u32,
        signers: SmartTable<vector<u8>, bool>,
        cursed_subjects: SmartTable<vector<u8>, bool>,
        config_set_events: EventHandle<ConfigSet>,
        cursed_events: EventHandle<Cursed>,
        uncursed_events: EventHandle<Uncursed>
    }

    struct Config has copy, drop, store {
        rmn_home_contract_config_digest: vector<u8>,
        signers: vector<Signer>,
        f_sign: u64
    }

    struct Signer has copy, drop, store {
        onchain_public_key: vector<u8>,
        node_index: u64
    }

    struct Report has drop {
        dest_chain_id: u64,
        dest_chain_selector: u64,
        rmn_remote_contract_address: address,
        off_ramp_address: address,
        rmn_home_contract_config_digest: vector<u8>,
        merkle_roots: vector<MerkleRoot>
    }

    struct MerkleRoot has drop {
        source_chain_selector: u64,
        on_ramp_address: vector<u8>,
        min_seq_nr: u64,
        max_seq_nr: u64,
        merkle_root: vector<u8>
    }

    #[event]
    struct ConfigSet has store, drop {
        version: u32,
        config: Config
    }

    #[event]
    struct Cursed has store, drop {
        subjects: vector<vector<u8>>
    }

    #[event]
    struct Uncursed has store, drop {
        subjects: vector<vector<u8>>
    }

    // ================================================================
    // |                  AllowedCursersV2 (Fast Cursing)              |
    // ================================================================
    struct AllowedCursersV2 has key {
        allowed_cursers: OrderedMap<address, bool>,
        allowed_cursers_added_events: EventHandle<AllowedCursersAdded>,
        allowed_cursers_removed_events: EventHandle<AllowedCursersRemoved>
    }

    #[event]
    struct AllowedCursersAdded has store, drop {
        cursers: vector<address>
    }

    #[event]
    struct AllowedCursersRemoved has store, drop {
        cursers: vector<address>
    }

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
    const E_UNKNOWN_FUNCTION: u64 = 18;
    const E_NOT_OWNER_OR_ALLOWED_CURSER: u64 = 19;
    const E_ALLOWED_CURSERS_V2_ALREADY_INITIALIZED: u64 = 20;
    const E_ALLOWED_CURSERS_V2_NOT_INITIALIZED: u64 = 21;
    const E_CURSER_ALREADY_ALLOWED: u64 = 22;
    const E_CURSER_NOT_ALLOWED: u64 = 23;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"RMNRemote 1.6.0")
    }

    fun init_module(publisher: &signer) {
        // Register the entrypoint with mcms
        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };
    }

    public entry fun initialize(caller: &signer, local_chain_selector: u64) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            local_chain_selector != 0,
            error::invalid_argument(E_ZERO_VALUE_NOT_ALLOWED)
        );
        assert!(
            !exists<RMNRemoteState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let state_object_signer = state_object::object_signer();

        // Create V1 state (RMNRemoteState)
        let state = RMNRemoteState {
            local_chain_selector,
            config: Config {
                rmn_home_contract_config_digest: vector[],
                signers: vector[],
                f_sign: 0
            },
            config_count: 0,
            signers: smart_table::new(),
            cursed_subjects: smart_table::new(),
            config_set_events: account::new_event_handle(&state_object_signer),
            cursed_events: account::new_event_handle(&state_object_signer),
            uncursed_events: account::new_event_handle(&state_object_signer)
        };
        move_to(&state_object_signer, state);

        // Create V2 state (AllowedCursersV2) - new deployments get both
        move_to(
            &state_object_signer,
            AllowedCursersV2 {
                allowed_cursers: ordered_map::new(),
                allowed_cursers_added_events: account::new_event_handle(
                    &state_object_signer
                ),
                allowed_cursers_removed_events: account::new_event_handle(
                    &state_object_signer
                )
            }
        );
    }

    #[test_only]
    /// Legacy initialization that only creates RMNRemoteState (V1).
    /// Used for testing migration scenarios from V1 to V2.
    public entry fun initialize_v1(
        caller: &signer, local_chain_selector: u64
    ) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            local_chain_selector != 0,
            error::invalid_argument(E_ZERO_VALUE_NOT_ALLOWED)
        );
        assert!(
            !exists<RMNRemoteState>(state_object::object_address()),
            error::invalid_argument(E_ALREADY_INITIALIZED)
        );

        let state_object_signer = state_object::object_signer();
        let state = RMNRemoteState {
            local_chain_selector,
            config: Config {
                rmn_home_contract_config_digest: vector[],
                signers: vector[],
                f_sign: 0
            },
            config_count: 0,
            signers: smart_table::new(),
            cursed_subjects: smart_table::new(),
            config_set_events: account::new_event_handle(&state_object_signer),
            cursed_events: account::new_event_handle(&state_object_signer),
            uncursed_events: account::new_event_handle(&state_object_signer)
        };

        move_to(&state_object_signer, state);
    }

    inline fun calculate_digest(report: &Report): vector<u8> {
        let digest = vector[];
        eth_abi::encode_right_padded_bytes32(&mut digest, get_report_digest_header());
        eth_abi::encode_u64(&mut digest, report.dest_chain_id);
        eth_abi::encode_u64(&mut digest, report.dest_chain_selector);
        eth_abi::encode_address(&mut digest, report.rmn_remote_contract_address);
        eth_abi::encode_address(&mut digest, report.off_ramp_address);
        eth_abi::encode_right_padded_bytes32(
            &mut digest, report.rmn_home_contract_config_digest
        );
        report.merkle_roots.for_each_ref(
            |merkle_root| {
                let merkle_root: &MerkleRoot = merkle_root;
                eth_abi::encode_u64(&mut digest, merkle_root.source_chain_selector);
                eth_abi::encode_bytes(&mut digest, merkle_root.on_ramp_address);
                eth_abi::encode_u64(&mut digest, merkle_root.min_seq_nr);
                eth_abi::encode_u64(&mut digest, merkle_root.max_seq_nr);
                eth_abi::encode_right_padded_bytes32(
                    &mut digest, merkle_root.merkle_root
                );
            }
        );
        aptos_hash::keccak256(digest)
    }

    #[view]
    public fun verify(
        off_ramp_address: address,
        merkle_root_source_chain_selectors: vector<u64>,
        merkle_root_on_ramp_addresses: vector<vector<u8>>,
        merkle_root_min_seq_nrs: vector<u64>,
        merkle_root_max_seq_nrs: vector<u64>,
        merkle_root_values: vector<vector<u8>>,
        signatures: vector<vector<u8>>
    ): bool acquires RMNRemoteState {
        let state = borrow_state();

        assert!(state.config_count > 0, error::invalid_argument(E_CONFIG_NOT_SET));

        let signatures_len = signatures.length();
        assert!(
            signatures_len >= (state.config.f_sign + 1),
            error::invalid_argument(E_THRESHOLD_NOT_MET)
        );

        let merkle_root_len = merkle_root_source_chain_selectors.length();
        assert!(
            merkle_root_len == merkle_root_on_ramp_addresses.length(),
            error::invalid_argument(E_MERKLE_ROOT_LENGTH_MISMATCH)
        );
        assert!(
            merkle_root_len == merkle_root_min_seq_nrs.length(),
            error::invalid_argument(E_MERKLE_ROOT_LENGTH_MISMATCH)
        );
        assert!(
            merkle_root_len == merkle_root_max_seq_nrs.length(),
            error::invalid_argument(E_MERKLE_ROOT_LENGTH_MISMATCH)
        );
        assert!(
            merkle_root_len == merkle_root_values.length(),
            error::invalid_argument(E_MERKLE_ROOT_LENGTH_MISMATCH)
        );

        // Since we cannot pass structs, we need to reconstruct it from the individual components.
        let merkle_roots = vector[];
        for (i in 0..merkle_root_len) {
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
        };

        let report = Report {
            dest_chain_id: (chain_id::get() as u64),
            dest_chain_selector: state.local_chain_selector,
            rmn_remote_contract_address: @ccip,
            off_ramp_address,
            rmn_home_contract_config_digest: state.config.rmn_home_contract_config_digest,
            merkle_roots
        };

        let digest = calculate_digest(&report);

        let previous_eth_address = vector[];
        for (i in 0..signatures_len) {
            let signature_bytes = signatures[i];
            let signature = secp256k1::ecdsa_signature_from_bytes(signature_bytes);

            // rmn only generates signatures with v = 27, subtract the ethereum recover id offset of 27 to get zero.
            let v = 0;
            let maybe_public_key = secp256k1::ecdsa_recover(digest, v, &signature);
            assert!(
                maybe_public_key.is_some(),
                error::invalid_argument(E_INVALID_SIGNATURE)
            );

            let public_key_bytes =
                secp256k1::ecdsa_raw_public_key_to_bytes(&maybe_public_key.extract());
            // trim the first 12 bytes of the hash to recover the ethereum address.
            let eth_address = aptos_hash::keccak256(public_key_bytes).trim(12);

            assert!(
                state.signers.contains(eth_address),
                error::invalid_argument(E_UNEXPECTED_SIGNER)
            );
            if (i > 0) {
                assert!(
                    merkle_proof::vector_u8_gt(&eth_address, &previous_eth_address),
                    error::invalid_argument(E_OUT_OF_ORDER_SIGNATURES)
                );
            };
            previous_eth_address = eth_address;
        };

        true
    }

    #[view]
    public fun get_arm(): address {
        @ccip
    }

    public entry fun set_config(
        caller: &signer,
        rmn_home_contract_config_digest: vector<u8>,
        signer_onchain_public_keys: vector<vector<u8>>,
        node_indexes: vector<u64>,
        f_sign: u64
    ) acquires RMNRemoteState {
        auth::assert_only_owner(signer::address_of(caller));

        let state = borrow_state_mut();

        assert!(
            rmn_home_contract_config_digest.length() == 32,
            error::invalid_argument(E_INVALID_DIGEST_LENGTH)
        );

        assert!(
            eth_abi::decode_u256_value(rmn_home_contract_config_digest) != 0,
            error::invalid_argument(E_ZERO_VALUE_NOT_ALLOWED)
        );

        let signers_len = signer_onchain_public_keys.length();
        assert!(
            signers_len == node_indexes.length(),
            error::invalid_argument(E_SIGNERS_MISMATCH)
        );

        for (i in 1..signers_len) {
            let previous_node_index = node_indexes[i - 1];
            let current_node_index = node_indexes[i];
            assert!(
                previous_node_index < current_node_index,
                error::invalid_argument(E_INVALID_SIGNER_ORDER)
            );
        };

        assert!(
            signers_len >= (2 * f_sign + 1),
            error::invalid_argument(E_NOT_ENOUGH_SIGNERS)
        );

        state.signers.clear();

        let signers =
            signer_onchain_public_keys.zip_map_ref(
                &node_indexes,
                |signer_public_key_bytes, node_indexes| {
                    let signer_public_key_bytes: vector<u8> = *signer_public_key_bytes;
                    let node_index: u64 = *node_indexes;
                    // expect an ethereum address of 20 bytes.
                    assert!(
                        signer_public_key_bytes.length() == 20,
                        error::invalid_argument(E_INVALID_PUBLIC_KEY_LENGTH)
                    );
                    assert!(
                        !state.signers.contains(signer_public_key_bytes),
                        error::invalid_argument(E_DUPLICATE_SIGNER)
                    );
                    state.signers.add(signer_public_key_bytes, true);
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

        event::emit_event(
            &mut state.config_set_events,
            ConfigSet { version: new_config_count, config: new_config }
        );
    }

    #[view]
    public fun get_versioned_config(): (u32, Config) acquires RMNRemoteState {
        let state = borrow_state();
        (state.config_count, state.config)
    }

    #[view]
    public fun get_local_chain_selector(): u64 acquires RMNRemoteState {
        borrow_state().local_chain_selector
    }

    #[view]
    public fun get_report_digest_header(): vector<u8> {
        aptos_hash::keccak256(b"RMN_V1_6_ANY2APTOS_REPORT")
    }

    public entry fun curse(
        caller: &signer, subject: vector<u8>
    ) acquires RMNRemoteState, AllowedCursersV2 {
        curse_multiple(caller, vector[subject]);
    }

    public entry fun curse_multiple(
        caller: &signer, subjects: vector<vector<u8>>
    ) acquires RMNRemoteState, AllowedCursersV2 {
        assert_owner_or_allowed_curser(signer::address_of(caller));

        let state = borrow_state_mut();

        subjects.for_each_ref(
            |subject| {
                let subject: vector<u8> = *subject;
                assert!(
                    subject.length() == 16,
                    error::invalid_argument(E_INVALID_SUBJECT_LENGTH)
                );
                assert!(
                    !state.cursed_subjects.contains(subject),
                    error::invalid_argument(E_ALREADY_CURSED)
                );
                state.cursed_subjects.add(subject, true);
            }
        );
        event::emit_event(&mut state.cursed_events, Cursed { subjects });
    }

    public entry fun uncurse(
        caller: &signer, subject: vector<u8>
    ) acquires RMNRemoteState, AllowedCursersV2 {
        uncurse_multiple(caller, vector[subject]);
    }

    public entry fun uncurse_multiple(
        caller: &signer, subjects: vector<vector<u8>>
    ) acquires RMNRemoteState, AllowedCursersV2 {
        assert_owner_or_allowed_curser(signer::address_of(caller));

        let state = borrow_state_mut();

        subjects.for_each_ref(
            |subject| {
                let subject: vector<u8> = *subject;
                assert!(
                    state.cursed_subjects.contains(subject),
                    error::invalid_argument(E_NOT_CURSED)
                );
                state.cursed_subjects.remove(subject);
            }
        );
        event::emit_event(&mut state.uncursed_events, Uncursed { subjects });
    }

    #[view]
    public fun get_cursed_subjects(): vector<vector<u8>> acquires RMNRemoteState {
        borrow_state().cursed_subjects.keys()
    }

    #[view]
    public fun is_cursed_global(): bool acquires RMNRemoteState {
        borrow_state().cursed_subjects.contains(GLOBAL_CURSE_SUBJECT)
    }

    #[view]
    public fun is_cursed(subject: vector<u8>): bool acquires RMNRemoteState {
        borrow_state().cursed_subjects.contains(subject) || is_cursed_global()
    }

    #[view]
    public fun is_cursed_u128(subject_value: u128): bool acquires RMNRemoteState {
        let subject = bcs::to_bytes(&subject_value);
        subject.reverse();
        is_cursed(subject)
    }

    inline fun borrow_state(): &RMNRemoteState {
        borrow_global<RMNRemoteState>(state_object::object_address())
    }

    inline fun borrow_state_mut(): &mut RMNRemoteState {
        borrow_global_mut<RMNRemoteState>(state_object::object_address())
    }

    // ================================================================
    // |              AllowedCursersV2 Helper Functions                |
    // ================================================================
    inline fun borrow_allowed_cursers_v2(): &AllowedCursersV2 {
        borrow_global<AllowedCursersV2>(state_object::object_address())
    }

    inline fun borrow_allowed_cursers_v2_mut(): &mut AllowedCursersV2 {
        borrow_global_mut<AllowedCursersV2>(state_object::object_address())
    }

    #[view]
    /// Check if an address is an allowed curser.
    /// Returns false if AllowedCursersV2 is not initialized (V1 behavior: only owner can curse).
    public fun is_allowed_curser(curser: address): bool acquires AllowedCursersV2 {
        if (!exists<AllowedCursersV2>(state_object::object_address())) { false }
        else {
            borrow_allowed_cursers_v2().allowed_cursers.contains(&curser)
        }
    }

    #[view]
    /// Get the list of allowed cursers.
    /// Returns empty vector if AllowedCursersV2 is not initialized.
    public fun get_allowed_cursers(): vector<address> acquires AllowedCursersV2 {
        if (!exists<AllowedCursersV2>(state_object::object_address())) {
            vector[]
        } else {
            borrow_allowed_cursers_v2().allowed_cursers.keys()
        }
    }

    inline fun assert_owner_or_allowed_curser(caller: address) {
        assert!(
            caller == auth::owner() || is_allowed_curser(caller),
            error::permission_denied(E_NOT_OWNER_OR_ALLOWED_CURSER)
        );
    }

    // ================================================================
    // |           AllowedCursersV2 Admin Functions (Owner Only)       |
    // ================================================================

    /// Initialize the AllowedCursersV2 resource. Owner only.
    /// This must be called before adding allowed cursers.
    public entry fun initialize_allowed_cursers_v2(
        caller: &signer, initial_cursers: vector<address>
    ) {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            !exists<AllowedCursersV2>(state_object::object_address()),
            error::already_exists(E_ALLOWED_CURSERS_V2_ALREADY_INITIALIZED)
        );

        let state_object_signer = state_object::object_signer();
        let allowed_cursers = ordered_map::new();

        initial_cursers.for_each_ref(
            |curser| {
                allowed_cursers.add(*curser, true);
            }
        );

        move_to(
            &state_object_signer,
            AllowedCursersV2 {
                allowed_cursers,
                allowed_cursers_added_events: account::new_event_handle(
                    &state_object_signer
                ),
                allowed_cursers_removed_events: account::new_event_handle(
                    &state_object_signer
                )
            }
        );

        if (!initial_cursers.is_empty()) {
            event::emit(AllowedCursersAdded { cursers: initial_cursers });
        };
    }

    /// Add allowed cursers. Owner only.
    /// AllowedCursersV2 must be initialized first.
    public entry fun add_allowed_cursers(
        caller: &signer, cursers_to_add: vector<address>
    ) acquires AllowedCursersV2 {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            exists<AllowedCursersV2>(state_object::object_address()),
            error::invalid_state(E_ALLOWED_CURSERS_V2_NOT_INITIALIZED)
        );

        let state = borrow_allowed_cursers_v2_mut();

        cursers_to_add.for_each_ref(
            |curser| {
                assert!(
                    !state.allowed_cursers.contains(curser),
                    error::already_exists(E_CURSER_ALREADY_ALLOWED)
                );
                state.allowed_cursers.add(*curser, true);
            }
        );

        event::emit_event(
            &mut state.allowed_cursers_added_events,
            AllowedCursersAdded { cursers: cursers_to_add }
        );
    }

    /// Remove allowed cursers. Owner only.
    /// AllowedCursersV2 must be initialized first.
    public entry fun remove_allowed_cursers(
        caller: &signer, cursers_to_remove: vector<address>
    ) acquires AllowedCursersV2 {
        auth::assert_only_owner(signer::address_of(caller));

        assert!(
            exists<AllowedCursersV2>(state_object::object_address()),
            error::invalid_state(E_ALLOWED_CURSERS_V2_NOT_INITIALIZED)
        );

        let state = borrow_allowed_cursers_v2_mut();

        cursers_to_remove.for_each_ref(
            |curser| {
                assert!(
                    state.allowed_cursers.contains(curser),
                    error::not_found(E_CURSER_NOT_ALLOWED)
                );
                state.allowed_cursers.remove(curser);
            }
        );

        event::emit_event(
            &mut state.allowed_cursers_removed_events,
            AllowedCursersRemoved { cursers: cursers_to_remove }
        );
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): option::Option<u128> acquires RMNRemoteState, AllowedCursersV2 {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@ccip, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let local_chain_selector = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            initialize(&caller, local_chain_selector);
        } else if (function_bytes == b"set_config") {
            let rmn_home_contract_config_digest =
                bcs_stream::deserialize_vector_u8(&mut stream);
            let signer_onchain_public_keys =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            let node_indexes =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_u64(stream)
                );
            let f_sign = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_config(
                &caller,
                rmn_home_contract_config_digest,
                signer_onchain_public_keys,
                node_indexes,
                f_sign
            )
        } else if (function_bytes == b"curse") {
            let subject = bcs_stream::deserialize_vector_u8(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            curse(&caller, subject)
        } else if (function_bytes == b"curse_multiple") {
            let subjects =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            curse_multiple(&caller, subjects)
        } else if (function_bytes == b"uncurse") {
            let subject = bcs_stream::deserialize_vector_u8(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            uncurse(&caller, subject)
        } else if (function_bytes == b"uncurse_multiple") {
            let subjects =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            uncurse_multiple(&caller, subjects)
        } else if (function_bytes == b"initialize_allowed_cursers_v2") {
            let initial_cursers =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            initialize_allowed_cursers_v2(&caller, initial_cursers)
        } else if (function_bytes == b"add_allowed_cursers") {
            let cursers_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            add_allowed_cursers(&caller, cursers_to_add)
        } else if (function_bytes == b"remove_allowed_cursers") {
            let cursers_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            remove_allowed_cursers(&caller, cursers_to_remove)
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"rmn_remote"), McmsCallback {}
        );
    }
}
