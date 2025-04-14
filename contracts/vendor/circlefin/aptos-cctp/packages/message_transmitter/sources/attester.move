/// Copyright (c) 2024, Circle Internet Group, Inc.
/// All rights reserved.
///
/// SPDX-License-Identifier: Apache-2.0
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
/// http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

module message_transmitter::attester {
    // Built-in Modules
    use std::error;
    use std::signer;
    use std::event;
    use std::option;
    use std::vector;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::comparator;
    use aptos_std::from_bcs;
    use aptos_std::secp256k1;

    // Package Modules
    use message_transmitter::state;

    // Friend Modules
    friend message_transmitter::message_transmitter;

    // Constants
    const SIGNATURE_LENGTH: u64 = 65;
    const HALF_CURVE_ORDER: vector<u8> = x"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";

    // Errors
    const ENOT_OWNER: u64 = 1;
    const EATTESTER_ALREADY_ENABLED: u64 = 2;
    const ETOO_FEW_ENABLED_ATTESTERS: u64 = 3;
    const ENUM_ATTESTERS_SHOULD_BE_GREATER_THAN_SIGNATURE_THRESHOLD: u64 = 4;
    const ENOT_ATTESTER_MANAGER: u64 = 5;
    const EINVALID_ATTESTER_MANAGER: u64 = 6;
    const EINVALID_SIGNATURE_THRESHOLD: u64 = 7;
    const ESIGNATURE_THRESHOLD_ALREADY_SET: u64 = 8;
    const ESIGNATURE_THRESHOLD_TOO_HIGH: u64 = 9;
    const EINVALID_ATTESTATION_LENGTH: u64 = 10;
    const EINVALID_SIGNATURE: u64 = 11;
    const ESIGNATURE_IS_NOT_ATTESTER: u64 = 12;
    const EINVALID_MESSAGE_OR_SIGNATURE: u64 = 13;
    const EINVALID_SIGNATURE_CURVE_ORDER: u64 = 14;
    const EINVALID_ATTESTER_ADDRESS: u64 = 15;
    const EATTESTER_NOT_IN_INCREASING_ORDER: u64 = 16;

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct AttesterEnabled has drop, store {
        attester: address
    }

    #[event]
    struct AttesterDisabled has drop, store {
        attester: address
    }

    #[event]
    struct SignatureThresholdUpdated has drop, store {
        old_signature_threshold: u64,
        new_signature_threshold: u64
    }

    #[event]
    struct AttesterManagerUpdated has drop, store {
        previous_attester_manager: address,
        new_attester_manager: address
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    /// Returns true if the passed address is one of the enabled attester.
    public fun is_enabled_attester(attester: address): bool {
        let enabled_attesters = state::get_enabled_attesters();
        vector::contains(&enabled_attesters, &attester)
    }

    #[view]
    /// Returns the attester manager address.
    public fun attester_manager(): address {
        state::get_attester_manager()
    }

    #[view]
    /// Returns attester address at the given index.
    public fun get_enabled_attester(index: u64): address {
        let enabled_attesters = state::get_enabled_attesters();
        *vector::borrow(&enabled_attesters, index)
    }

    #[view]
    /// Returns the number of enabled attesters.
    public fun get_num_enabled_attesters(): u64 {
        state::get_num_enabled_attesters()
    }

    #[view]
    /// Returns signature threshold.
    public fun get_signature_threshold(): u64 {
        state::get_signature_threshold()
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    /// Enables an attester. Emits `AttesterEnabled` event
    /// Aborts if:
    /// - the caller is not the attester manager
    /// - attester is zero address
    /// - the attester is already enabled
    entry fun enable_attester(caller: &signer, new_attester: address) {
        assert_is_attester_manager(caller);
        assert!(new_attester != @0x0, error::invalid_argument(EINVALID_ATTESTER_ADDRESS));
        assert!(!is_enabled_attester(new_attester), error::already_exists(EATTESTER_ALREADY_ENABLED));
        state::add_attester(new_attester);
        event::emit(AttesterEnabled { attester: new_attester });
    }

    /// Disables an attester. Emits `AttesterDisabled` event
    /// Aborts if:
    /// - the caller is not the attester manager
    /// - there is only 1 enabled attester
    /// - the number of remaining enabled attesters will fall below signature threshold
    /// - the attester is not in the list of enabled attesters
    entry fun disable_attester(caller: &signer, attester: address) {
        assert_is_attester_manager(caller);
        let enabled_attesters = state::get_enabled_attesters();
        assert!(vector::length<address>(&enabled_attesters) > 1, error::invalid_state(ETOO_FEW_ENABLED_ATTESTERS));
        assert!(
            vector::length<address>(&enabled_attesters) > state::get_signature_threshold(),
            error::invalid_state(ENUM_ATTESTERS_SHOULD_BE_GREATER_THAN_SIGNATURE_THRESHOLD)
        );
        state::remove_attester(attester);
        event::emit(AttesterDisabled { attester });
    }

    /// Updates attester manager. Emits `AttesterManagerUpdated` event
    /// Aborts if:
    /// - the caller is not the owner
    /// - the new attester manager is the same the old one
    entry fun update_attester_manager(caller: &signer, new_attester_manager: address) {
        assert!(state::get_owner() == signer::address_of(caller), error::permission_denied(ENOT_OWNER));
        let previous_attester_manager = state::get_attester_manager();
        assert!(previous_attester_manager != new_attester_manager, error::already_exists(EINVALID_ATTESTER_MANAGER));
        state::set_attester_manager(new_attester_manager);
        event::emit(AttesterManagerUpdated { previous_attester_manager, new_attester_manager });
    }

    /// Sets the signature threshold. Emits `SignatureThresholdUpdated` event
    /// Aborts if:
    /// - the caller is not the attester manager
    /// - the signature threshold is not valid (e.g 0)
    /// - the signature threshold is the same as the existing one
    /// - the signature threshold exceeds the number of enabled attesters
    entry fun set_signature_threshold(caller: &signer, new_signature_threshold: u64) {
        assert_is_attester_manager(caller);
        assert!(new_signature_threshold != 0, error::invalid_argument(EINVALID_SIGNATURE_THRESHOLD));
        let old_signature_threshold = state::get_signature_threshold();
        assert!(
            new_signature_threshold != old_signature_threshold,
            error::already_exists(ESIGNATURE_THRESHOLD_ALREADY_SET)
        );
        assert!(
            new_signature_threshold <= state::get_num_enabled_attesters(),
            error::invalid_argument(ESIGNATURE_THRESHOLD_TOO_HIGH)
        );
        state::set_signature_threshold(new_signature_threshold);
        event::emit(SignatureThresholdUpdated { old_signature_threshold, new_signature_threshold });
    }

    /// Validates the attestation for the given message
    /// Aborts if:
    /// - length of attestation != ATTESTATION_SIGNATURE_LENGTH * signature_threshold
    /// - there are duplicate signers
    /// - signer is not one of the enabled attesters
    /// - addresses recovered are not in increasing order
    public fun verify_attestation_signature(message: &vector<u8>, attestation: &vector<u8>) {
        // Validate Attestation Size
        let signature_threshold =  state::get_signature_threshold();
        assert!(
            vector::length(attestation) == SIGNATURE_LENGTH * signature_threshold,
            error::invalid_argument(EINVALID_ATTESTATION_LENGTH)
        );

        // Create message hash
        let message_digest = keccak256(*message);
        let current_attester_address = @0x0;
        for (i in 0..signature_threshold) {
            // Get the nth signature
            let signature_with_recovery_id = vector::slice(
                attestation,
                i * SIGNATURE_LENGTH,
                (i + 1) * SIGNATURE_LENGTH
            );

            // Enforce low s value signature check to prevent malleability
            assert!(verify_low_s_value(&signature_with_recovery_id), error::invalid_argument(
                EINVALID_SIGNATURE_CURVE_ORDER
            ));

            // Recover address from signature
            let recovered_attester_address = recover_attester_address(&signature_with_recovery_id, &message_digest);

            // Compare the recovered attester address with existing one to make sure they are in increasing order
            let result = comparator::compare(&recovered_attester_address, &current_attester_address);
            assert!(comparator::is_greater_than(&result), error::invalid_argument(EATTESTER_NOT_IN_INCREASING_ORDER));

            // Validate the recovered attester is one of the enabled attesters
            assert!(
                is_enabled_attester(recovered_attester_address),
                error::invalid_argument(ESIGNATURE_IS_NOT_ATTESTER)
            );
            current_attester_address = recovered_attester_address;
        }
    }

    // -----------------------------
    // ----- Friend Functions ------
    // -----------------------------

    public(friend) fun init_attester(caller: &signer, attester: address) {
        enable_attester(caller, attester);
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    fun assert_is_attester_manager(caller: &signer) {
        let attester_manager = state::get_attester_manager();
        assert!(attester_manager == signer::address_of(caller), error::permission_denied(ENOT_ATTESTER_MANAGER));
    }

    fun recover_attester_address(signature: &vector<u8>, message_digest: &vector<u8>): address {
        // Retrieve and validate signature id
        let recovery_id = *vector::borrow(signature, SIGNATURE_LENGTH - 1) - 27;
        assert!(
            vector::contains(&vector[0, 1], &recovery_id),
            error::invalid_argument(EINVALID_SIGNATURE)
        );

        // Recover public key
        let ecdsa_signature = secp256k1::ecdsa_signature_from_bytes(
            vector::slice(signature, 0, SIGNATURE_LENGTH - 1)
        );
        let recovered_public_key = secp256k1::ecdsa_recover(*message_digest, recovery_id, &ecdsa_signature);
        assert!(option::is_some(&recovered_public_key), error::invalid_argument(EINVALID_MESSAGE_OR_SIGNATURE));

        // Convert public key to address
        let recovered_attester_address = get_address_from_public_key(
            &secp256k1::ecdsa_raw_public_key_to_bytes(option::borrow(&recovered_public_key))
        );
        recovered_attester_address
    }

    /// Returns true if `s` value of signature is in the lower half of curve order
    /// Using Secp256k1Ecdsa Half Curve order from OpenZeppelin ecdsa recover
    /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol#L137
    fun verify_low_s_value(signature: &vector<u8>): bool {
        // Signature is made of r(32 bytes) + s(32 Bytes) + v(1 Byte)
        let signature_s_value = vector::slice(signature, 32, SIGNATURE_LENGTH-1);
        let result = comparator::compare(&signature_s_value, &HALF_CURVE_ORDER);
        comparator::is_smaller_than(&result) || comparator::is_equal(&result)
    }

    fun get_address_from_public_key(public_key: &vector<u8>): address {
        // Hash the public key
        let address_bytes = keccak256(*public_key);

        // EVM address is the made of last 20 bytes of the hash
        let address_without_prefix = vector::slice(
            &address_bytes,
            vector::length(&address_bytes) - 20,
            vector::length(&address_bytes)
        );

        // Add 0x0 prefix to make the address 32 bytes
        let address_with_prefix = x"000000000000000000000000";
        vector::append(&mut address_with_prefix, address_without_prefix);
        from_bcs::to_address(address_with_prefix)
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account::create_signer_for_test;

    #[test_only]
    public fun init_for_test(caller: &signer, attester: address) {
        state::init_test_state(caller);
        init_attester(caller, attester);
    }

    #[test(owner = @message_transmitter)]
    fun test_init_attester(owner: &signer) {
        state::init_test_state(owner);
        let attester = @0xfab;

        init_attester(owner, attester);
        assert!(state::get_num_enabled_attesters() == 1, 0);
        assert!(*vector::borrow(&state::get_enabled_attesters(), 0) == attester, 0);

        let attester_enabled_event = AttesterEnabled { attester };
        assert!(event::was_event_emitted(&attester_enabled_event), 0);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_init_attester_not_attester_manager(owner: &signer) {
        state::init_test_state(owner);
        let not_owner = create_signer_for_test(@0x10);
        init_attester(&not_owner, @0xfab);
    }

    // Admin Tests

    #[test(owner = @message_transmitter)]
    fun test_is_attester_manager_valid(owner: &signer) {
        state::init_test_state(owner);
        assert_is_attester_manager(owner);
    }

    #[test(owner = @message_transmitter, caller = @0xfab)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_is_attester_manager_invalid(owner: &signer, caller: &signer) {
        state::init_test_state(owner);
        assert_is_attester_manager(caller);
    }

    // Enable Attester Tests

    #[test(owner = @message_transmitter)]
    fun test_enable_attester_success(owner: &signer) {
        init_for_test(owner, @0xfac);

        let new_attester = @0xfab;
        enable_attester(owner, new_attester);
        assert!(vector::contains(&state::get_enabled_attesters(), &new_attester), 0);

        let attester_enabled_event = AttesterEnabled { attester: new_attester };
        assert!(event::was_event_emitted(&attester_enabled_event), 0);
    }

    #[test(owner = @message_transmitter, not_attester_manager =  @0x99)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_enable_attester_not_attester_manager(owner: &signer, not_attester_manager: &signer) {
        init_for_test(owner, @0xfac);
        let new_attester = @0xfab;
        enable_attester(not_attester_manager, new_attester);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x80002, location = Self)]
    fun test_enable_attester_not_already_exist(owner: &signer) {
        init_for_test(owner, @0xfac);
        enable_attester(owner, @0xfac);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000f, location = Self)]
    fun test_enable_attester_zero_address(owner: &signer) {
        init_for_test(owner, @0xfac);
        enable_attester(owner, @0x0);
    }

    // Disable Attester Tests

    #[test(owner = @message_transmitter)]
    fun test_disable_attester_success(owner: &signer) {
        init_for_test(owner, @0xfac);

        let new_attester = @0xfab;
        enable_attester(owner, new_attester);
        assert!(vector::contains(&state::get_enabled_attesters(), &new_attester), 0);

        disable_attester(owner, new_attester);
        assert!(!vector::contains(&state::get_enabled_attesters(), &new_attester), 0);

        let attester_enabled_event = AttesterDisabled { attester: new_attester };
        assert!(event::was_event_emitted(&attester_enabled_event), 0);
    }

    #[test(owner = @message_transmitter, not_attester_manager =  @0x99)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_disable_attester_not_attester_manager(owner: &signer, not_attester_manager: &signer) {
        init_for_test(owner, @0xfac);
        let new_attester = @0xfab;
        disable_attester(not_attester_manager, new_attester);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x30003, location = Self)]
    fun test_disable_attester_too_few_attesters(owner: &signer) {
        init_for_test(owner, @0xfac);
        disable_attester(owner, @0xfac);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x30004, location = Self)]
    fun test_disable_attester_low_signature_threshold(owner: &signer) {
        init_for_test(owner, @0xfac);
        state::add_attester(@0xfab);
        state::set_signature_threshold(2);
        disable_attester(owner, @0xfab);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x60001, location = state)]
    fun test_disable_attester_attester_not_found(owner: &signer) {
        init_for_test(owner, @0xfac);
        state::add_attester(@0xfab);
        disable_attester(owner, @0xfaa);
    }

    // Update Attester Manager Tests

    #[test(owner = @message_transmitter)]
    fun test_update_attester_manager_success(owner: &signer) {
        init_for_test(owner, @0xfac);

        let new_attester_manager = @0xfab;
        update_attester_manager(owner, new_attester_manager);

        let attester_manager_updated_event = AttesterManagerUpdated {
            previous_attester_manager: signer::address_of(owner),
            new_attester_manager
        };
        assert!(event::was_event_emitted(&attester_manager_updated_event), 0);
    }

    #[test(owner = @message_transmitter, not_owner = @0x99)]
    #[expected_failure(abort_code = 0x50001, location = Self)]
    fun test_update_attester_manager_not_owner(owner: &signer, not_owner: &signer) {
        init_for_test(owner, @0xfac);
        let new_attester_manager = @0xfab;
        update_attester_manager(not_owner, new_attester_manager);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x80006, location = Self)]
    fun test_update_attester_manager_already_exists(owner: &signer) {
        init_for_test(owner, @0xfac);
        update_attester_manager(owner, @message_transmitter);
    }

    // Set Signature Threshold Tests

    #[test(owner = @message_transmitter)]
    fun test_set_signature_threshold(owner: &signer) {
        init_for_test(owner, @0xfac);
        state::add_attester(@0xfab);

        let old_signature_threshold = state::get_signature_threshold();
        let new_signature_threshold = 2;
        set_signature_threshold(owner, new_signature_threshold);

        let attester_enabled_event = SignatureThresholdUpdated { old_signature_threshold, new_signature_threshold };
        assert!(event::was_event_emitted(&attester_enabled_event), 0);
    }

    #[test(owner = @message_transmitter, not_attester_manager =  @0x99)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_set_signature_threshold_not_attester_manager(owner: &signer, not_attester_manager: &signer) {
        init_for_test(owner, @0xfac);
        set_signature_threshold(not_attester_manager, 2);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    fun test_set_signature_threshold_too_high(owner: &signer) {
        init_for_test(owner, @0xfac);
        set_signature_threshold(owner, 2);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    fun test_set_signature_threshold_zero_threshold(owner: &signer) {
        init_for_test(owner, @0xfac);
        set_signature_threshold(owner, 0);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x80008, location = Self)]
    fun test_set_signature_threshold_already_exists(owner: &signer) {
        init_for_test(owner, @0xfac);
        set_signature_threshold(owner, state::get_signature_threshold());
    }

    // Verify Attestation Signature Tests
    // Based on valid Message and Attestation From DepositForBurn Tx
    // https://subnets.avax.network/c-chain/tx/0x1f0eb507b4650881092fbb238065d10ddedaac3bfe7fa456957176aa80e2e15f

    #[test(owner = @message_transmitter)]
    fun test_verify_attestation_signature_single_signature(owner: &signer) {
        let attester = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        init_for_test(owner, attester);
        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    fun test_verify_attestation_signature_multiple_signatures(owner: &signer) {
        let attester_one = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        let attester_two = @0xE2fEfe09E74b921CbbFF229E7cD40009231501CA;

        init_for_test(owner, attester_one);
        enable_attester(owner, attester_two);
        set_signature_threshold(owner, 2);

        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c742186b73f110593d67ffd1272979dfbccf467d005701392bc41714045f17ecc0c88242eba6a2c230202ebd0c2bb7c1a11358375bc6a035ba377a0cfe1b5a4e21c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000e, location = Self)]
    fun test_verify_attestation_signature_malleable_signature(owner: &signer) {
        let attester = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        init_for_test(owner, attester);
        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d0e1c96827a37f5fb3a3ad66007be63da952275524f868ab2f62e1fc70850c41821b";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_verify_attestation_signature_invalid_attestation_length(owner: &signer) {
        let attester = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        init_for_test(owner, attester);

        let message = b"message";
        let attestation = x"9ca6e57c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    fun test_verify_attestation_signature_failed_recovery(owner: &signer) {
        let attester = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        init_for_test(owner, attester);
        let message = b"hello";
        let attestation = x"67315456c4b8e5b453174517326d8e1eefbb2d461d343e303dd25106afadfe35586c7375afd81251b0e72c0de112d2b9d9bdb136744c26d0d96d7bd2f84284021c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    fun test_verify_attestation_signature_invalid_signature_recovery_id(owner: &signer) {
        let attester = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        init_for_test(owner, attester);

        let message = b"message";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbfcc";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x10010, location = Self)]
    fun test_verify_attestation_signature_duplicate_attester(owner: &signer) {
        let attester_one = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        let attester_two = @0xE2fEfe09E74b921CbbFF229E7cD40009231501CA;

        init_for_test(owner, attester_one);
        enable_attester(owner, attester_two);
        set_signature_threshold(owner, 2);

        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x10010, location = Self)]
    fun test_verify_attestation_signature_wrong_signature_order(owner: &signer) {
        let attester_one = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        let attester_two = @0xE2fEfe09E74b921CbbFF229E7cD40009231501CA;

        init_for_test(owner, attester_one);
        enable_attester(owner, attester_two);
        set_signature_threshold(owner, 2);

        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"742186b73f110593d67ffd1272979dfbccf467d005701392bc41714045f17ecc0c88242eba6a2c230202ebd0c2bb7c1a11358375bc6a035ba377a0cfe1b5a4e21c9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c";
        verify_attestation_signature(&message, &attestation);
    }

    #[test(owner = @message_transmitter)]
    #[expected_failure(abort_code = 0x1000c, location = Self)]
    fun test_verify_attestation_signature_incorrect_attester(owner: &signer) {
        let attester_one = @0xb0Ea8E1bE37F346C7EA7ec708834D0db18A17361;
        let attester_two = @0x0a992d191DEeC32aFe36203Ad87D7d289a738F81;

        init_for_test(owner, attester_one);
        enable_attester(owner, attester_two);
        set_signature_threshold(owner, 2);

        let message = x"000000000000000100000005000000000001c50c0000000000000000000000006b25532e1060ce10cc3b0a99e5683b91bfde6982a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e2b35a76035073ce97cd401aa4781fe579433c2fed59e7bdcc458748a7632277900000000000000000000000000000000000000000000000000000000483b92f90000000000000000000000001cd223dbc9ff35ff6b29dab2339acc842bf58ccb";
        let attestation = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf1c742186b73f110593d67ffd1272979dfbccf467d005701392bc41714045f17ecc0c88242eba6a2c230202ebd0c2bb7c1a11358375bc6a035ba377a0cfe1b5a4e21c";
        verify_attestation_signature(&message, &attestation);
    }

    // Test Malleability

    #[test]
    fun test_verify_low_s_value_normal_signature() {
        let signature_less_than_half = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d01e3697d85c80a04c5c5299ff8419c255688787c1b6dff50c5cf0621c4b29ffbf";
        assert!(verify_low_s_value(&signature_less_than_half), 0);
    }

    #[test]
    fun test_verify_low_s_value_malleable_greater_signature() {
        let signature_greater_than_half = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d0e1c96827a37f5fb3a3ad66007be63da952275524f868ab2f62e1fc70850c4182";
        assert!(!verify_low_s_value(&signature_greater_than_half), 0);
    }

    #[test]
    fun test_verify_low_s_value_malleable_equal_signature() {
        let signature_equals_half = x"9ca6e57cdbaff834d0faaffa5315a2da29d751ad26616a8a394e4b365f09f2d07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";
        assert!(verify_low_s_value(&signature_equals_half), 0);
    }

    // View Function Tests

    #[test(owner = @message_transmitter)]
    fun test_is_enabled_attester(owner: &signer) {
        init_for_test(owner, @0xfac);
        assert!(is_enabled_attester(@0xfac) == true, 0);
        assert!(is_enabled_attester(@0xfab) == false, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_num_enabled_attester(owner: &signer) {
        init_for_test(owner, @0xfac);
        assert!(get_num_enabled_attesters() == 1, 0);
        enable_attester(owner, @0xfab);
        assert!(get_num_enabled_attesters() == 2, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_view_attester_manager(owner: &signer) {
        init_for_test(owner, @0xfac);
        assert!(attester_manager() == state::get_attester_manager(), 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_signature_threshold(owner: &signer) {
        init_for_test(owner, @0xfac);
        assert!(get_signature_threshold() == 1, 0);
    }
}
