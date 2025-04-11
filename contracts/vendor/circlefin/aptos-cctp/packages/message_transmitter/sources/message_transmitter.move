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

module message_transmitter::message_transmitter {
    // Built-in Modules
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer;
    use std::vector;
    use aptos_std::aptos_hash;
    use aptos_std::from_bcs;
    use aptos_framework::event;
    use aptos_framework::object;
    use aptos_framework::resource_account;
    use aptos_extensions::upgradable;
    use aptos_extensions::manageable;
    use aptos_extensions::pausable;
    use aptos_extensions::ownable;

    // Package Modules
    use message_transmitter::state;
    use message_transmitter::attester;
    use message_transmitter::message;

    // Constants
    const SEED_NAME: vector<u8> = b"MessageTransmitter";

    // Errors
    const EMESSAGE_BODY_EXCEEDS_MAX_SIZE: u64 = 1;
    const EINVALID_RECIPIENT_ADDRESS: u64 = 2;
    const EINVALID_DESTINATION_CALLER_ADDRESS: u64 = 3;
    const ENOT_ORIGINAL_SENDER: u64 = 4;
    const EINCORRECT_SOURCE_DOMAIN: u64 = 5;
    const EALREADY_INITIALIZED: u64 = 6;
    const EINCORRECT_DESTINATION_DOMAIN: u64 = 7;
    const EINCORRECT_CALLER_FOR_THE_MESSAGE: u64 = 8;
    const EINVALID_MESSAGE_VERSION: u64 = 9;
    const ENONCE_ALREADY_USED: u64 = 10;
    const EUNAUTHORIZED_RECEIVING_ADDRESS: u64 = 11;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// Store the extend ref to generate signer
    struct ObjectController has key {
        extend_ref: object::ExtendRef,
    }

    struct Receipt {
        caller: address,
        recipient: address,
        source_domain: u32,
        sender: address,
        nonce: u64,
        message_body: vector<u8>
    }

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct MessageSent has drop, store {
        message: vector<u8>
    }

    #[event]
    struct MessageReceived has drop, store {
        caller: address,
        source_domain: u32,
        nonce: u64,
        sender: address,
        message_body: vector<u8>
    }

    #[event]
    struct MaxMessageBodySizeUpdated has drop, store {
        max_message_body_size: u64,
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    public fun local_domain(): u32 {
        state::get_local_domain()
    }

    #[view]
    public fun version(): u32 {
        state::get_version()
    }

    #[view]
    public fun is_nonce_used(hash: address): bool {
        state::is_nonce_used(hash)
    }

    #[view]
    public fun next_available_nonce(): u64 {
        state::get_next_available_nonce()
    }

    #[view]
    public fun max_message_body_size(): u64 {
        state::get_max_message_body_size()
    }

    #[view]
    public fun object_address(): address {
        state::get_object_address()
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    fun init_module(resource_acct_signer: &signer) {
        let constructor_ref = object::create_named_object(resource_acct_signer, SEED_NAME);
        let message_transmitter_signer = &object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        move_to(message_transmitter_signer, ObjectController { extend_ref });

        ownable::new(message_transmitter_signer, @deployer);
        pausable::new(message_transmitter_signer, @deployer);

        let signer_cap = resource_account::retrieve_resource_account_cap(resource_acct_signer, @deployer);
        manageable::new(resource_acct_signer, @deployer);
        upgradable::new(resource_acct_signer, signer_cap);

    }
    /// Create and initialize Message Transmitter object
    /// Aborts if:
    /// - caller is not the deployer
    /// - it has already been initialized
    entry fun initialize_message_transmitter(
        caller: &signer,
        local_domain: u32,
        attester: address,
        max_message_body_size: u64,
        version: u32
    ) acquires ObjectController {
        manageable::assert_is_admin(caller, @message_transmitter);
        assert!(!state::is_initialized(), error::already_exists(EALREADY_INITIALIZED));
        state::init_state(caller, &get_signer(), local_domain, version, max_message_body_size);
        attester::init_attester(caller, attester);
    }

    /// Send the message to the destination domain and recipient. Increments the nonce, serializes the message and
    /// emits `MessageSent` event.
    /// Aborts if:
    /// - the contract is paused
    /// - message body size exceeds the max size allowed
    /// - recipient is zero address
    public fun send_message(
        caller: &signer,
        destination_domain: u32,
        recipient: address,
        message_body: &vector<u8>
    ): u64 {
        pausable::assert_not_paused(state::get_object_address());
        let empty_destination_caller = @0x0;
        let nonce = reserve_and_increment_nonce();
        let sender_address = signer::address_of(caller);
        serialize_message_and_emit_event(
            destination_domain,
            recipient,
            sender_address,
            empty_destination_caller,
            nonce,
            message_body
        );
        nonce
    }

    /// Send the message to the destination domain and recipient for a specified `destinationCaller`.
    /// Only the `destinationCaller` can receive this message. Increments the nonce, serializes the message and
    /// emits `MessageSent` event.
    /// Aborts if:
    /// - the contract is paused
    /// - message body size exceeds than the max size allowed
    /// - recipient is zero address
    /// - destination caller is zero address
    public fun send_message_with_caller(
        caller: &signer,
        destination_domain: u32,
        recipient: address,
        destination_caller: address,
        message_body: &vector<u8>
    ): u64 {
        pausable::assert_not_paused(state::get_object_address());
        assert!(destination_caller != @0x0, error::invalid_argument(EINVALID_DESTINATION_CALLER_ADDRESS));
        let nonce = reserve_and_increment_nonce();
        let sender_address = signer::address_of(caller);
        serialize_message_and_emit_event(
            destination_domain,
            recipient,
            sender_address,
            destination_caller,
            nonce,
            message_body
        );
        nonce
    }

    /// Replaces the given message with new message body and/or destination caller. The replaced message reuses the same
    /// nonce making both the existing and new messages valid. Serializes the message and emits `MessageSent` event.
    /// Aborts if:
    /// - the contract is paused
    /// - message is invalid
    /// - attestation is invalid
    /// - message body size exceeds than the max size allowed
    /// - caller is not the original sender
    /// - domain id from the message doesn't matches the local domain id
    public fun replace_message(
        caller: &signer,
        original_message: &vector<u8>,
        original_attestation: &vector<u8>,
        new_message_body: &option::Option<vector<u8>>,
        new_destination_caller: &option::Option<address>
    ) {
        pausable::assert_not_paused(state::get_object_address());
        message::validate_message(original_message);
        attester::verify_attestation_signature(original_message, original_attestation);

        let sender_address = message::get_sender_address(original_message);
        assert!(sender_address == signer::address_of(caller), error::permission_denied(ENOT_ORIGINAL_SENDER));

        let source_domain = message::get_src_domain_id(original_message);
        assert!(source_domain == local_domain(), error::invalid_argument(EINCORRECT_SOURCE_DOMAIN));

        let destination_domain = message::get_destination_domain_id(original_message);
        let recipient = message::get_recipient_address(original_message);
        let nonce = message::get_nonce(original_message);
        let original_destination_caller = message::get_destination_caller(original_message);
        let original_message_body = message::get_message_body(original_message);
        serialize_message_and_emit_event(
            destination_domain,
            recipient,
            sender_address,
            option::get_with_default(new_destination_caller, original_destination_caller),
            nonce,
            option::borrow_with_default(new_message_body, &original_message_body),
        )
    }

    /// Receives a message. Messages with a given nonce can only be received once for a 
    /// (sourceDomain, destinationDomain). Message format is defined in `message_transmitter::message` module.
    /// A valid attestation is the concatenated 65-byte signature(s) of exactly `thresholdSignature` signatures, in
    /// increasing order of attester address.
    ///
    /// This functions returns `Receipt` struct ([Hot Potato](https://medium.com/@borispovod/move-hot-potato-pattern-bbc48a48d93c))
    /// after validating attestation and marking nonce used. The receiving contract calls `complete_receive()` with the
    /// receipt after running through its own logic to emit the `MessageReceived` event
    /// and destroy `Receipt`. e.g
    /// ```
    ///     let receipt = message_transmitter::receive_message(caller, message, attestation);
    ///     receiving_module::handle_receive_message(caller, receipt)
    ///
    ///     // The `complete_receive_message` will be called from the receiving contract. Signer should be generated
    ///     // from the receiving contract's account or object.
    ///     let success = message_transmitter::complete_receive_message(caller, receipt);
    ///     assert!(success, 0);
    /// ```
    /// Aborts if:
    /// - the contract is paused
    /// - message is invalid
    /// - attestation is not valid
    /// - caller is not authorized to receive the message (not the destination caller)
    /// - message version is invalid
    /// - destination domain id from the message doesn't match the local domain id
    /// - the nonce is already used
    public fun receive_message(caller: &signer, message_bytes: &vector<u8>, attestation: &vector<u8>): Receipt {
        pausable::assert_not_paused(state::get_object_address());
        message::validate_message(message_bytes);
        attester::verify_attestation_signature(message_bytes, attestation);

        // Validate destination domain
        let destination_domain = message::get_destination_domain_id(message_bytes);
        assert!(destination_domain == local_domain(), error::invalid_argument(EINCORRECT_DESTINATION_DOMAIN));

        // Validate destination caller
        let destination_caller = message::get_destination_caller(message_bytes);
        assert!(
            destination_caller == @0x0 || destination_caller == signer::address_of(caller),
            error::permission_denied(EINCORRECT_CALLER_FOR_THE_MESSAGE)
        );

        // Validate message version
        assert!(
            message::get_message_version(message_bytes) == version(),
            error::invalid_argument(EINVALID_MESSAGE_VERSION)
        );

        // Validate nonce is available and mark it used
        let source_domain = message::get_src_domain_id(message_bytes);
        let nonce = message::get_nonce(message_bytes);
        let source_and_nonce_hash = hash_source_and_nonce(source_domain, nonce);
        assert!(!is_nonce_used(source_and_nonce_hash), error::already_exists(ENONCE_ALREADY_USED));
        state::set_nonce_used(source_and_nonce_hash);

        // Return unstamped receipt
        Receipt {
            caller: signer::address_of(caller),
            recipient: message::get_recipient_address(message_bytes),
            source_domain,
            nonce,
            sender: message::get_sender_address(message_bytes),
            message_body: message::get_message_body(message_bytes)
        }
    }

    /// This function takes in a receipt, verifies it, emits `MessageReceived` event and destroys the receipt.
    /// Aborts if:
    /// - caller is not the receipt recipient
    public fun complete_receive_message(caller: &signer, receipt: Receipt): bool {
        assert!(
            receipt.recipient == signer::address_of(caller),
            error::permission_denied(EUNAUTHORIZED_RECEIVING_ADDRESS)
        );
        event::emit(MessageReceived {
            caller: receipt.caller,
            source_domain: receipt.source_domain,
            nonce: receipt.nonce,
            sender: receipt.sender,
            message_body: receipt.message_body
        });
        destroy_receipt(receipt);
        true
    }

    /// Sets the max message body size (in bytes). Emits `MaxMessageBodySizeUpdated` event.
    /// Aborts if:
    /// - the caller is not the owner
    entry fun set_max_message_body_size(caller: &signer, new_max_message_body_size: u64) {
        ownable::assert_is_owner(caller, state::get_object_address());
        state::set_max_message_body_size(new_max_message_body_size);
        event::emit(MaxMessageBodySizeUpdated { max_message_body_size: new_max_message_body_size })
    }

    /// Public helper functions to retrieve struct fields since structs are only accessible within the same module
    public fun get_receipt_details(receipt: &Receipt): (address, address, u32, vector<u8>) {
        (receipt.sender, receipt.recipient, receipt.source_domain, receipt.message_body)
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    /// Generate signer from the `ExtendRef`
    fun get_signer(): signer acquires ObjectController {
        let object_address = state::get_object_address();
        let object_controller = borrow_global<ObjectController>(object_address);
        let object_signer = object::generate_signer_for_extending(
            &object_controller.extend_ref
        );
        object_signer
    }

    fun serialize_message_and_emit_event(
        destination_domain: u32,
        recipient: address,
        sender_address: address,
        destination_caller: address,
        nonce: u64,
        message_body: &vector<u8>
    ) {
        assert!(
            vector::length(message_body) <= state::get_max_message_body_size(),
            error::invalid_argument(EMESSAGE_BODY_EXCEEDS_MAX_SIZE)
        );
        assert!(recipient != @0x0, error::invalid_argument(EINVALID_RECIPIENT_ADDRESS));
        let message = message::serialize(
            version(),
            local_domain(),
            destination_domain,
            nonce,
            sender_address,
            recipient,
            destination_caller,
            message_body
        );
        event::emit(MessageSent { message });
    }

    fun reserve_and_increment_nonce(): u64 {
        let nonce = state::get_next_available_nonce();
        state::set_next_available_nonce(nonce+1);
        nonce
    }

    /// Create hash based on "{source}-{nonce}"
    fun hash_source_and_nonce(source: u32, nonce: u64): address {
        let key = bcs::to_bytes(&source);
        vector::append(&mut key, b"-");
        vector::append(&mut key, bcs::to_bytes(&nonce));
        let hash = aptos_hash::keccak256(key);
        from_bcs::to_address(hash)
    }

    fun destroy_receipt(receipt: Receipt) {
        let Receipt {
            caller: _,
            recipient: _,
            source_domain: _,
            nonce: _,
            sender: _,
            message_body: _
        } = receipt;
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_std::aptos_hash::keccak256;
    #[test_only]
    use aptos_framework::account::{Self, create_signer_for_test};
    #[test_only]
    use aptos_extensions::ownable::OwnerRole;
    #[test_only]
    use aptos_extensions::pausable::PauseState;

    // Test Helper Functions

    #[test_only]
    const RECEIVING_CONTRACT: address = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e;
    #[test_only]
    const TEST_SEED: vector<u8>  = b"test_seed_mt";

    #[test_only]
    public fun init_test_message_transmitter_module(deployer: address) {
        account::create_account_for_test(deployer);
        resource_account::create_resource_account(
            &create_signer_for_test(deployer),
            TEST_SEED,
            x"",
        );
        let resource_account_address = account::create_resource_address(&deployer, TEST_SEED);
        assert!(@message_transmitter == resource_account_address, 0);
        let resource_account_signer = create_signer_for_test(resource_account_address);
        init_module(&resource_account_signer);
    }

    #[test_only]
    public fun initialize_test_message_transmitter(deployer: &signer) acquires ObjectController {
        init_test_message_transmitter_module(signer::address_of(deployer));
        initialize_message_transmitter(deployer, 9, @0xC0664d3a3b411653A3DD791492c01f4819AC84B4, 256, 0);
    }

    #[test_only]
    fun get_valid_send_message_and_attestation(): (vector<u8>, vector<u8>) {
        let original_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            1,
            7384,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            &b"Hello",
        );
        let original_attestation = x"027a76974e2c7c5264544eaf079a62a42d48d7c5015844dd996ab35c4285380a5e7dc8d22813cccd1650aac26965abc1224145ec37cc4f80b027ca2d7877aa451b";
        (original_message, original_attestation)
    }

    #[test_only]
    fun get_valid_receive_message_and_attestation(): (vector<u8>, vector<u8>){
        let message = message::serialize(
            state::get_version(),
            0,
            local_domain(),
            7384,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            RECEIVING_CONTRACT,
            @deployer,
            &b"Hello",
        );
        let attestation = x"78eede2dcaa5dbf6d1a9ce0831f699a6f8a6db9150cb8e26354432b2667f92406092b130cfc71f21ddb814a5ee1f1cee4f2d5cb43b712a7bb0b59fbbae018f2c1c";
        (message, attestation)
    }

    #[test_only]
    public fun get_message_from_event(message_sent_event: &MessageSent): vector<u8> {
        message_sent_event.message
    }

    // Message Transmitter Initialization Tests

    #[test(owner = @deployer)]
    fun test_init_message_transmitter(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        assert!(state::is_initialized(), 0);
        assert!(exists<ObjectController>(state::get_object_address()), 0);
        assert!(attester::is_enabled_attester(attester::get_enabled_attester(0)), 0);
        assert!(manageable::admin(@message_transmitter) == @deployer, 0);
        assert!(ownable::owner(object::address_to_object<OwnerRole>(state::get_object_address())) == @deployer, 0);
        assert!(pausable::pauser(object::address_to_object<PauseState>(state::get_object_address())) == @deployer, 0);
        assert!(!pausable::is_paused(object::address_to_object<PauseState>(state::get_object_address())), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80006, location = Self)]
    fun test_init_message_transmitter_already_initialized(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        initialize_message_transmitter(owner, 9, @0xfac, 256, 0);
    }

    #[test(not_owner = @0xfaa)]
    #[expected_failure(abort_code = manageable::ENOT_ADMIN, location = manageable)]
    fun test_init_message_transmitter_not_owner(not_owner: &signer) acquires ObjectController {
        init_test_message_transmitter_module(@deployer);
        initialize_message_transmitter(not_owner, 9, @0xfac, 256, 0);
    }

    // Send Message Tests

    #[test(owner = @deployer)]
    fun test_send_message_success(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);

        let expected_nonce = state::get_next_available_nonce();
        let recipient = @0xfac;
        let message_body = b"message";
        let destination_domain = 1;
        let nonce = send_message(owner, destination_domain, recipient, &message_body);
        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            destination_domain,
            expected_nonce,
            @deployer,
            recipient,
            @0x0,
            &message_body
        );

        assert!(nonce == expected_nonce, 0);
        assert!(event::was_event_emitted(&MessageSent { message: expected_message }), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_send_message_contract_paused(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        send_message(owner, 1, @0xfac, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_send_message_excess_message_body_size(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_max_message_body_size(2);
        send_message(owner, 1, @0xfac, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_send_message_zero_recipient_address(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        send_message(owner, 1, @0x0, &b"message");
    }

    // Send Message With Caller Tests

    #[test(owner = @deployer)]
    fun test_send_message_with_caller_success(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);

        let expected_nonce = state::get_next_available_nonce();
        let recipient = @0xfac;
        let message_body = b"message";
        let destination_domain = 1;
        let destination_caller = @0xfaa;
        let nonce = send_message_with_caller(owner, destination_domain, recipient, destination_caller, &message_body);
        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            destination_domain,
            expected_nonce,
            @deployer,
            recipient,
            destination_caller,
            &message_body
        );

        assert!(nonce == expected_nonce, 0);
        assert!(event::was_event_emitted(&MessageSent { message: expected_message }), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_send_message_with_caller_contract_paused(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        send_message_with_caller(owner, 1, @0xfac, @0xfaa, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_send_message_with_caller_excess_message_body_size(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_max_message_body_size(2);
        send_message_with_caller(owner, 1, @0xfac, @0xfaa, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_send_message_with_caller_zero_recipient_address(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        send_message_with_caller(owner, 1, @0x0, @0xfaa, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_send_message_with_caller_zero_destination_caller_address(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        send_message_with_caller(owner, 1, @0xfac, @0x0, &b"message");
    }

    // Replace Message Tests

    #[test(owner = @deployer)]
    fun test_replace_message_new_destination_caller(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        let new_destination_caller = @0xfab;
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::some(new_destination_caller),
        );

        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            1,
            7384,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            new_destination_caller,
            &b"Hello",
        );
        assert!(event::was_event_emitted(&MessageSent { message: expected_message }), 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_message_new_message_body(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        let new_message_bdy = b"New Message";
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::some(new_message_bdy),
            &option::none(),
        );

        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            1,
            7384,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            &new_message_bdy,
        );
        assert!(event::was_event_emitted(&MessageSent { message: expected_message }), 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_message_new_message_body_and_destination_caller(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        let new_message_bdy = b"New Message";
        let new_destination_caller = @0xfab;
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::some(new_message_bdy),
            &option::some(new_destination_caller),
        );

        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            1,
            7384,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            new_destination_caller,
            &new_message_bdy,
        );
        assert!(event::was_event_emitted(&MessageSent { message: expected_message }), 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_message_no_change(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::none(),
        );
        assert!(event::was_event_emitted(&MessageSent { message: original_message }), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_replace_message_contract_paused(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::none(),
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_replace_message_excess_message_body_size(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_max_message_body_size(2);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::some(b"Hello"),
            &option::none(),
        );
    }

    #[test(owner = @deployer, incorrect_sender = @0xfaa)]
    #[expected_failure(abort_code = 0x50004, location = Self)]
    fun test_replace_message_not_original_sender(owner: &signer, incorrect_sender: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        replace_message(
            incorrect_sender,
            &original_message,
            &original_attestation,
            &option::some(b"New Message"),
            &option::none(),
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10005, location = Self)]
    fun test_replace_message_incorrect_domain_id(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let original_message = message::serialize(
            state::get_version(),
            5,
            1,
            7384,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            &b"Hello",
        );
        let original_attestation = x"d83ece55985280777daff7e74c80e3480aa8c98aec0da457817ce95c4e7be7d34e4e66ef12a6e32cd7c95571873bd3a186cb510a093644abb5c7c07525dfe8221b";
        replace_message(
            owner,
            &original_message,
            &original_attestation,
            &option::some(b"New Message"),
            &option::none(),
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = message)]
    fun test_replace_message_invalid_message(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, original_attestation) = get_valid_send_message_and_attestation();
        let invalid_message = vector::slice(&original_message, 0, 10);
        replace_message(
            owner,
            &invalid_message,
            &original_attestation,
            &option::none(),
            &option::none(),
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000c, location = attester)]
    fun test_replace_message_invalid_attestation(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (original_message, _) = get_valid_send_message_and_attestation();
        let (_, attestation) = get_valid_receive_message_and_attestation();
        replace_message(
            owner,
            &original_message,
            &attestation,
            &option::none(),
            &option::none(),
        );
    }

    // Receive Message Tests

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_receive_message_success(owner: &signer, receiving_contract: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);

        let source_domain = 0;
        let sender = @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb;
        let message_body = b"Hello";
        let nonce = 7384;
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);

        assert!(receipt.nonce == nonce, 0);
        assert!(receipt.recipient == RECEIVING_CONTRACT, 0);
        assert!(receipt.sender == sender, 0);
        assert!(receipt.source_domain == source_domain, 0);
        assert!(receipt.message_body == message_body, 0);
        assert!(complete_receive_message(receiving_contract, receipt), 0);
        assert!(event::was_event_emitted(&MessageReceived {
            caller: signer::address_of(owner),
            source_domain,
            nonce,
            sender,
            message_body
        }), 0);
        assert!(state::is_nonce_used(hash_source_and_nonce(source_domain, nonce)), 0);
    }

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_receive_message_empty_destination_caller(owner: &signer, receiving_contract: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);

        let source_domain = 0;
        let sender = @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb;
        let message_body = b"Hello";
        let recipient = RECEIVING_CONTRACT;
        let nonce = 7384;
        let message = message::serialize(
            state::get_version(),
            source_domain,
            local_domain(),
            nonce,
            sender,
            recipient,
            @0x0,
            &b"Hello"
        );
        let attestation = x"2a5f3a941fa31140b74e05b4fb218976691777a00199ec5de6fb24146060f6c96c8da25b08a3cb3be22d11c9cf3ac0705062167104db50cb6111e3193efafccd1b";
        let receipt = receive_message(owner, &message, &attestation);
        assert!(receipt.nonce == nonce, 0);
        assert!(receipt.recipient == recipient, 0);
        assert!(receipt.sender == sender, 0);
        assert!(receipt.source_domain == source_domain, 0);
        assert!(receipt.message_body == message_body, 0);
        assert!(complete_receive_message(receiving_contract, receipt), 0);
        assert!(event::was_event_emitted(&MessageReceived {
            caller: signer::address_of(owner),
            source_domain,
            nonce,
            sender,
            message_body
        }), 0);
        assert!(state::is_nonce_used(hash_source_and_nonce(source_domain, nonce)), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_receive_message_contract_paused(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = message)]
    fun test_receive_message_invalid_message(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let invalid_message = vector::slice(&message, 0, 10);
        let receipt = receive_message(owner, &invalid_message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000c, location = attester)]
    fun test_receive_message_invalid_attestation(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, _) = get_valid_receive_message_and_attestation();
        let (_, attestation) = get_valid_send_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer, unauthorized_caller = @0xfaa)]
    #[expected_failure(abort_code = 0x50008, location = Self)]
    fun test_receive_message_not_authorized(owner: &signer, unauthorized_caller: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = receive_message(unauthorized_caller, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10007, location = Self)]
    fun test_receive_message_incorrect_domain_id(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_send_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    fun test_receive_message_invalid_message_version(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        state::set_version(1);
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x8000a, location = Self)]
    fun test_receive_message_nonce_already_used(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let nonce = message::get_nonce(&message);
        let source_domain = message::get_src_domain_id(&message);
        state::set_nonce_used(hash_source_and_nonce(source_domain, nonce));
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    // Complete Receive Message Tests

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_complete_receive_message_success(owner: &signer, receiving_contract: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let receipt = Receipt {
            caller: signer::address_of(owner),
            recipient: RECEIVING_CONTRACT,
            source_domain: 6,
            nonce: 523344,
            sender: @0xfaa,
            message_body: b"Message",
        };
        assert!(complete_receive_message(receiving_contract, receipt), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x5000b, location = Self)]
    fun test_complete_receive_message_unauthorized_caller(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let stamped_receipt = Receipt {
            caller: signer::address_of(owner),
            recipient: RECEIVING_CONTRACT,
            source_domain: 6,
            nonce: 523344,
            sender: @0xfaa,
            message_body: b"Message",
        };
        complete_receive_message(owner, stamped_receipt);
    }

    // Set Max Message Body Size Tests

    #[test(owner = @deployer)]
    fun test_set_max_message_body_size_success(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        set_max_message_body_size(owner, 512);
        assert!(state::get_max_message_body_size() == 512, 0);
        assert!(event::was_event_emitted(&MaxMessageBodySizeUpdated {
            max_message_body_size: 512
        }), 0)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_set_max_message_body_size_not_owner(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        state::set_owner(@0xfaa);
        set_max_message_body_size(owner, 512);
    }

    // Get Receipt Details test

    #[test]
    fun test_get_receipt_details() {
        let receipt = Receipt {
            caller: @0xfac,
            recipient: @0xfaa,
            source_domain: 1,
            sender: @0xfab,
            nonce: 5723,
            message_body: b"message_body"
        };

        let (sender, recipient, source_domain, message_body) = get_receipt_details(&receipt);
        assert!(recipient == @0xfaa, 0);
        assert!(source_domain == 1, 0);
        assert!(sender == @0xfab, 0);
        assert!(message_body == b"message_body", 0);
        destroy_receipt(receipt);
    }

    // View Function Tests

    #[test(owner = @deployer)]
    fun test_is_nonce_used(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        let key = from_bcs::to_address(keccak256(b"Hello!"));
        state::set_nonce_used(key);
        assert!(is_nonce_used(key), 0);
    }

    #[test(owner = @deployer)]
    fun test_next_available_nonce(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        assert!(next_available_nonce() == state::get_next_available_nonce(), 0);
    }

    #[test(owner = @deployer)]
    fun test_max_message_body_size(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        assert!(max_message_body_size() == state::get_max_message_body_size(), 0);
    }

    #[test(owner = @deployer)]
    fun test_object_address(owner: &signer) acquires ObjectController {
        initialize_test_message_transmitter(owner);
        assert!(object_address() == state::get_object_address(), 0);
    }
}
