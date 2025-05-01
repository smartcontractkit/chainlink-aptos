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

module message_transmitter::state {
    // Built-in Modules
    use std::error;
    use std::signer;
    use std::vector;
    use aptos_std::table_with_length::{Self, TableWithLength};
    use aptos_framework::object;
    use aptos_extensions::ownable::OwnerRole;

    // Package Modules
    use aptos_extensions::ownable;

    // Friend Modules
    friend message_transmitter::attester;
    friend message_transmitter::message_transmitter;

    // Constants
    const SEED_NAME: vector<u8> = b"MessageTransmitter";

    // Error Codes
    const EATTESTER_NOT_FOUND: u64 = 1;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct State has key {
        local_domain: u32,
        version: u32,
        max_message_body_size: u64,
        next_available_nonce: u64,
        // Key for used_nonces is 32 bytes hash which can be represented using address
        used_nonces: TableWithLength<address, bool>,
        signature_threshold: u64,

        // Admin Roles
        enabled_attesters: vector<address>,         // Authorized witnesses to bridge transactions
        attester_manager: address,                  // Manages attester state and configuration
    }

    public(friend) fun init_state(
        owner: &signer,
        object_signer: &signer,
        local_domain: u32,
        version: u32,
        max_message_body_size: u64
    ) {
        move_to(
            object_signer,
            State {
                local_domain,
                version,
                max_message_body_size,
                next_available_nonce: 0,
                used_nonces: table_with_length::new(),
                signature_threshold: 1,

                // Admin Roles
                attester_manager: signer::address_of(owner),
                enabled_attesters: vector::empty(),
            }
        );
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    public(friend) fun is_initialized(): bool {
        exists<State>(get_object_address())
    }

    public(friend) fun get_local_domain(): u32 acquires State {
        borrow_global<State>(get_object_address()).local_domain
    }

    public(friend) fun get_version(): u32 acquires State {
        borrow_global<State>(get_object_address()).version
    }

    public(friend) fun get_max_message_body_size(): u64 acquires State {
        borrow_global<State>(get_object_address()).max_message_body_size
    }

    public(friend) fun get_next_available_nonce(): u64 acquires State {
        borrow_global<State>(get_object_address()).next_available_nonce
    }

    public(friend) fun is_nonce_used(source_and_nonce_hash: address): bool acquires State {
        table_with_length::contains(&borrow_global<State>(get_object_address()).used_nonces, source_and_nonce_hash)
    }

    public(friend) fun get_signature_threshold(): u64 acquires State {
        borrow_global<State>(get_object_address()).signature_threshold
    }

    public(friend) fun get_enabled_attesters(): vector<address> acquires State {
        borrow_global<State>(get_object_address()).enabled_attesters
    }

    public(friend) fun get_num_enabled_attesters(): u64 acquires State {
        vector::length(&borrow_global<State>(get_object_address()).enabled_attesters)
    }

    public(friend) fun get_attester_manager(): address acquires State {
        borrow_global<State>(get_object_address()).attester_manager
    }

    public(friend) fun get_owner(): address {
        ownable::owner(object::address_to_object<OwnerRole>(get_object_address()))
    }

    public(friend) fun get_object_address(): address {
        object::create_object_address(&@message_transmitter, SEED_NAME)
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    public(friend) fun set_max_message_body_size(max_message_body_size: u64) acquires State {
        borrow_global_mut<State>(get_object_address()).max_message_body_size = max_message_body_size
    }

    public(friend) fun set_next_available_nonce(next_available_nonce: u64) acquires State {
        borrow_global_mut<State>(get_object_address()).next_available_nonce = next_available_nonce
    }

    public(friend) fun set_nonce_used(source_and_nonce_hash: address) acquires State {
        table_with_length::add(
            &mut borrow_global_mut<State>(get_object_address()).used_nonces, source_and_nonce_hash,
            true
        );
    }

    public(friend) fun set_signature_threshold(signature_threshold: u64) acquires State {
        borrow_global_mut<State>(get_object_address()).signature_threshold = signature_threshold
    }

    public(friend) fun add_attester(attester: address) acquires State {
        vector::push_back(&mut borrow_global_mut<State>(get_object_address()).enabled_attesters, attester);
    }

    public(friend) fun remove_attester(attester: address) acquires State {
        let state = borrow_global_mut<State>(get_object_address());
        let (found, index) = vector::index_of(&mut state.enabled_attesters, &attester);
        assert!(found, error::not_found(EATTESTER_NOT_FOUND));
        vector::remove(&mut state.enabled_attesters, index);
    }

    public(friend) fun set_attester_manager(attester_manager: address) acquires State {
        borrow_global_mut<State>(get_object_address()).attester_manager = attester_manager
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_std::aptos_hash::keccak256;
    #[test_only]
    use aptos_std::from_bcs;
    #[test_only]
    use aptos_framework::account::{Self, create_signer_for_test};
    #[test_only]
    use aptos_extensions::pausable::{Self, PauseState};

    #[test_only]
    public fun init_test_state(caller: &signer) {
        let resource_account_address = account::create_resource_address(&@deployer, b"test_seed_mt");
        let resource_account_signer = create_signer_for_test(resource_account_address);
        let constructor_ref = object::create_named_object(&resource_account_signer, SEED_NAME);
        let signer = object::generate_signer(&constructor_ref);
        init_state(caller, &signer, 9, 0, 256);
        ownable::new(&signer, signer::address_of(caller));
        pausable::new(&signer, signer::address_of(caller));
    }

    #[test_only]
    public fun set_paused(pauser: &signer) {
        pausable::test_pause(pauser, object::address_to_object<PauseState>(get_object_address()));
    }

    #[test_only]
    public fun set_owner(owner_address: address) {
        ownable::set_owner_for_testing(get_object_address(), owner_address);
    }

    #[test_only]
    public fun set_version(version: u32) acquires State {
        borrow_global_mut<State>(get_object_address()).version = version
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    #[test(owner = @message_transmitter)]
    fun test_is_initialized(owner: &signer) {
        init_test_state(owner);
        assert!(is_initialized() == true, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_local_domain(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_local_domain() == 9, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_version(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_version() == 0, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_max_message_body_size(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_max_message_body_size() == 256, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_next_available_nonce(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_next_available_nonce() == 0, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_is_nonce_used(owner: &signer) acquires State {
        init_test_state(owner);
        let key = from_bcs::to_address(keccak256(b"Hello!"));
        assert!(is_nonce_used(key) == false, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_signature_threshold(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_signature_threshold() == 1, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_attester_manager(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_attester_manager() == signer::address_of(owner), 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_enabled_attesters(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_enabled_attesters() == vector::empty(), 0);
    }

    #[test(owner = @message_transmitter, attester = @0x1234)]
    fun test_get_num_enabled_attesters(owner: &signer, attester: &signer) acquires State {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        assert!(get_num_enabled_attesters() == 1, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_get_owner(owner: &signer) {
        init_test_state(owner);
        assert!(get_owner() == signer::address_of(owner), 0);
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    #[test(owner = @message_transmitter)]
    fun test_set_max_message_body_size(owner: &signer) acquires State {
        init_test_state(owner);
        let max_message_body_size = 512;
        set_max_message_body_size(max_message_body_size);
        assert!(get_max_message_body_size() == max_message_body_size, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_set_next_available_nonce(owner: &signer) acquires State {
        init_test_state(owner);
        let next_available_nonce = 10;
        set_next_available_nonce(next_available_nonce);
        assert!(get_next_available_nonce() == next_available_nonce, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_set_nonce_used(owner: &signer) acquires State {
        init_test_state(owner);
        let key = from_bcs::to_address(keccak256(b"Hello!"));
        set_nonce_used(key);
        assert!(is_nonce_used(key) == true, 0);
    }

    #[test(owner = @message_transmitter)]
    fun test_set_signature_threshold(owner: &signer) acquires State {
        init_test_state(owner);
        let signature_threshold = 10;
        set_signature_threshold(signature_threshold);
        assert!(get_signature_threshold() == signature_threshold, 0);
    }

    #[test(owner = @message_transmitter, manager = @0x1234)]
    fun test_set_attester_manager(owner: &signer, manager: &signer) acquires State {
        init_test_state(owner);
        let address = signer::address_of(manager);
        set_attester_manager(address);
        assert!(get_attester_manager() == address, 0);
    }

    #[test(owner = @message_transmitter, attester = @0x1234)]
    fun test_add_attester(owner: &signer, attester: &signer) acquires State {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        assert!(vector::contains(&get_enabled_attesters(), &address), 0);
    }

    #[test(owner = @message_transmitter, attester = @0x1234)]
    fun test_remove_attester(owner: &signer, attester: &signer) acquires State {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        remove_attester(address);
        assert!(!vector::contains(&get_enabled_attesters(), &address), 0);
    }

    #[test(owner = @message_transmitter, unknown_attester = @0x1234)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_remove_attester_attester_does_not_exist(owner: &signer, unknown_attester: &signer) acquires State {
        init_test_state(owner);
        let address = signer::address_of(unknown_attester);
        remove_attester(address);
    }
}
