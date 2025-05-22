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

module token_messenger_minter::state {
    // Built-in Modules
    use std::bcs;
    use std::vector;
    use aptos_std::aptos_hash;
    use aptos_std::from_bcs;
    use aptos_std::smart_table;
    use aptos_framework::object;
    use aptos_extensions::pausable::PauseState;

    // Package Modules
    use aptos_extensions::pausable;
    #[test_only]
    use std::signer;
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_extensions::ownable;

    // Friend Modules
    friend token_messenger_minter::token_messenger_minter;
    friend token_messenger_minter::token_messenger;
    friend token_messenger_minter::token_controller;
    friend token_messenger_minter::token_minter;

    // Constants
    const SEED_NAME: vector<u8> = b"TokenMessengerMinter";

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct State has key {
        message_body_version: u32,
        remote_token_messengers: smart_table::SmartTable<u32, address>,
        burn_limits_per_message: smart_table::SmartTable<address, u64>,
        remote_tokens_to_local_tokens: smart_table::SmartTable<address, address>,

        // Admin Roles
        token_controller: address                   // Controls remote resources and burn limits
    }

    public(friend) fun init_state(
        admin: &signer,
        message_body_version: u32,
    ) {
        move_to(
            admin,
            State {
                message_body_version,
                remote_token_messengers: smart_table::new(),
                remote_tokens_to_local_tokens: smart_table::new(),
                burn_limits_per_message: smart_table::new(),

                // Admin Roles
                token_controller: @0x0,             // Token Controller gets initialized in its own module
            }
        );
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    public(friend) fun is_initialized(): bool {
        exists<State>(get_object_address())
    }

    public(friend) fun get_message_body_version(): u32 acquires State {
        borrow_global<State>(get_object_address()).message_body_version
    }

    public(friend) fun get_remote_token_messenger(domain: u32): address acquires State {
        *smart_table::borrow(&borrow_global<State>(get_object_address()).remote_token_messengers, domain)
    }

    public(friend) fun is_remote_token_messenger_set_for_domain(
        domain: u32
    ): bool acquires State {
        smart_table::contains(
            &borrow_global<State>(get_object_address()).remote_token_messengers,
            domain
        )
    }

    public(friend) fun get_max_burn_limit_per_message_for_token(token: address): (bool, u64) acquires State {
        let exists = smart_table::contains(&borrow_global<State>(get_object_address()).burn_limits_per_message, token);
        if (exists) {
            (true, *smart_table::borrow(&borrow_global<State>(get_object_address()).burn_limits_per_message, token))
        } else {
            (false, 0)
        }
    }

    public(friend) fun local_token_exists(remote_domain: u32, remote_token: address): bool acquires State {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        smart_table::contains(&borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens, key)
    }

    public(friend) fun get_local_token(remote_domain: u32, remote_token: address): address acquires State {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        *smart_table::borrow(&borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens, key)
    }

    public(friend) fun is_paused(): bool {
        pausable::is_paused(object::address_to_object<PauseState>(get_object_address()))
    }

    public(friend) fun get_token_controller(): address acquires State {
        borrow_global<State>(get_object_address()).token_controller
    }

    public(friend) fun get_num_remote_token_messengers(): u64 acquires State {
        smart_table::length(&borrow_global<State>(get_object_address()).remote_token_messengers)
    }

    public(friend) fun get_num_linked_tokens(): u64 acquires State {
        smart_table::length(&borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens)
    }

    public(friend) fun get_object_address(): address {
        object::create_object_address(&@token_messenger_minter, SEED_NAME)
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    public(friend) fun add_remote_token_messenger(domain: u32, token_messenger: address) acquires State {
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_token_messengers,
            domain,
            token_messenger
        );
    }

    public(friend) fun remove_remote_token_messenger(domain: u32): address acquires State {
        smart_table::remove(
            &mut borrow_global_mut<State>(get_object_address()).remote_token_messengers,
            domain
        )
    }

    public(friend) fun add_local_token_for_remote_token(
        remote_domain: u32,
        remote_token: address,
        local_token: address
    ) acquires State {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens,
            key,
            local_token
        );
    }

    public(friend) fun remove_local_token_for_remote_token(
        remote_domain: u32,
        remote_token: address
    ): address acquires State {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        smart_table::remove(
            &mut borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens,
            key
        )
    }

    public(friend) fun set_max_burn_limit_per_message_for_token(token: address, limit: u64) acquires State {
        smart_table::upsert(
            &mut borrow_global_mut<State>(get_object_address()).burn_limits_per_message,
            token,
            limit
        );
    }

    public(friend) fun set_token_controller(token_controller: address) acquires State {
        borrow_global_mut<State>(get_object_address()).token_controller = token_controller;
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    /// Create hash based on "{remote_domain}{token}"
    fun hash_remote_domain_and_token(remote_domain: u32, token: address): address {
        let key = bcs::to_bytes(&remote_domain);
        vector::append(&mut key, bcs::to_bytes(&token));
        let hash = aptos_hash::keccak256(key);
        from_bcs::to_address(hash)
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    public fun init_test_state(caller: &signer) {
        let resource_account_address = account::create_resource_address(&@deployer, b"test_seed_tmm");
        let resource_account_signer = create_signer_for_test(resource_account_address);
        let constructor_ref = object::create_named_object(&resource_account_signer, SEED_NAME);
        let signer = object::generate_signer(&constructor_ref);
        init_state(&signer, 1);
        ownable::new(&signer, signer::address_of(caller));
        pausable::new(&signer, signer::address_of(caller));
    }

    #[test_only]
    public fun set_paused(pauser: &signer) {
        pausable::test_pause(pauser, object::address_to_object<PauseState>(get_object_address()));
    }

    #[test_only]
    public fun set_message_body_version(message_body_version: u32) acquires State {
        borrow_global_mut<State>(get_object_address()).message_body_version = message_body_version;
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    #[test(owner = @token_messenger_minter)]
    fun test_is_initialized(owner: &signer) {
        init_test_state(owner);
        assert!(is_initialized() == true, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_message_body_version(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_message_body_version() == 1, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_remote_token_messenger(owner: &signer) acquires State {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_token_messengers,
            domain,
            token_messenger
        );
        assert!(get_remote_token_messenger(domain) == token_messenger, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_is_remote_token_messenger_set_for_domain(owner: &signer) acquires State {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_token_messengers,
            domain,
            token_messenger
        );
        assert!(is_remote_token_messenger_set_for_domain(domain), 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_burn_limit_per_message_for_token(owner: &signer) acquires State {
        init_test_state(owner);
        let token = @0xfab;
        let expected_limit = 300;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).burn_limits_per_message,
            token,
            expected_limit
        );
        let (exists, limit) = get_max_burn_limit_per_message_for_token(token);
        assert!(exists, 0);
        assert!(limit == expected_limit, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_is_remote_token(owner: &signer) acquires State {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens,
            hash_remote_domain_and_token(remote_domain, remote_token),
            local_token
        );
        assert!(local_token_exists(remote_domain, remote_token), 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_remote_token(owner: &signer) acquires State {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens,
            hash_remote_domain_and_token(remote_domain, remote_token),
            local_token
        );
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_is_paused(owner: &signer) {
        init_test_state(owner);
        assert!(is_paused() == false, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_token_controller(owner: &signer) acquires State {
        init_test_state(owner);
        assert!(get_token_controller() == @0x0, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_num_remote_token_messengers(owner: &signer) acquires State {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_token_messengers,
            domain,
            token_messenger
        );
        assert!(get_num_remote_token_messengers() == 1, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_hash_remote_domain_and_token(owner: &signer) {
        init_test_state(owner);
        let hash = hash_remote_domain_and_token(4, @0xfac);
        assert!(hash == @0x8ae28a8d79ea231bafe63fb643c45dce060b33a1c2e122d161c4d8b75997436, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_get_num_linked_tokens(owner: &signer) acquires State {
        init_test_state(owner);
        smart_table::add(
            &mut borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens, @0x100, @0x101
        );
        assert!(get_num_linked_tokens() == 1, 0)
    }


    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    #[test(owner = @token_messenger_minter)]
    fun test_add_remote_token_messenger(owner: &signer) acquires State {
        init_test_state(owner);
        let domain = 5;
        let token_messenger = @0xcaf;
        add_remote_token_messenger(domain, token_messenger);
        assert!(get_remote_token_messenger(domain) == token_messenger, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_remove_remote_token_messenger(owner: &signer) acquires State {
        init_test_state(owner);
        let domain = 5;
        let token_messenger = @0xcaf;
        add_remote_token_messenger(domain, token_messenger);
        assert!(get_remote_token_messenger(domain) == token_messenger, 0);

        remove_remote_token_messenger(domain);
        assert!(!is_remote_token_messenger_set_for_domain(domain), 0)
    }

    #[test(owner = @token_messenger_minter)]
    fun test_add_remote_token(owner: &signer) acquires State {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_remove_remote_token(owner: &signer) acquires State {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);

        remove_local_token_for_remote_token(remote_domain, remote_token);
        assert!(!local_token_exists(remote_domain, remote_token), 0);
    }

    #[test(owner = @token_messenger_minter)]
    fun test_set_max_burn_limit_for_token(owner: &signer) acquires State {
        init_test_state(owner);
        let token = @0xcaf;
        let limit = 300;
        set_max_burn_limit_per_message_for_token(token, limit);
        assert!(
            *smart_table::borrow(&borrow_global<State>(get_object_address()).burn_limits_per_message, token) == limit,
            0
        )
    }

    #[test(owner = @token_messenger_minter)]
    fun test_set_token_controller(owner: &signer) acquires State {
        init_test_state(owner);
        let new_token_controller = @0xfad;
        set_token_controller(new_token_controller);
        assert!(get_token_controller() == new_token_controller, 0);
    }
}
