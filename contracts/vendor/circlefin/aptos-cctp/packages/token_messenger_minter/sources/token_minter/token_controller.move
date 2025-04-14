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


module token_messenger_minter::token_controller {
    // Built-in Modules
    use std::error;
    use std::signer;
    use aptos_framework::event;
    use aptos_extensions::ownable;

    // Package Modules
    use token_messenger_minter::state;

    // Friend Modules
    friend token_messenger_minter::token_minter;
    friend token_messenger_minter::token_messenger_minter;

    // Errors
    const ENOT_TOKEN_CONTROLLER: u64 = 1;
    const EBURN_TOKEN_NOT_SUPPORTED: u64 = 2;
    const EAMOUNT_EXCEEDS_BURN_LIMIT: u64 = 3;
    const EREMOTE_DOMAIN_AND_TOKEN_ALREADY_LINKED: u64 = 4;
    const ENO_LINK_EXIST_FOR_REMOTE_DOMAIN_AND_TOKEN: u64 = 5;

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct TokenPairLinked has drop, store {
        local_token: address,
        remote_domain: u32,
        remote_token: address
    }

    #[event]
    struct TokenPairUnlinked has drop, store {
        local_token: address,
        remote_domain: u32,
        remote_token: address
    }

    #[event]
    struct SetBurnLimitPerMessage has drop, store {
        token: address,
        burn_limit_per_message: u64,
    }

    #[event]
    struct SetTokenController has drop, store {
        token_controller: address,
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    public fun token_controller(): address {
        state::get_token_controller()
    }

    #[view]
    public fun get_linked_token(remote_domain: u32, remote_token: address): address {
        get_local_token(remote_domain, remote_token)
    }

    #[view]
    public fun get_num_linked_tokens(): u64 {
        state::get_num_linked_tokens()
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    /// Sets the token controller address. Emits `SetTokenController` event
    /// Aborts if:
    /// - the caller is not the owner
    public(friend) entry fun set_token_controller(caller: &signer, new_token_controller: address) {
        ownable::assert_is_owner(caller, state::get_object_address());
        state::set_token_controller(new_token_controller);
        event::emit(SetTokenController { token_controller: new_token_controller });
    }

    /// Sets the maximum amount allowed to be burned per message/tx. Emits `SetBurnLimitPerMessage` event
    /// Aborts if:
    /// - the caller is not the token controller
    entry fun set_max_burn_amount_per_message(caller: &signer, token: address, burn_limit_per_message: u64) {
        assert_is_token_controller(caller);
        state::set_max_burn_limit_per_message_for_token(token, burn_limit_per_message);
        event::emit(SetBurnLimitPerMessage { token, burn_limit_per_message })
    }

    /// Links remote token to local token that can be minted/burned. Remote token can only be linked to one local token
    /// at a time. Emits `TokenPairLinked` event
    /// Aborts if:
    /// - the caller is not the token controller
    /// - remote token is already linked to a local token
    entry fun link_token_pair(caller: &signer, local_token: address, remote_domain: u32, remote_token: address) {
        assert_is_token_controller(caller);
        assert!(
            !state::local_token_exists(remote_domain, remote_token),
            error::already_exists(EREMOTE_DOMAIN_AND_TOKEN_ALREADY_LINKED)
        );
        state::add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        event::emit(TokenPairLinked { local_token, remote_domain, remote_token } );
    }

    /// Unlinks remote token and local token pair. Emits `TokenPairUnlinked` event
    /// Aborts if:
    /// - the caller is not the token controller
    /// - no link exists for the given remote token and domain
    entry fun unlink_token_pair(caller: &signer, remote_domain: u32, remote_token: address) {
        assert_is_token_controller(caller);
        assert!(
            state::local_token_exists(remote_domain, remote_token),
            error::not_found(ENO_LINK_EXIST_FOR_REMOTE_DOMAIN_AND_TOKEN)
        );
        let local_token = state::remove_local_token_for_remote_token(remote_domain, remote_token);
        event::emit(TokenPairUnlinked { local_token, remote_domain, remote_token } );
    }

    // -----------------------------
    // ----- Friend Functions ------
    // -----------------------------

    public(friend) fun assert_amount_within_burn_limit(token: address, amount: u64) {
        let (token_exists, limit) = state::get_max_burn_limit_per_message_for_token(token);
        assert!(token_exists, error::invalid_argument(EBURN_TOKEN_NOT_SUPPORTED));
        assert!(amount <= limit, error::out_of_range(EAMOUNT_EXCEEDS_BURN_LIMIT))
    }

    public(friend) fun get_local_token(remote_domain: u32, remote_token: address): address {
        assert!(
            state::local_token_exists(remote_domain, remote_token),
            error::not_found(ENO_LINK_EXIST_FOR_REMOTE_DOMAIN_AND_TOKEN)
        );
        state::get_local_token(remote_domain, remote_token)
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    fun assert_is_token_controller(caller: &signer) {
        assert!(token_controller() == signer::address_of(caller), error::permission_denied(ENOT_TOKEN_CONTROLLER));
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account::create_signer_for_test;

    #[test_only] const TOKEN_CONTROLLER: address = @0x8e72;

    #[test_only]
    public fun init_test_token_controller(owner: &signer) {
        state::init_test_state(owner);
        set_token_controller(owner, TOKEN_CONTROLLER);
    }

    #[test_only]
    public fun test_link_token_pair(caller: &signer, local_token: address, remote_domain: u32, remote_token: address) {
        link_token_pair(caller, local_token, remote_domain, remote_token);
    }

    #[test_only]
    public fun test_unlink_token_pair(caller: &signer, remote_domain: u32, remote_token: address) {
        unlink_token_pair(caller, remote_domain, remote_token);
    }

    #[test_only]
    public fun test_set_max_burn_amount_per_message(caller: &signer, token: address, burn_limit_per_message: u64) {
        set_max_burn_amount_per_message(caller, token, burn_limit_per_message)
    }

    // Test Set Token Controller

    #[test(owner = @deployer)]
    fun test_set_token_controller(owner: &signer) {
        init_test_token_controller(owner);
        let token_controller = @0xfac;
        set_token_controller(owner, token_controller);
        assert!(state::get_token_controller() == token_controller, 0);
        assert!(event::was_event_emitted(&SetTokenController { token_controller }), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_set_token_controller_not_owner(owner: &signer) {
        init_test_token_controller(owner);
        let not_owner = create_signer_for_test(@10);
        set_token_controller(&not_owner, @0xfac);
    }

    // Test Assert Amount Within Burn Limit

    #[test(owner = @deployer)]
    fun test_assert_amount_within_burn_limit(owner: &signer) {
        init_test_token_controller(owner);
        let token = @0xfac;
        state::set_max_burn_limit_per_message_for_token(token, 10);
        assert_amount_within_burn_limit(token, 8);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_assert_amount_within_burn_limit_token_not_supported(owner: &signer) {
        init_test_token_controller(owner);
        assert_amount_within_burn_limit(@0xfac, 8);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x20003, location = Self)]
    fun test_assert_amount_within_burn_limit_amount_exceeds_limit(owner: &signer) {
        init_test_token_controller(owner);
        let token = @0xfac;
        state::set_max_burn_limit_per_message_for_token(token, 10);
        assert_amount_within_burn_limit(token, 15);
    }

    // Test Is Token Controller

    #[test(owner = @deployer, token_controller = @0xfac )]
    fun test_is_token_controller_success(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        set_token_controller(owner, signer::address_of(token_controller));
        assert_is_token_controller(token_controller);
    }

    #[test(owner = @deployer )]
    #[expected_failure(abort_code = 0x50001, location = Self)]
    fun test_is_token_controller_permission_denied(owner: &signer) {
        init_test_token_controller(owner);
        assert_is_token_controller(owner);
    }

    // Test Set Max Burn Amount Per Message

    #[test(owner = @deployer, token_controller = @0x8e72)]
    fun test_set_max_burn_amount_per_message_success(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        let token = @0xfac;
        let limit = 87345;
        set_max_burn_amount_per_message(token_controller, token, limit);
        let (exists, burn_limit) = state::get_max_burn_limit_per_message_for_token(token);
        assert!(exists, 0);
        assert!(burn_limit == limit, 0);
        assert!(event::was_event_emitted(&SetBurnLimitPerMessage { token, burn_limit_per_message: limit } ), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50001, location = Self)]
    fun test_set_max_burn_amount_per_message_not_token_controller(owner: &signer) {
        init_test_token_controller(owner);
        set_max_burn_amount_per_message(owner, @0xfac, 87345);
    }

    // Test Get Local Token

    #[test(owner = @deployer)]
    fun test_get_local_token(owner: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfac;
        let remote_domain = 4;
        let local_token = @0xfab;
        state::add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
    }

    // Test Link Token Pair

    #[test(owner = @deployer, token_controller = @0x8e72)]
    fun test_link_token_pair_success(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        link_token_pair(token_controller, local_token, remote_domain, remote_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
        assert!(event::was_event_emitted(&TokenPairLinked { local_token, remote_token, remote_domain } ), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50001, location = Self)]
    fun test_link_token_pair_not_token_controller(owner: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        link_token_pair(owner, local_token, remote_domain, remote_token);
    }

    #[test(owner = @deployer, token_controller = @0x8e72)]
    #[expected_failure(abort_code = 0x80004, location = Self)]
    fun test_link_token_pair_already_linked(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        link_token_pair(token_controller, local_token, remote_domain, remote_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
        link_token_pair(token_controller, @0xfff, remote_domain, remote_token);
    }

    // Test Unlink Token Pair

    #[test(owner = @deployer, token_controller = @0x8e72)]
    fun test_unlink_token_pair_success(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        state::add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        unlink_token_pair(token_controller, remote_domain, remote_token);
        assert!(!state::local_token_exists(remote_domain, remote_token), 0);
        assert!(event::was_event_emitted(&TokenPairUnlinked { local_token, remote_token, remote_domain } ), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50001, location = Self)]
    fun test_unlink_token_pair_not_token_controller(owner: &signer) {
        init_test_token_controller(owner);
        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        state::add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        unlink_token_pair(owner, remote_domain, remote_token);
    }

    #[test(owner = @deployer, token_controller = @0x8e72)]
    #[expected_failure(abort_code = 0x60005, location = Self)]
    fun test_unlink_token_pair_no_link_exist(owner: &signer, token_controller: &signer) {
        init_test_token_controller(owner);
        unlink_token_pair(token_controller, 5, @0xfab);
    }

    // Test Vew Functions

    #[test(owner = @deployer)]
    fun test_view_functions(owner: &signer) {
        init_test_token_controller(owner);
        assert!(token_controller() == state::get_token_controller(), 0);
        assert!(get_num_linked_tokens() == 0, 0);

        let remote_token = @0xfab;
        let remote_domain = 5;
        let local_token = @0xfaa;
        state::add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_linked_token(remote_domain, remote_token) == local_token, 1);
        assert!(get_num_linked_tokens() == 1, 0);
    }
}
