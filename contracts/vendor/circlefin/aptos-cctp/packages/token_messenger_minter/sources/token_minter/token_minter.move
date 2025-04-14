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

module token_messenger_minter::token_minter {
    // Built-in Modules
    use std::error;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::fungible_asset;
    use aptos_framework::fungible_asset::{Metadata, FungibleAsset, FungibleStore};
    use aptos_framework::object;
    use aptos_framework::object::Object;
    use aptos_framework::primary_fungible_store;
    use stablecoin::stablecoin::stablecoin_address;
    use aptos_extensions::pausable;
    use token_messenger_minter::token_messenger_minter;
    use stablecoin::treasury;

    // Package Modules
    use token_messenger_minter::state;
    use token_messenger_minter::token_controller;

    // Friend Modules
    friend token_messenger_minter::token_messenger;

    // Errors
    const EMINT_TOKEN_NOT_SUPPORTED: u64 = 1;

    // -----------------------------
    // ----- Friend Functions ------
    // -----------------------------

    /// Mints a specified amount of tokens to a recipient address. The address can be store address or account address.
    /// In the later case, tokens will be minted into the primary store of the account address. If the store does not
    /// exist, it will be created.
    /// Aborts if:
    /// - contract is paused
    /// - the burn_token isn't supported
    /// - the mint_token isn't supported
    /// - stablecoin mint aborts
    public(friend) fun mint(source_domain: u32, burn_token: address, mint_recipient: address, amount: u64): address {
        pausable::assert_not_paused(state::get_object_address());
        let mint_token = token_controller::get_local_token(source_domain, burn_token);
        assert!(mint_token == stablecoin_address(), error::invalid_argument(EMINT_TOKEN_NOT_SUPPORTED));
        let token_messenger_minter_signer = token_messenger_minter::get_signer();
        let asset = treasury::mint(&token_messenger_minter_signer, amount);
        let token_obj: Object<Metadata> = object::address_to_object(mint_token);
        let store = if (fungible_asset::store_exists(mint_recipient)) {
            object::address_to_object<FungibleStore>(mint_recipient)
        } else {
            primary_fungible_store::ensure_primary_store_exists(mint_recipient, token_obj)
        };
        dispatchable_fungible_asset::deposit(store, asset);
        mint_token
    }

    /// Burns the passed in Fungible Asset.
    /// Aborts if:
    /// - contract is paused
    /// - the burn_token isn't supported
    /// - amount exceeds the burn limit
    /// - stablecoin burn aborts
    public(friend) fun burn(burn_token: address, asset: FungibleAsset) {
        pausable::assert_not_paused(state::get_object_address());
        let amount = fungible_asset::amount(&asset);
        token_controller::assert_amount_within_burn_limit(burn_token, amount);
        let token_messenger_minter_signer = token_messenger_minter::get_signer();
        treasury::burn(&token_messenger_minter_signer, asset);
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use std::signer;
    #[test_only]
    use std::string;
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_framework::fungible_asset::{create_test_store};
    #[test_only]
    use aptos_framework::resource_account;
    #[test_only]
    use stablecoin::stablecoin;

    // Test Helpers

    #[test_only]
    const REMOTE_DOMAIN: u32 = 4;

    #[test_only]
    const REMOTE_STABLECOIN_ADDRESS: address = @0xcafe;

    #[test_only]
    const TEST_SEED: vector<u8> = b"test_seed_stablecoin";

    #[test_only]
    public fun get_account_balance(account_address: address): u64 {
        let asset: Object<Metadata> = object::address_to_object(stablecoin::stablecoin_address());
        primary_fungible_store::ensure_primary_store_exists(account_address, asset);
        primary_fungible_store::balance(account_address, asset)
    }

    #[test_only]
    fun deploy_stablecoin_package(): signer {
        account::create_account_for_test(@deployer);

        // deploy an empty package to a new resource account
        resource_account::create_resource_account(
            &create_signer_for_test(@deployer),
            TEST_SEED,
            b"",
        );

        // compute the resource account address
        let resource_account_address = account::create_resource_address(&@deployer, TEST_SEED);

        // verify the resource account address is the same as the configured test package address
        assert!(@stablecoin == resource_account_address, 1);

        // return a resource account signer
        let resource_account_signer = create_signer_for_test(resource_account_address);
        resource_account_signer
    }

    #[test_only]
    fun init_test_stablecoin() {
        let resource_acct_signer = deploy_stablecoin_package();
        stablecoin::test_init_module(&resource_acct_signer);
        stablecoin::test_initialize_v1(
            &create_signer_for_test(@deployer),
            string::utf8(b"name"),
            string::utf8(b"symbol"),
            6,
            string::utf8( b"icon uri"),
            string::utf8(b"project uri")
        );
    }

    #[test_only]
    public(friend) fun init_test_token_minter(owner: &signer) {
        // Initialize Token Messenger minter
        token_messenger_minter::initialize_test_token_messenger_minter(1, signer::address_of(owner));

        // Initialize Stablecoin
        init_test_stablecoin();

        // Add Token Messenger Minter object signer as minter
        let tmm_signer = token_messenger_minter::get_signer();
        treasury::test_configure_controller(owner, signer::address_of(&tmm_signer), signer::address_of(&tmm_signer));
        treasury::test_configure_minter(&tmm_signer, 10_000_000);

        // Link the newly created FA
        token_controller::test_link_token_pair(
            owner,
            stablecoin::stablecoin_address(),
            REMOTE_DOMAIN,
            REMOTE_STABLECOIN_ADDRESS
        );

        // Set Burn Limit
        token_controller::test_set_max_burn_amount_per_message(
            owner,
            stablecoin::stablecoin_address(),
            1_000_000
        );
    }

    #[test_only]
    public(friend) fun withdraw_from_primary_store(owner: &signer, amount: u64, burn_token: address): FungibleAsset {
        let token_obj: Object<Metadata> = object::address_to_object(burn_token);
        let store = primary_fungible_store::ensure_primary_store_exists(signer::address_of(owner), token_obj);
        dispatchable_fungible_asset::withdraw(owner, store, amount)
    }

    // Mint Tests

    #[test(owner = @deployer, user = @0xfaa)]
    fun test_mint_and_burn_success(owner: &signer, user: &signer) {
        init_test_token_minter(owner);
        let to_address = signer::address_of(user);
        let balance = get_account_balance(to_address);
        assert!(balance == 0, 0);

        // Mint 100 tokens to the user
        let expected_mint_token = state::get_local_token(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS);
        let mint_token = mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, to_address, 100);
        assert!(mint_token == expected_mint_token, 0);
        assert!(get_account_balance(to_address) == 100, 0);

        // Burn 50 tokens from the user
        let asset = withdraw_from_primary_store(user, 50, stablecoin::stablecoin_address());
        burn(stablecoin::stablecoin_address(), asset);
        assert!(get_account_balance(signer::address_of(user)) == 50, 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_mint_contract_paused(owner: &signer) {
        init_test_token_minter(owner);
        state::set_paused(owner);
        mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, @0xfaa, 57834);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60005, location = token_controller)]
    fun test_mint_no_local_token(owner: &signer) {
        init_test_token_minter(owner);
        mint(REMOTE_DOMAIN + 1, REMOTE_STABLECOIN_ADDRESS, @0xfaa, 57834);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_mint_unsupported_mint_token(owner: &signer) {
        init_test_token_minter(owner);
        token_controller::test_unlink_token_pair(owner, REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS);
        token_controller::test_link_token_pair(
            owner,
            @0xfac,
            REMOTE_DOMAIN,
            REMOTE_STABLECOIN_ADDRESS
        );

        mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, @0xfaa, 57834);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    fun test_mint_and_burn_secondary_store_success(owner: &signer, user: &signer) {
        init_test_token_minter(owner);
        let to_address = signer::address_of(user);
        let balance = get_account_balance(to_address);
        assert!(balance == 0, 0);

        // Create secondary store
        let metadata: Object<Metadata> = object::address_to_object(stablecoin::stablecoin_address());
        let secondary_store = create_test_store(user, metadata);
        let store_address = object::object_address(&secondary_store);
        assert!(fungible_asset::balance(secondary_store) == 0, 0);

        // Mint 100 tokens to the user's secondary store
        let expected_mint_token = state::get_local_token(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS);
        let mint_token = mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, store_address, 100);
        assert!(mint_token == expected_mint_token, 0);
        assert!(fungible_asset::balance(secondary_store) == 100, 0);

        // Burn 50 tokens from the user's secondary store
        let asset = dispatchable_fungible_asset::withdraw(user, secondary_store, 50);
        burn(stablecoin::stablecoin_address(), asset);
        assert!(fungible_asset::balance(secondary_store) == 50, 0);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_burn_contract_paused(owner: &signer, user: &signer) {
        init_test_token_minter(owner);
        mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, signer::address_of(user), 100);
        state::set_paused(owner);
        let asset = withdraw_from_primary_store(user, 50, stablecoin::stablecoin_address());
        burn(stablecoin::stablecoin_address(), asset);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    #[expected_failure(abort_code = 0x20003, location = token_controller)]
    fun test_burn_invalid_burn_amount(owner: &signer, user: &signer) {
        init_test_token_minter(owner);
        mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, signer::address_of(user), 100);

        // Set limit of 10 tokens
        state::set_max_burn_limit_per_message_for_token(stablecoin::stablecoin_address(), 10);

        // Try to Burn 50 tokens from the user
        let asset = withdraw_from_primary_store(user, 50, stablecoin::stablecoin_address());
        burn(stablecoin::stablecoin_address(), asset);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    #[expected_failure(abort_code = 0x10002, location = token_controller)]
    fun test_burn_invalid_burn_token(owner: &signer, user: &signer) {
        init_test_token_minter(owner);
        mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, signer::address_of(user), 100);

        // Try to Burn 50 tokens from the user
        let asset = withdraw_from_primary_store(user, 50, stablecoin::stablecoin_address());
        burn(REMOTE_STABLECOIN_ADDRESS, asset);
    }
}
