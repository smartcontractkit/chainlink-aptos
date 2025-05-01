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

module token_messenger_minter::token_messenger {
    // Built-in Modules
    use std::error;
    use std::option;
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, FungibleAsset};
    use aptos_framework::object::object_address;
    use aptos_extensions::ownable;
    use message_transmitter::message;
    use token_messenger_minter::token_messenger_minter;

    // Package Modules
    use token_messenger_minter::state;
    use token_messenger_minter::token_minter;
    use token_messenger_minter::burn_message;
    use message_transmitter::message_transmitter::{Self, Receipt};

    // Errors
    const EINVALID_AMOUNT: u64 = 1;
    const EINVALID_MINT_RECIPIENT_ADDRESS: u64 = 2;
    const EINVALID_DESTINATION_CALLER_ADDRESS: u64 = 3;
    const ENOT_ORIGINAL_SENDER: u64 = 4;
    const ETOKEN_MESSENGER_ALREADY_SET: u64 = 5;
    const ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN: u64 = 6;
    const ENOT_TOKEN_MESSENGER: u64 = 7;
    const EINVALID_MESSAGE_BODY_VERSION: u64 = 8;
    const ERECIPIENT_NOT_TOKEN_MESSENGER: u64 = 9;
    const EUNSUPPORTED_DESTINATION_DOAMIN: u64 = 10;
    const EINVALID_TOKEN_MESSENGER_ADDRESS: u64 = 11;

    // Constants
    const MAX_U64: u256 = 18_446_744_073_709_551_615;

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct DepositForBurn has drop, store {
        nonce: u64,
        burn_token: address,
        amount: u64,
        depositor: address,
        mint_recipient: address,
        destination_domain: u32,
        destination_token_messenger: address,
        destination_caller: address
    }

    #[event]
    struct MintAndWithdraw has drop, store {
        mint_recipient: address,
        amount: u64,
        mint_token: address
    }

    #[event]
    struct RemoteTokenMessengerAdded has drop, store {
        domain: u32,
        token_messenger: address
    }

    #[event]
    struct RemoteTokenMessengerRemoved has drop, store {
        domain: u32,
        token_messenger: address
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    public fun message_body_version(): u32 {
        state::get_message_body_version()
    }

    #[view]
    public fun remote_token_messenger(domain: u32): address {
        state::get_remote_token_messenger(domain)
    }

    #[view]
    public fun num_remote_token_messengers(): u64 {
        state::get_num_remote_token_messengers()
    }

    #[view]
    public fun max_burn_amount_per_message(token: address): u64 {
        let (_, max_burn_amount) = state::get_max_burn_limit_per_message_for_token(token);
        max_burn_amount
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    /// Burns the passed in token asset, to be minted on destination domain. Emits `DepositForBurn` event.
    /// Aborts if:
    /// - amount is zero
    /// - destination domain has no TokenMessenger registered
    /// - mint recipient is zero address
    /// - TokenMinter aborts (e.g burn token is not supported)
    /// - MessageTransmitter aborts
    public fun deposit_for_burn(
        caller: &signer,
        asset: FungibleAsset,
        destination_domain: u32,
        mint_recipient: address,
    ): u64 {
        return deposit_for_burn_helper(
            caller,
            asset,
            destination_domain,
            mint_recipient,
            @0x0
        )
    }

    /// Burns the passed in token asset, to be minted on destination domain. The mint on the destination domain must
    /// be called by `destinationCaller`. Emits `DepositForBurn` event.
    /// Aborts if:
    /// - amount is zero
    /// - destination caller is zero address
    /// - destination domain has no TokenMessenger registered
    /// - mint recipient is zero address
    /// - TokenMinter aborts (e.g burn token is not supported)
    /// - MessageTransmitter aborts
    public fun deposit_for_burn_with_caller(
        caller: &signer,
        asset: FungibleAsset,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address
    ): u64 {
        assert!(destination_caller != @0x0, error::invalid_argument(EINVALID_DESTINATION_CALLER_ADDRESS));
        return deposit_for_burn_helper(
            caller,
            asset,
            destination_domain,
            mint_recipient,
            destination_caller
        )
    }

    /// Replaces the given burn message with new new_mint_recipient and/or destination caller.
    /// The replaced message reuses the same nonce making both the existing and new messages valid.
    /// Serializes the new burn message and emits `DepositForBurn` event.
    /// Aborts if:
    /// - caller is not the original sender
    /// - new mint recipient is zero address
    /// - MessageTransmitter aborts
    public fun replace_deposit_for_burn(
        caller: &signer,
        original_message: &vector<u8>,
        original_attestation: &vector<u8>,
        new_destination_caller: &option::Option<address>,
        new_mint_recipient: &option::Option<address>
    ) {
        // Validate message
        message::validate_message(original_message);

        // Validate message body (burn message)
        let burn_msg = message::get_message_body(original_message);
        burn_message::validate_message(&burn_msg);

        // Only original sender can replace the message
        let original_message_sender = burn_message::get_message_sender(&burn_msg);
        assert!(signer::address_of(caller) == original_message_sender, error::permission_denied(ENOT_ORIGINAL_SENDER));

        let burn_token = burn_message::get_burn_token(&burn_msg);
        let amount = burn_message::get_amount(&burn_msg);
        let old_mint_recipient = burn_message::get_mint_recipient(&burn_msg);
        let message_body = option::none<vector<u8>>();

        // Create new message body based on updated mint recipient
        let mint_recipient = option::get_with_default(new_mint_recipient, old_mint_recipient);
        assert!(mint_recipient != @0x0, error::invalid_argument(EINVALID_MINT_RECIPIENT_ADDRESS));
        let new_burn_message = burn_message::serialize(
            message_body_version(),
            burn_token,
            mint_recipient,
            amount,
            original_message_sender
        );
        option::fill(&mut message_body, new_burn_message);

        // Use Token Messenger Minter's signer for calling replace_message
        let token_messenger_minter_signer = token_messenger_minter::get_signer();
        message_transmitter::replace_message(
            &token_messenger_minter_signer,
            original_message,
            original_attestation,
            &message_body,
            new_destination_caller
        );

        let destination_caller = option::get_with_default(
            new_destination_caller,
            message::get_destination_caller(original_message)
        );
        event::emit(DepositForBurn {
            nonce: message::get_nonce(original_message),
            burn_token,
            amount: (amount as u64),
            depositor: original_message_sender,
            mint_recipient,
            destination_domain: message::get_destination_domain_id(original_message),
            destination_token_messenger: message::get_recipient_address(original_message),
            destination_caller
        });
    }

    /// Handles incoming message based on the receipt generated by local message transmitter. For a burn message, mints
    /// the associated token to the requested recipient on the local domain. Call local message transmitter's
    /// `complete_receive` function to destroy receipt. Emits `MintAndWithdraw` event.
    /// Aborts if:
    /// - sender in receipt is not a remote token messenger
    /// - recipient in receipt is not `TokenMessengerMinter` object
    /// - message body is not a valid burn message
    /// - message body version is invalid
    /// - mint function in `TokenMinter` aborts
    public fun handle_receive_message(receipt: Receipt): bool {
        let (sender, recipient, remote_domain, message_body) = message_transmitter::get_receipt_details(&receipt);

        // Validate `recipient` in receipt is the `TokenMessengerMinter` contract
        assert!(recipient == state::get_object_address(), error::invalid_argument(ERECIPIENT_NOT_TOKEN_MESSENGER));

        // Validate `sender` in receipt is a remote token messenger for `remote_domain`
        validate_remote_token_messenger(remote_domain, sender);

        // Verify message body is a valid burn message
        burn_message::validate_message(&message_body);

        // Verify message body version matches the one included in the burn message
        let message_version = burn_message::get_version(&message_body);
        assert!(message_version == message_body_version(), error::invalid_argument(EINVALID_MESSAGE_BODY_VERSION));

        // Mint the given amount of tokens at recipient's address
        let mint_recipient = burn_message::get_mint_recipient(&message_body);
        let burn_token = burn_message::get_burn_token(&message_body);
        let amount = burn_message::get_amount(&message_body);
        assert!(amount <= MAX_U64, error::invalid_argument(EINVALID_AMOUNT));
        let mint_token = token_minter::mint(
            remote_domain,
            burn_token,
            mint_recipient,
            (amount as u64)
        );
        event::emit(MintAndWithdraw {
            mint_recipient,
            amount: (amount as u64),
            mint_token
        });

        // Call message transmitter to emit `MessageReceived` event and destroy receipt
        let token_messenger_minter_signer = token_messenger_minter::get_signer();
        message_transmitter::complete_receive_message(&token_messenger_minter_signer, receipt)
    }

    /// Add TokenMessenger for a remote domain. Emits `RemoteTokenMessengerAdded` event
    /// Aborts if:
    /// - caller is not the owner
    /// - TokenMessenger is zero address
    /// - there is already a TokenMessenger set for domain
    entry fun add_remote_token_messenger(caller: &signer, domain: u32, token_messenger: address) {
        ownable::assert_is_owner(caller, state::get_object_address());
        assert!(token_messenger != @0x0, error::invalid_argument(EINVALID_TOKEN_MESSENGER_ADDRESS));
        assert!(
            !state::is_remote_token_messenger_set_for_domain(domain),
            error::already_exists(ETOKEN_MESSENGER_ALREADY_SET)
        );
        state::add_remote_token_messenger(domain, token_messenger);
        event::emit(RemoteTokenMessengerAdded { domain, token_messenger } );
    }

    /// Remove TokenMessenger for a remote domain. Emits `RemoteTokenMessengerRemoved` event
    /// Aborts if:
    /// - caller is not the owner
    /// - there is no TokenMessenger set for domain
    entry fun remove_remote_token_messenger(caller: &signer, domain: u32) {
        ownable::assert_is_owner(caller, state::get_object_address());
        assert!(
            state::is_remote_token_messenger_set_for_domain(domain),
            error::invalid_argument(ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN)
        );
        let token_messenger = state::remove_remote_token_messenger(domain);
        event::emit(RemoteTokenMessengerRemoved { domain, token_messenger } );
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    fun deposit_for_burn_helper(
        caller: &signer,
        asset: FungibleAsset,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address
    ): u64 {
        let amount = fungible_asset::amount(&asset);
        assert!(amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert!(mint_recipient != @0x0, error::invalid_argument(EINVALID_MINT_RECIPIENT_ADDRESS));

        // Get burn token address from asset metadata
        let metadata = fungible_asset::metadata_from_asset(&asset);
        let burn_token = object_address(&metadata);

        // Verify the destination domain is supported
        assert!(
            state::is_remote_token_messenger_set_for_domain(destination_domain),
            error::invalid_argument(EUNSUPPORTED_DESTINATION_DOAMIN)
        );

        let destination_token_messenger = state::get_remote_token_messenger(destination_domain);
        token_minter::burn(burn_token, asset);

        let serialized_burn_message = burn_message::serialize(
            message_body_version(),
            burn_token,
            mint_recipient,
            (amount as u256),
            signer::address_of(caller)
        );
        let nonce = send_deposit_for_burn(
            destination_domain,
            destination_token_messenger,
            destination_caller,
            &serialized_burn_message
        );
        event::emit(DepositForBurn {
            nonce,
            burn_token,
            amount,
            depositor: signer::address_of(caller),
            mint_recipient,
            destination_domain,
            destination_token_messenger,
            destination_caller
        });
        nonce
    }

    /// Execute `send_message` or `send_message_with_caller` on local MessageTransmitter using
    /// TokenMessengerMinter'signer
    fun send_deposit_for_burn(
        destination_domain: u32,
        destination_token_messenger: address,
        destination_caller: address,
        burn_message: &vector<u8>,
    ): u64 {
        let token_messenger_minter_signer = token_messenger_minter::get_signer();
        if (destination_caller == @0x0) {
            message_transmitter::send_message(
                &token_messenger_minter_signer,
                destination_domain,
                destination_token_messenger,
                burn_message
            )
        } else {
            message_transmitter::send_message_with_caller(
                &token_messenger_minter_signer,
                destination_domain,
                destination_token_messenger,
                destination_caller,
                burn_message
            )
        }
    }

    fun validate_remote_token_messenger(domain: u32, token_messenger: address) {
        assert!(
            state::is_remote_token_messenger_set_for_domain(domain),
            error::invalid_argument(ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN)
        );
        assert!(
            state::get_remote_token_messenger(domain) == token_messenger,
            error::permission_denied(ENOT_TOKEN_MESSENGER)
        );
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use std::hash;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_std::from_bcs;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_extensions::pausable;
    #[test_only]
    use message_transmitter::message_transmitter::MessageSent;
    #[test_only]
    use message_transmitter::state as mt_state;
    #[test_only]
    use stablecoin::stablecoin::stablecoin_address;

    // Test Helpers

    #[test_only]
    const REMOTE_DOMAIN: u32 = 4;
    #[test_only]
    const REMOTE_TOKEN_MESSENGER: address = @0xe786e705b98581cbf28488ce4ae116db0918e1f7eb1877d07bf0995cf67724ef;
    #[test_only]
    const REMOTE_STABLECOIN_ADDRESS: address = @0xcafe;

    #[test_only]
    fun init_test_token_messenger(owner: &signer) {
        // Initialize Message Transmitter
        let mt_deployer = create_signer_for_test(@deployer);
        message_transmitter::initialize_test_message_transmitter(&mt_deployer);

        // Initialize Token Messenger and Minter
        token_minter::init_test_token_minter(owner);
        state::add_remote_token_messenger(REMOTE_DOMAIN, REMOTE_TOKEN_MESSENGER);
        token_minter::mint(REMOTE_DOMAIN, REMOTE_STABLECOIN_ADDRESS, signer::address_of(owner), 1_000_000);
    }

    #[test_only]
    fun get_signer_balance(account: &signer): u64 {
        let account_address = signer::address_of(account);
        token_minter::get_account_balance(account_address)
    }

    #[test_only]
    fun get_valid_deposit_for_burn_message_and_attestation(): (vector<u8>, vector<u8>) {
        let burn_message = burn_message::serialize(
            message_body_version(),
            from_bcs::to_address(hash::sha3_256(b"burn_token")),
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            85720194,
            @deployer
        );
        let original_message = message::serialize(
            0,
            9,
            REMOTE_DOMAIN,
            7384,
            signer::address_of(&token_messenger_minter::get_signer()),
            REMOTE_TOKEN_MESSENGER,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            &burn_message,
        );
        let original_attestation = x"278a9949e5e022256553a072ef00f9e5928235354c79f277539ec56174becea7133ac670f9fc6c38bca534e14aca05e8271112f5d8a9da3375c56d399790d5ea1c";
        (original_message, original_attestation)
    }

    #[test_only]
    fun get_valid_receive_message_and_attestation(): (vector<u8>, vector<u8>) {
        let burn_message = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            8572,
            from_bcs::to_address(hash::sha3_256(b"sender_address"))
        );
        let message_bytes = message::serialize(
            0,
            REMOTE_DOMAIN,
            9,
            7384,
            REMOTE_TOKEN_MESSENGER,
            signer::address_of(&token_messenger_minter::get_signer()),
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            &burn_message,
        );
        let attestation = x"2718d6be14108dfef8f0a24a5dc7a4623dd8139420c0b695baa8178cd2f48d8a70484a52ec5d71c9575685b0319927e669355139c099601d29e3f9363c2d20ba1c";
        (message_bytes, attestation)
    }

    // Deposit For Burn Tests

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_success(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 3482;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let account_balance = get_signer_balance(owner);
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        let nonce = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce,
            burn_token,
            amount,
            depositor: signer::address_of(owner),
            mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: from_bcs::to_address(hash::sha3_256(b"token_messenger")),
            destination_caller: @0x0
        }), 0);
        let expected_account_balance = account_balance - amount;
        assert!(get_signer_balance(owner) == expected_account_balance, 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_deposit_for_burn_invalid_amount(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 0;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_deposit_for_burn_invalid_destination_domain(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 51;
        let destination_domain = 3;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn(owner, asset, destination_domain, mint_recipient,);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_deposit_for_burn_invalid_mint_recipient(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 51;
        let mint_recipient = @0x0;
        let burn_token = stablecoin_address();
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient);
    }

    #[test(owner = @deployer, mt_signer = @message_transmitter)]
    #[expected_failure(abort_code = pausable::ENOT_PAUSER, location = pausable)]
    fun test_deposit_for_burn_message_transmitter_aborts(owner: &signer, mt_signer: &signer) {
        init_test_token_messenger(owner);
        mt_state::set_paused(mt_signer);
        let amount = 51;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient);
    }

    // Deposit For Burn With Caller Tests

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_with_caller_success(owner: &signer) {
        init_test_token_messenger(owner);
        let account_balance = get_signer_balance(owner);
        let amount = 3482;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        let nonce = deposit_for_burn_with_caller(
            owner,
            asset,
            REMOTE_DOMAIN,
            mint_recipient,
            destination_caller
        );
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce,
            burn_token,
            amount,
            depositor: signer::address_of(owner),
            mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: from_bcs::to_address(hash::sha3_256(b"token_messenger")),
            destination_caller
        }), 0);
        let expected_account_balance = account_balance - amount;
        assert!(get_signer_balance(owner) == expected_account_balance, 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_deposit_for_burn_with_caller_invalid_amount(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 0;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn_with_caller(
            owner,
            asset,
            REMOTE_DOMAIN,
            mint_recipient,
            destination_caller
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_deposit_for_burn_with_caller_invalid_destination_domain(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 12;
        let destination_domain = 3;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn_with_caller(
            owner,
            asset,
            destination_domain,
            mint_recipient,
            destination_caller
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_deposit_for_burn_with_caller_invalid_mint_recipient(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 12;
        let mint_recipient = @0x0;
        let burn_token = stablecoin_address();
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn_with_caller(
            owner,
            asset,
            REMOTE_DOMAIN,
            mint_recipient,
            destination_caller
        );
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_deposit_for_burn_with_caller_invalid_destination_caller(owner: &signer) {
        init_test_token_messenger(owner);
        let amount = 12;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let destination_caller = @0x0;
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn_with_caller(
            owner,
            asset,
            REMOTE_DOMAIN,
            mint_recipient,
            destination_caller
        );
    }

    #[test(owner = @deployer, mt_signer = @message_transmitter)]
    #[expected_failure(abort_code = pausable::ENOT_PAUSER, location = pausable)]
    fun test_deposit_for_burn_with_caller_message_transmitter_aborts(owner: &signer, mt_signer: &signer) {
        init_test_token_messenger(owner);
        mt_state::set_paused(mt_signer);
        let amount = 12;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = stablecoin_address();
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        let asset = token_minter::withdraw_from_primary_store(owner, amount, burn_token);
        deposit_for_burn_with_caller(
            owner,
            asset,
            REMOTE_DOMAIN,
            mint_recipient,
            destination_caller
        );
    }

   // Replace Deposit For Burn Tests

   #[test(owner = @deployer)]
   fun test_replace_deposit_for_burn_new_destination_caller(owner: &signer) {
       init_test_token_messenger(owner);
       let original_account_balance = get_signer_balance(owner);
       let new_destination_caller = @0xfab;
       let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
       replace_deposit_for_burn(
           owner,
           &original_message,
           &original_attestation,
           &option::some(new_destination_caller),
           &option::none()
       );

       let burn_msg = message::get_message_body(&original_message);
       assert!(event::was_event_emitted(&DepositForBurn {
           nonce: message::get_nonce(&original_message),
           burn_token: burn_message::get_burn_token(&burn_msg),
           amount: (burn_message::get_amount(&burn_msg) as u64),
           depositor: signer::address_of(owner),
           mint_recipient: burn_message::get_mint_recipient(&burn_msg),
           destination_domain: REMOTE_DOMAIN,
           destination_token_messenger: REMOTE_TOKEN_MESSENGER,
           destination_caller: new_destination_caller
       }), 0);
       let message_sent_event = vector::borrow(&event::emitted_events<MessageSent>(), 0);
       let message = message_transmitter::get_message_from_event(message_sent_event);
       let new_burn_message = message::get_message_body(&message);
       assert!(burn_message::get_version(&new_burn_message) == message_body_version(), 0);
       assert!(get_signer_balance(owner) == original_account_balance, 0);
   }

    #[test(owner = @deployer)]
    fun test_replace_deposit_for_burn_new_mint_recipient(owner: &signer) {
        init_test_token_messenger(owner);
        let new_mint_recipient = @0xfab;
        let original_account_balance = get_signer_balance(owner);
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::some(new_mint_recipient),
        );

        let burn_msg = message::get_message_body(&original_message);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce: message::get_nonce(&original_message),
            burn_token: burn_message::get_burn_token(&burn_msg),
            amount: (burn_message::get_amount(&burn_msg) as u64),
            depositor: signer::address_of(owner),
            mint_recipient: new_mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller: message::get_destination_caller(&original_message)
        }), 0);
        let message_sent_event = vector::borrow(&event::emitted_events<MessageSent>(), 0);
        let message = message_transmitter::get_message_from_event(message_sent_event);
        let new_burn_message = message::get_message_body(&message);
        assert!(burn_message::get_version(&new_burn_message) == message_body_version(), 0);
        assert!(get_signer_balance(owner) == original_account_balance, 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_deposit_for_burn_new_destination_caller_version_bump(owner: &signer) {
        init_test_token_messenger(owner);
        let original_account_balance = get_signer_balance(owner);
        let new_destination_caller = @0xfab;
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        state::set_message_body_version(2);
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::some(new_destination_caller),
            &option::none()
        );

        let burn_msg = message::get_message_body(&original_message);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce: message::get_nonce(&original_message),
            burn_token: burn_message::get_burn_token(&burn_msg),
            amount: (burn_message::get_amount(&burn_msg) as u64),
            depositor: signer::address_of(owner),
            mint_recipient: burn_message::get_mint_recipient(&burn_msg),
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller: new_destination_caller
        }), 0);

        let message_sent_event = vector::borrow(&event::emitted_events<MessageSent>(), 0);
        let message = message_transmitter::get_message_from_event(message_sent_event);
        let new_burn_message = message::get_message_body(&message);
        assert!(burn_message::get_version(&new_burn_message) == message_body_version(), 0);
        assert!(get_signer_balance(owner) == original_account_balance, 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_deposit_for_burn_new_mint_recipient_version_bump(owner: &signer) {
        init_test_token_messenger(owner);
        let new_mint_recipient = @0xfab;
        let original_account_balance = get_signer_balance(owner);
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        state::set_message_body_version(2);
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::some(new_mint_recipient),
        );

        let burn_msg = message::get_message_body(&original_message);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce: message::get_nonce(&original_message),
            burn_token: burn_message::get_burn_token(&burn_msg),
            amount: (burn_message::get_amount(&burn_msg) as u64),
            depositor: signer::address_of(owner),
            mint_recipient: new_mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller: message::get_destination_caller(&original_message)
        }), 0);
        let message_sent_event = vector::borrow(&event::emitted_events<MessageSent>(), 0);
        let message = message_transmitter::get_message_from_event(message_sent_event);
        let new_burn_message = message::get_message_body(&message);
        assert!(burn_message::get_version(&new_burn_message) == message_body_version(), 0);
        assert!(get_signer_balance(owner) == original_account_balance, 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_deposit_for_burn_new_mint_recipient_and_destination_caller(owner: &signer) {
        init_test_token_messenger(owner);
        let original_account_balance = get_signer_balance(owner);
        let new_destination_caller = @0xfab;
        let new_mint_recipient = @0xfac;
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::some(new_destination_caller),
            &option::some(new_mint_recipient),
        );

        let burn_msg = message::get_message_body(&original_message);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce: message::get_nonce(&original_message),
            burn_token: burn_message::get_burn_token(&burn_msg),
            amount: (burn_message::get_amount(&burn_msg) as u64),
            depositor: signer::address_of(owner),
            mint_recipient: new_mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller: new_destination_caller
        }), 0);
        assert!(get_signer_balance(owner) == original_account_balance, 0);
    }

    #[test(owner = @deployer)]
    fun test_replace_deposit_for_burn_no_change(owner: &signer) {
        init_test_token_messenger(owner);
        let original_account_balance = get_signer_balance(owner);
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::none(),
        );

        let burn_msg = message::get_message_body(&original_message);
        assert!(event::was_event_emitted(&DepositForBurn {
            nonce: message::get_nonce(&original_message),
            burn_token: burn_message::get_burn_token(&burn_msg),
            amount: (burn_message::get_amount(&burn_msg) as u64),
            depositor: signer::address_of(owner),
            mint_recipient: burn_message::get_mint_recipient(&burn_msg),
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller: message::get_destination_caller(&original_message)
        }), 0);
        assert!(get_signer_balance(owner) == original_account_balance, 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_replace_deposit_for_burn_invalid_mint_recipient(owner: &signer) {
        init_test_token_messenger(owner);
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        replace_deposit_for_burn(
            owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::some(@0x0),
        );
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = 0x50004, location = Self)]
    fun test_replace_deposit_for_burn_not_the_original_sender(owner: &signer, not_owner: &signer) {
        init_test_token_messenger(owner);
        let (original_message, original_attestation) = get_valid_deposit_for_burn_message_and_attestation();
        replace_deposit_for_burn(
            not_owner,
            &original_message,
            &original_attestation,
            &option::none(),
            &option::none(),
        );
    }

    // Add TokenMessenger Tests

    #[test(owner = @deployer)]
    fun test_add_remote_token_messenger(owner: &signer) {
        init_test_token_messenger(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        add_remote_token_messenger(owner, domain, token_messenger);
        assert!(event::was_event_emitted(&RemoteTokenMessengerAdded { domain, token_messenger }), 0);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_add_remote_token_messenger_not_owner(owner: &signer, not_owner: &signer) {
        init_test_token_messenger(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        add_remote_token_messenger(not_owner, domain, token_messenger);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80005, location = Self)]
    fun test_add_remote_token_messenger_already_set(owner: &signer) {
        init_test_token_messenger(owner);
        assert!(state::is_remote_token_messenger_set_for_domain(REMOTE_DOMAIN), 0);
        add_remote_token_messenger(owner, REMOTE_DOMAIN, REMOTE_TOKEN_MESSENGER);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    fun test_add_remote_token_messenger_zero_address(owner: &signer) {
        init_test_token_messenger(owner);
        add_remote_token_messenger(owner, 7, @0x0);
    }

    // Remove TokenMessenger Tests

    #[test(owner = @deployer)]
    fun test_remove_remote_token_messenger(owner: &signer) {
        init_test_token_messenger(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        state::add_remote_token_messenger(domain, token_messenger);
        remove_remote_token_messenger(owner, domain);
        assert!(event::was_event_emitted(&RemoteTokenMessengerRemoved{ domain, token_messenger }), 0);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_remove_remote_token_messenger_not_owner(owner: &signer, not_owner: &signer) {
        init_test_token_messenger(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        state::add_remote_token_messenger(domain, token_messenger);
        remove_remote_token_messenger(not_owner, domain);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_remove_remote_token_messenger_none_set(owner: &signer) {
        init_test_token_messenger(owner);
        let remote_domain = 15;
        assert!(!state::is_remote_token_messenger_set_for_domain(remote_domain), 0);
        remove_remote_token_messenger(owner, remote_domain);
    }

    // Handle Receive Message Tests

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    fun test_handle_receive_message_success(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let account_balance = token_minter::get_account_balance(mint_recipient);
        let amount = 8572;
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        assert!(handle_receive_message(receipt), 0);
        assert!(event::was_event_emitted(&MintAndWithdraw {
            mint_token: stablecoin_address(),
            mint_recipient,
            amount
        }), 0);
        let expected_account_balance = account_balance + amount;
        assert!(token_minter::get_account_balance(mint_recipient) == expected_account_balance, 0);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    fun test_handle_receive_message_invalid_version(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        state::set_message_body_version(2);
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x10001, location = burn_message)]
    fun test_handle_receive_message_invalid_burn_message(owner: &signer, destination_caller: &signer
    ) {
        init_test_token_messenger(owner);
        let message = message::serialize(
            0,
            REMOTE_DOMAIN,
            9,
            7384,
            REMOTE_TOKEN_MESSENGER,
            signer::address_of(&token_messenger_minter::get_signer()),
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            &b"Invalid Message",
        );
        let attestation = x"a17e6548171cc8d014ec1d3953e3b90ab17c47ae029de4fdf32bbfc68d7bdc5003a8e3fface57934d54e6f907a3b5fd5825da1ffec1016972d5a508f0738beda1c";
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    fun test_handle_receive_message_invalid_message_recipient(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let burn_message = burn_message::serialize(
            message_body_version(),
            from_bcs::to_address(hash::sha3_256(b"burn_token")),
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            85720194,
            from_bcs::to_address(hash::sha3_256(b"sender_address"))
        );
        let message = message::serialize(
            0,
            REMOTE_DOMAIN,
            9,
            7384,
            REMOTE_TOKEN_MESSENGER,
            from_bcs::to_address(hash::sha3_256(b"invalid_message_recipient")),
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            &burn_message,
        );
        let attestation = x"94e9bc648d05934214c52f5e8a43f44ab5bf74e4e19666ff00c7acb8d21b4bcc0f346dc91e953cf0bd09f89f77380480c01e4ce591b77ee0661cb3b1fa7f17361b";
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_handle_receive_message_no_remote_token_messenger(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        state::remove_remote_token_messenger(REMOTE_DOMAIN);
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_handle_receive_message_invalid_remote_token_messenger(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        state::remove_remote_token_messenger(REMOTE_DOMAIN);
        state::add_remote_token_messenger(REMOTE_DOMAIN, @0xfaa);
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    #[test(
        owner = @deployer,
        destination_caller = @0x8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f71
    )]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_handle_receive_invalid_amount(owner: &signer, destination_caller: &signer) {
        init_test_token_messenger(owner);
        let message = x"0000000000000004000000090000000000001cd8e786e705b98581cbf28488ce4ae116db0918e1f7eb1877d07bf0995cf67724ef0b27dce48d6e8682b00e1a51d6e19728194770ff0a5b5549aa5c417a6f0aed0f8a4edb71919e22728ffe9a925df33202328aca8d6e13be2c5f4e02b4370c8f7100000001000000000000000000000000000000000000000000000000000000000000cafee6344c4f54e1e11cdfa1ee14a721177c3d9289d9989aa439b8e0141c486e161b00000000000000000000000000000000000000000000000100000000000000003ec52aadabf6254eaa382b3dec7256b360e804114611c12c551d99daec50d1c1";
        let attestation = x"543ac51d16dd8ccc8ba2cd849be3bc0ee63dfe490d01ad35a33017d904fbb3257a43b5f8699e817efc946fd99b4445a4b0864b0f763c152c57ac8600dcb388481b";
        let receipt = message_transmitter::receive_message(destination_caller, &message, &attestation);
        handle_receive_message(receipt);
    }

    // View Function Test

    #[test(owner = @deployer)]
    fun test_view_message_body_version(owner: &signer) {
        init_test_token_messenger(owner);
        assert!(message_body_version() == state::get_message_body_version(), 0);
    }

    #[test(owner = @deployer)]
    fun test_view_remote_token_messenger(owner: &signer) {
        init_test_token_messenger(owner);
        assert!(state::get_remote_token_messenger(REMOTE_DOMAIN) == remote_token_messenger(REMOTE_DOMAIN), 0);
    }

    #[test(owner = @deployer)]
    fun test_view_num_remote_token_messengers(owner: &signer) {
        init_test_token_messenger(owner);
        assert!(state::get_num_remote_token_messengers() == num_remote_token_messengers(), 0);
    }

    #[test(owner = @deployer)]
    fun test_view_max_burn_amount_per_message(owner: &signer) {
        init_test_token_messenger(owner);
        let (_, max_burn_amount) = state::get_max_burn_limit_per_message_for_token(@stablecoin);
        assert!(max_burn_amount_per_message(@stablecoin) == max_burn_amount, 0);
    }
}
