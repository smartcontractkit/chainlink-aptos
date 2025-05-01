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

/// Module for serializing outgoing and deserializing deposit for burn messages
///
/// Message is structured in the following order:
/// --------------------------------------------------
/// Field                 Bytes      Type       Index
/// version               4          uint32     0
/// burnToken             32         bytes32    4
/// mintRecipient         32         bytes32    36
/// amount                32         uint256    68
/// messageSender         32         bytes32    100
/// --------------------------------------------------
module token_messenger_minter::burn_message {
    // Built-in Modules
    use std::error;
    use std::vector;

    // Package Modules
    use message_transmitter::serialize;
    use message_transmitter::deserialize;

    // Friend Modules
    friend token_messenger_minter::token_messenger;

    // Constants
    const VERSION_INDEX: u64 = 0;
    const VERSION_LEN: u64 = 4;
    const BURN_TOKEN_INDEX: u64 = 4;
    const BURN_TOKEN_LEN: u64 = 32;
    const MINT_RECIPIENT_INDEX: u64 = 36;
    const MINT_RECIPIENT_LEN: u64 = 32;
    const AMOUNT_INDEX: u64 = 68;
    const AMOUNT_LEN: u64 = 32;
    const MSG_SENDER_INDEX: u64 = 100;
    const MSG_SENDER_LEN: u64 = 32;

    // 4 byte version + 32 bytes burn_token + 32 bytes mint_recipient + 32 bytes amount + 32 bytes message_sender
    const BURN_MESSAGE_LEN: u64 = 132;

    // Errors
    const EINVALID_MESSAGE_LENGTH: u64 = 1;

    public(friend) fun get_version(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, VERSION_INDEX, VERSION_LEN)
    }

    public(friend) fun get_burn_token(message: &vector<u8>): address {
        deserialize::deserialize_address(message, BURN_TOKEN_INDEX, BURN_TOKEN_LEN)
    }

    public(friend) fun get_mint_recipient(message: &vector<u8>): address {
        deserialize::deserialize_address(message, MINT_RECIPIENT_INDEX, MINT_RECIPIENT_LEN)
    }

    public(friend) fun get_amount(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, AMOUNT_INDEX, AMOUNT_LEN)
    }

    public(friend) fun get_message_sender(message: &vector<u8>): address {
        deserialize::deserialize_address(message, MSG_SENDER_INDEX, MSG_SENDER_LEN)
    }

    public(friend) fun serialize(
        version: u32,
        burn_token: address,
        mint_recipient: address,
        amount: u256,
        message_sender: address
    ): vector<u8> {
        let result = vector::empty<u8>();
        vector::append(&mut result, serialize::serialize_u32(version));
        vector::append(&mut result, serialize::serialize_address(burn_token));
        vector::append(&mut result, serialize::serialize_address(mint_recipient));
        vector::append(&mut result, serialize::serialize_u256(amount));
        vector::append(&mut result, serialize::serialize_address(message_sender));
        result
    }

    public(friend) fun validate_message(message: &vector<u8>) {
        assert!(vector::length<u8>(message) == BURN_MESSAGE_LEN, error::invalid_argument(EINVALID_MESSAGE_LENGTH));
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    // Following test message is based on ->
    // ETH (Source): https://sepolia.etherscan.io/tx/0x151c196be83e2fcbd84204a521ee0a758a5e7335ac7d2c0958ef840fd485dc61
    // AVAX (Destination): https://testnet.snowtrace.io/tx/0xa98d5c33b7571609875f56ae148563411377392c87b9e8cebd483683a0e36413
    // Burn Token: 0x0000000000000000000000001c7D4B196Cb0C7B01d743Fbc6116a902379C7238
    // Mint Recipient: 0x0000000000000000000000001F26414439C8D03FC4B9CA912CEFD5CB508C9605
    // Amount: 1214
    // Sender: 0x0000000000000000000000003b61AbEe91852714E4e99b09a1AF3e9C13893eF1

    #[test_only]
    fun get_raw_test_message(): vector<u8> {
        x"000000000000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c960500000000000000000000000000000000000000000000000000000000000004be0000000000000000000000003b61abee91852714e4e99b09a1af3e9c13893ef1"
    }

    #[test_only] const VERSION: u32 = 0;
    #[test_only] const BURN_TOKEN: address = @0x0000000000000000000000001c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    #[test_only] const MINT_RECIPIENT: address = @0x0000000000000000000000001F26414439C8D03FC4B9CA912CEFD5CB508C9605;
    #[test_only] const AMOUNT: u256 = 1214;
    #[test_only] const MESSAGE_SENDER: address = @0x0000000000000000000000003b61AbEe91852714E4e99b09a1AF3e9C13893eF1;

    #[test]
    fun test_burn_message_serialization() {
        let original_message = get_raw_test_message();
        let serialized_message = serialize(VERSION, BURN_TOKEN, MINT_RECIPIENT, AMOUNT, MESSAGE_SENDER);
        assert!(original_message == serialized_message, 0);
    }

    #[test]
    fun test_get_version() {
        let original_message = get_raw_test_message();
        assert!(get_version(&original_message) == VERSION, 0);
    }

    #[test]
    fun test_get_burn_token() {
        let original_message = get_raw_test_message();
        assert!(get_burn_token(&original_message) == BURN_TOKEN, 0);
    }

    #[test]
    fun test_get_mint_recipient() {
        let original_message = get_raw_test_message();
        assert!(get_mint_recipient(&original_message) == MINT_RECIPIENT, 0);
    }

    #[test]
    fun test_get_amount() {
        let original_message = get_raw_test_message();
        assert!(get_amount(&original_message) == AMOUNT, 0);
    }

    #[test]
    fun test_get_message_sender() {
        let original_message = get_raw_test_message();
        assert!(get_message_sender(&original_message) == MESSAGE_SENDER, 0);
    }

    #[test]
    fun test_validate_message_success() {
        let original_message = get_raw_test_message();
        validate_message(&original_message)
    }

    #[test]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_validate_message_not_sufficient_length() {
        let invalid_message = vector[5, 2, 32, 2, 21, 23];
        validate_message(&invalid_message)
    }
}
