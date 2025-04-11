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

/// Module for serializing outgoing and deserializing incoming messages. Message is dynamically sized.
///
/// Message is structured in the following order:
/// --------------------------------------------------
/// Field                 Bytes      Type       Index
/// version               4          uint32     0
/// sourceDomain          4          uint32     4
/// destinationDomain     4          uint32     8
/// nonce                 8          uint64     12
/// sender                32         bytes32    20
/// recipient             32         bytes32    52
/// destinationCaller     32         bytes32    84
/// messageBody           dynamic    bytes      116
/// --------------------------------------------------
module message_transmitter::message {
  // Built-in Modules
  use std::error;
  use std::vector;

  // Package Modules
  use message_transmitter::serialize;
  use message_transmitter::deserialize;

  // Constants
  const VERSION_INDEX: u64 = 0;
  const VERSION_LEN: u64 = 4;
  const SOURCE_DOMAIN_INDEX: u64 = 4;
  const SOURCE_DOMAIN_LEN: u64 = 4;
  const DESTINATION_DOMAIN_INDEX: u64 = 8;
  const DESTINATION_DOMAIN_LEN: u64 = 4;
  const NONCE_INDEX: u64 = 12;
  const NONCE_LEN: u64 = 8;
  const SENDER_INDEX: u64 = 20;
  const SENDER_LEN: u64 = 32;
  const RECIPIENT_INDEX: u64 = 52;
  const RECIPIENT_LEN: u64 = 32;
  const DESTINATION_CALLER_INDEX: u64 = 84;
  const DESTINATION_CALLER_LEN: u64 = 32;
  const MESSAGE_BODY_INDEX: u64 = 116;

  // Errors
  const EINVALID_FORMAT: u64 = 1;

  public fun get_message_version(message: &vector<u8>): u32 {
    deserialize::deserialize_u32(message, VERSION_INDEX, VERSION_LEN)
  }

  public fun get_src_domain_id(message: &vector<u8>): u32 {
    deserialize::deserialize_u32(message, SOURCE_DOMAIN_INDEX, SOURCE_DOMAIN_LEN)
  }

  public fun get_destination_domain_id(message: &vector<u8>): u32 {
    deserialize::deserialize_u32(message, DESTINATION_DOMAIN_INDEX, DESTINATION_DOMAIN_LEN)
  }

  public fun get_nonce(message: &vector<u8>): u64 {
    deserialize::deserialize_u64(message, NONCE_INDEX, NONCE_LEN)
  }

  public fun get_sender_address(message: &vector<u8>): address {
    deserialize::deserialize_address(message, SENDER_INDEX, SENDER_LEN)
  }

  public fun get_recipient_address(message: &vector<u8>): address {
    deserialize::deserialize_address(message, RECIPIENT_INDEX, RECIPIENT_LEN)
  }

  public fun get_destination_caller(message: &vector<u8>): address {
    deserialize::deserialize_address(message, DESTINATION_CALLER_INDEX, DESTINATION_CALLER_LEN)
  }

  public fun get_message_body(message: &vector<u8>): vector<u8> {
    vector::slice(message, MESSAGE_BODY_INDEX, vector::length<u8>(message))
  }

  public fun serialize(
    version: u32,
    source_domain: u32,
    destination_domain: u32,
    nonce: u64,
    sender: address,
    recipient: address,
    destination_caller: address,
    raw_body: &vector<u8>
  ): vector<u8> {
    let result = vector::empty<u8>();
    vector::append(&mut result, serialize::serialize_u32(version));
    vector::append(&mut result, serialize::serialize_u32(source_domain));
    vector::append(&mut result, serialize::serialize_u32(destination_domain));
    vector::append(&mut result, serialize::serialize_u64(nonce));
    vector::append(&mut result, serialize::serialize_address(sender));
    vector::append(&mut result, serialize::serialize_address(recipient));
    vector::append(&mut result, serialize::serialize_address(destination_caller));
    vector::append(&mut result, *raw_body);
    result
  }

  // Bytes message should contain every all the data required for message transmitter. Message body is optional
  public fun validate_message(message: &vector<u8>) {
    assert!(vector::length<u8>(message) >= MESSAGE_BODY_INDEX, error::invalid_argument(EINVALID_FORMAT));
  }

  // Following test are based on ->
  // ETH (Source): https://sepolia.etherscan.io/tx/0x151c196be83e2fcbd84204a521ee0a758a5e7335ac7d2c0958ef840fd485dc61
  // AVAX (Destination): https://testnet.snowtrace.io/tx/0xa98d5c33b7571609875f56ae148563411377392c87b9e8cebd483683a0e36413
  //
  // Sender: 0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5 (ETH TokenMessenger)
  // Recipient: 0xeb08f243e5d3fcff26a9e38ae5520a669f4019d0 (AVAX TokenMessenger)
  //
  // Custom destination caller: 0x1f26414439C8D03FC4b9CA912CeFd5Cb508C9605 (https://testnet.snowtrace.io/tx/0xa98d5c33b7571609875f56ae148563411377392c87b9e8cebd483683a0e36413)

  #[test]
  fun test_message_serialization() {
    let original_message = get_test_message();
    let serialized_message= serialize(0, 0, 1, 258836, @0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5, @0xeb08f243e5d3fcff26a9e38ae5520a669f4019d0, @0x1f26414439C8D03FC4b9CA912CeFd5Cb508C9605, &x"000000000000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c960500000000000000000000000000000000000000000000000000000000000004be0000000000000000000000003b61abee91852714e4e99b09a1af3e9c13893ef1");
    assert!(original_message == serialized_message, 0);
  }

  #[test]
  fun test_get_message_version() {
    let original_message = get_test_message();
    let expected_message_version = 0;
    assert!(get_message_version(&original_message) == expected_message_version, 0);
  }

  #[test]
  fun test_get_src_domain_id() {
    let original_message = get_test_message();
    let expected_src_domain_id = 0;
    assert!(get_src_domain_id(&original_message) == expected_src_domain_id, 0);
  }

  #[test]
  fun test_get_destination_domain_id() {
    let original_message = get_test_message();
    let expected_destination_domain_id = 1;
    assert!(get_destination_domain_id(&original_message) == expected_destination_domain_id, 0);
  }

  #[test]
  fun test_get_nonce() {
    let original_message = get_test_message();
    let expected_nonce = 258836;
    assert!(get_nonce(&original_message) == expected_nonce, 0);
  }

  #[test]
  fun test_get_sender_address() {
    let original_message = get_test_message();
    let expected_sender_address = @0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5;
    assert!(get_sender_address(&original_message) == expected_sender_address, 0);
  }

  #[test]
  fun test_get_recipient_address() {
    let original_message = get_test_message();
    let expected_recipient_address = @0xeb08f243e5d3fcff26a9e38ae5520a669f4019d0;
    assert!(get_recipient_address(&original_message) == expected_recipient_address, 0);
  }

  #[test]
  fun test_get_destination_caller() {
    let original_message = get_test_message();
    let expected_destination_caller = @0x1f26414439C8D03FC4b9CA912CeFd5Cb508C9605;
    assert!(get_destination_caller(&original_message) == expected_destination_caller, 0);
  }

  #[test]
  fun test_get_message_body() {
    let original_message = get_test_message();
    let expected_message_body = x"000000000000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c960500000000000000000000000000000000000000000000000000000000000004be0000000000000000000000003b61abee91852714e4e99b09a1af3e9c13893ef1";
    assert!(get_message_body(&original_message) == expected_message_body, 0);
  }

  #[test]
  fun test_message_serialization_deserialization_combined() {
    let original_message= get_test_message();
    let serialized_message= serialize(0, 0, 1, 258836, @0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5, @0xeb08f243e5d3fcff26a9e38ae5520a669f4019d0, @0x1f26414439C8D03FC4b9CA912CeFd5Cb508C9605, &vector[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,28,125,75,25,108,176,199,176,29,116,63,188,97,22,169,2,55,156,114,56,0,0,0,0,0,0,0,0,0,0,0,0,31,38,65,68,57,200,208,63,196,185,202,145,44,239,213,203,80,140,150,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,190,0,0,0,0,0,0,0,0,0,0,0,0,59,97,171,238,145,133,39,20,228,233,155,9,161,175,62,156,19,137,62,241]);

    assert!(get_message_version(&original_message) == get_message_version(&serialized_message), 1);
    assert!(get_src_domain_id(&original_message) == get_src_domain_id(&serialized_message), 1);
    assert!(get_destination_domain_id(&original_message) == get_destination_domain_id(&serialized_message), 1);
    assert!(get_nonce(&original_message) == get_nonce(&serialized_message), 1);
    assert!(get_sender_address(&original_message) == get_sender_address(&serialized_message), 1);
    assert!(get_recipient_address(&original_message) == get_recipient_address(&serialized_message), 1);
    assert!(get_destination_caller(&original_message) == get_destination_caller(&serialized_message), 1);
    assert!(get_message_body(&original_message) == get_message_body(&serialized_message), 1);
  }

  #[test]
  fun test_message_is_valid_sufficient_length() {
    let original_message = get_test_message();
    validate_message(&original_message)
  }

  #[test]
  #[expected_failure(abort_code = 0x10001, location = Self)]
  fun test_message_is_valid_not_sufficient_length() {
    let invalid_message = vector[5, 2, 32, 2, 21, 23];
    validate_message(&invalid_message)
  }

  #[test_only]
  fun get_test_message(): vector<u8> {
    x"000000000000000000000001000000000003f3140000000000000000000000009f3b8679c73c2fef8b59b4f3444d4e156fb70aa5000000000000000000000000eb08f243e5d3fcff26a9e38ae5520a669f4019d00000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c9605000000000000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c960500000000000000000000000000000000000000000000000000000000000004be0000000000000000000000003b61abee91852714e4e99b09a1af3e9c13893ef1"
  }
}
