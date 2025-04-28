// Copyright 2024 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[test_only]
module stablecoin::metadata_tests {
    use std::event;
    use std::option::{Self, Option};
    use std::string::{String, utf8};
    use aptos_framework::account::create_signer_for_test;
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object::{Self, ConstructorRef};

    use aptos_extensions::ownable;
    use aptos_extensions::test_utils::assert_eq;
    use stablecoin::fungible_asset_tests::setup_fa;
    use stablecoin::metadata;
    use stablecoin::stablecoin_utils::stablecoin_address;

    const OWNER: address = @0x10;
    const METADATA_UPDATER: address = @0x20;
    const RANDOM_ADDRESS: address = @0x30;
    const RANDOM_ADDRESS_2: address = @0x40;

    const NAME: vector<u8> = b"name";
    const SYMBOL: vector<u8> = b"symbol";
    const DECIMALS: u8 = 6;
    const ICON_URI: vector<u8> = b"icon uri";
    const PROJECT_URI: vector<u8> = b"project uri";

    #[test]
    fun metadata_updater__should_return_metadata_updater_address() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);

        assert_eq(metadata::metadata_updater(), METADATA_UPDATER);
    }

    #[test]
    fun new__should_succeed() {
        let (stablecoin_obj_constructor_ref, _, _) = setup_fa(@stablecoin);
        test_new(
            &stablecoin_obj_constructor_ref,
            METADATA_UPDATER,
        );
    }

    #[test]
    fun update_metadata_updater__should_update_role_to_different_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_metadata_updater(caller, OWNER, RANDOM_ADDRESS);
    }

    #[test]
    fun update_metadata_updater__should_succeed_with_same_address() {
        setup();
        let caller = &create_signer_for_test(OWNER);

        test_update_metadata_updater(caller, OWNER, OWNER);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    fun update_metadata_updater__should_fail_if_caller_is_not_owner() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);

        test_update_metadata_updater(caller, OWNER, RANDOM_ADDRESS);
    }

    #[test]
    fun update_metadata__should_update_the_token_metadata() {
        setup();
        metadata::set_metadata_updater_for_testing(RANDOM_ADDRESS);
        let metadata_updater_signer = &create_signer_for_test(RANDOM_ADDRESS);

        let name = option::some(utf8(b"test_name"));
        let symbol = option::some(utf8(b"symbol"));
        let icon_uri = option::some(utf8(b"test_icon_uri"));
        let project_uri = option::some(utf8(b"test_project_uri"));

        test_update_metadata(
            metadata_updater_signer,
            name,
            symbol,
            icon_uri,
            project_uri
        );
    }

    #[test]
    fun update_metadata__should_not_update_if_metadata_did_not_change() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        let name = option::none();
        let symbol = option::none();
        let icon_uri = option::none();
        let project_uri = option::none();

        test_update_metadata(
            metadata_updater_signer,
            name,
            symbol,
            icon_uri,
            project_uri
        );
    }

    #[test]
    fun update_metadata__should_update_name_if_name_is_changed() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        let name = option::some(utf8(b"test_name"));

        test_update_metadata(
            metadata_updater_signer,
            name,
            option::none(),
            option::none(),
            option::none()
        );
    }

    #[test]
    fun update_metadata__should_update_symbol_if_symbol_is_changed() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        let symbol = option::some(utf8(b"symbol"));

        test_update_metadata(
            metadata_updater_signer,
            option::none(),
            symbol,
            option::none(),
            option::none()
        );
    }

    #[test]
    fun update_metadata__should_update_icon_uri_if_icon_uri_is_changed() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        let icon_uri = option::some(utf8(b"test_icon_uri"));

        test_update_metadata(
            metadata_updater_signer,
            option::none(),
            option::none(),
            icon_uri,
            option::none()
        );
    }

    #[test]
    fun update_metadata__should_update_project_uri_if_project_uri_is_changed() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        let project_uri = option::some(utf8(b"test_project_uri"));

        test_update_metadata(
            metadata_updater_signer,
            option::none(),
            option::none(),
            option::none(),
            project_uri
        );
    }

    #[test, expected_failure(abort_code = stablecoin::metadata::ENOT_METADATA_UPDATER)]
    fun update_metadata__should_fail_if_caller_not_metadata_updater() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let invalid_metadata_updater_signer = &create_signer_for_test(RANDOM_ADDRESS_2);

        let name = option::some(utf8(b"test_name"));
        let symbol = option::some(utf8(b"symbol"));
        let icon_uri = option::some(utf8(b"test_icon_uri"));
        let project_uri = option::some(utf8(b"test_project_uri"));

        test_update_metadata(
            invalid_metadata_updater_signer,
            name,
            symbol,
            icon_uri,
            project_uri
        );
    }

    #[test]
    fun update_metadata__should_be_idempotent() {
        setup();
        metadata::set_metadata_updater_for_testing(METADATA_UPDATER);
        let metadata_updater_signer = &create_signer_for_test(METADATA_UPDATER);

        test_update_metadata(
            metadata_updater_signer,
            option::some(utf8(NAME)),
            option::some(utf8(SYMBOL)),
            option::some(utf8(ICON_URI)),
            option::some(utf8(PROJECT_URI))
        );
        test_update_metadata(
            metadata_updater_signer,
            option::some(utf8(NAME)),
            option::some(utf8(SYMBOL)),
            option::some(utf8(ICON_URI)),
            option::some(utf8(PROJECT_URI))
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_the_metadata() {
        setup();

        let name = option::some(utf8(b"test_name"));
        let symbol = option::some(utf8(b"symbol"));
        let decimals = option::some(8);
        let icon_uri = option::some(utf8(b"test_icon_uri"));
        let project_uri = option::some(utf8(b"test_project_uri"));

        test_mutate_asset_metadata(
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );
    }

    #[test]
    fun mutate_asset_metadata__should_be_idempotent() {
        setup();

        test_mutate_asset_metadata(
            option::some(utf8(NAME)),
            option::some(utf8(SYMBOL)),
            option::some(DECIMALS),
            option::some(utf8(ICON_URI)),
            option::some(utf8(PROJECT_URI))
        );
        test_mutate_asset_metadata(
            option::some(utf8(NAME)),
            option::some(utf8(SYMBOL)),
            option::some(DECIMALS),
            option::some(utf8(ICON_URI)),
            option::some(utf8(PROJECT_URI))
        );
    }

    #[test]
    fun mutate_asset_metadata__should_not_update_if_metadata_did_not_change() {
        setup();

        let name = option::none();
        let symbol = option::none();
        let decimals = option::none();
        let icon_uri = option::none();
        let project_uri = option::none();

        test_mutate_asset_metadata(
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_name_if_name_is_changed() {
        setup();

        let name = option::some(utf8(b"test_name"));

        test_mutate_asset_metadata(
            name,
            option::none(),
            option::none(),
            option::none(),
            option::none()
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_symbol_if_symbol_is_changed() {
        setup();

        let symbol = option::some(utf8(b"symbol"));

        test_mutate_asset_metadata(
            option::none(),
            symbol,
            option::none(),
            option::none(),
            option::none()
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_decimals_if_decimals_is_changed() {
        setup();

        let decimals = option::some(10);

        test_mutate_asset_metadata(
            option::none(),
            option::none(),
            decimals,
            option::none(),
            option::none()
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_icon_uri_if_icon_uri_is_changed() {
        setup();

        let icon_uri = option::some(utf8(b"test_icon_uri"));

        test_mutate_asset_metadata(
            option::none(),
            option::none(),
            option::none(),
            icon_uri,
            option::none()
        );
    }

    #[test]
    fun mutate_asset_metadata__should_update_project_uri_if_project_uri_is_changed() {
        setup();

        let project_uri = option::some(utf8(b"test_project_uri"));

        test_mutate_asset_metadata(
            option::none(),
            option::none(),
            option::none(),
            option::none(),
            project_uri
        );
    }

    // === Helpers ===

    fun setup() {
        let (stablecoin_obj_constructor_ref, _, _) = setup_fa(@stablecoin);
        test_new(&stablecoin_obj_constructor_ref, METADATA_UPDATER);
    }

    fun test_new(
        stablecoin_obj_constructor_ref: &ConstructorRef,
        metadata_updater: address,
    ) {
        let stablecoin_signer = object::generate_signer(stablecoin_obj_constructor_ref);
        let stablecoin_address = object::address_from_constructor_ref(stablecoin_obj_constructor_ref);
        let stablecoin_metadata = object::address_to_object<Metadata>(stablecoin_address);

        ownable::new(&stablecoin_signer, OWNER);
        metadata::new_for_testing(stablecoin_obj_constructor_ref, metadata_updater);

        assert_eq(metadata::mutate_metadata_ref_metadata_for_testing(), stablecoin_metadata);
        assert_eq(metadata::metadata_updater(), metadata_updater);
    }

    fun test_update_metadata(
        metadata_updater: &signer,
        name: Option<String>,
        symbol: Option<String>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) {
        metadata::test_update_metadata(
            metadata_updater,
            name,
            symbol,
            icon_uri,
            project_uri
        );

        verify_asset_metadata_updated(name, symbol, option::none(), icon_uri, project_uri);
    }

    fun test_mutate_asset_metadata(
        name: Option<String>,
        symbol: Option<String>,
        decimals: Option<u8>,
        icon_uri: Option<String>,
        project_uri: Option<String>
    ) {
        metadata::test_mutate_asset_metadata(
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );

        verify_asset_metadata_updated(name, symbol, decimals, icon_uri, project_uri);
    }

    fun verify_asset_metadata_updated(name: Option<String>,
                                      symbol: Option<String>,
                                      decimals: Option<u8>,
                                      icon_uri: Option<String>,
                                      project_uri: Option<String>) {
        let expected_name: String = {
            if (option::is_some(&name)) *option::borrow(&name)
            else utf8(NAME)
        };
        let expected_symbol: String = {
            if (option::is_some(&symbol))*option::borrow(&symbol)
            else utf8(SYMBOL)
        };
        let expected_decimals: u8 = {
            if (option::is_some(&decimals))*option::borrow(&decimals)
            else DECIMALS
        };
        let expected_icon_uri: String = {
            if (option::is_some(&icon_uri)) *option::borrow(&icon_uri)
            else utf8(ICON_URI)
        };
        let expected_project_uri: String = {
            if (option::is_some(&project_uri)) *option::borrow(&project_uri)
            else utf8(PROJECT_URI)
        };

        let stablecoin_address = stablecoin_address();

        assert_eq(fungible_asset::name(object::address_to_object<Metadata>(stablecoin_address)), expected_name);
        assert_eq(fungible_asset::symbol(object::address_to_object<Metadata>(stablecoin_address)), expected_symbol);
        assert_eq(fungible_asset::decimals(object::address_to_object<Metadata>(stablecoin_address)), expected_decimals);
        assert_eq(fungible_asset::icon_uri(object::address_to_object<Metadata>(stablecoin_address)), expected_icon_uri);
        assert_eq(
            fungible_asset::project_uri(object::address_to_object<Metadata>(stablecoin_address)),
            expected_project_uri
        );

        let expected_event = metadata::test_MetadataUpdated_event(
            expected_name,
            expected_symbol,
            expected_decimals,
            expected_icon_uri,
            expected_project_uri
        );
        assert_eq(event::was_event_emitted(&expected_event), true);
    }

    fun test_update_metadata_updater(
        caller: &signer,
        old_metadata_updater: address,
        new_metadata_updater: address
    ) {
        metadata::set_metadata_updater_for_testing(old_metadata_updater);
        let expected_event = metadata::test_MetadataUpdaterChanged_event(
            old_metadata_updater, new_metadata_updater
        );

        metadata::test_update_metadata_updater(
            caller, new_metadata_updater
        );

        assert_eq(event::was_event_emitted(&expected_event), true);
        assert_eq(metadata::metadata_updater(), new_metadata_updater);
    }
}
