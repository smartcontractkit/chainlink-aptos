// Code generated - DO NOT EDIT.
// This file is a generated registry and any manual changes will be lost.

package bind

// FunctionRegistry contains all function information organized by package -> module -> function name
var FunctionRegistry = map[string]map[string]map[string]FunctionInfo{
    "burn_mint_token_pool": {
        "burn_mint_token_pool": {
            "accept_ownership": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "add_remote_pool": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "add_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "apply_allowlist_updates": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "apply_allowlist_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "removes",
                        Type: "vector<address>",
                    },
                    {
                        Name: "adds",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_chain_updates": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "apply_chain_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors_to_remove",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_chain_selectors_to_add",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_pool_addresses_to_add",
                        Type: "vector<vector<vector<u8>>>",
                    },
                    {
                        Name: "remote_token_addresses_to_add",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "assert_can_initialize": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "assert_can_initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller_address",
                        Type: "address",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "remove_remote_pool": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "remove_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_chain_rate_limiter_config": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "set_chain_rate_limiter_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "outbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_rate",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "inbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_rate",
                        Type: "u64",
                    },
                },
            },
            "set_chain_rate_limiter_configs": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "set_chain_rate_limiter_configs",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "outbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_rates",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "inbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_rates",
                        Type: "vector<u64>",
                    },
                },
            },
            "store_address": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "store_address",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "burn_mint_token_pool",
                Module:     "burn_mint_token_pool",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
    "ccip": {
        "auth": {
            "accept_ownership": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "apply_allowed_offramp_updates": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "apply_allowed_offramp_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "offramps_to_remove",
                        Type: "vector<address>",
                    },
                    {
                        Name: "offramps_to_add",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_allowed_onramp_updates": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "apply_allowed_onramp_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "onramps_to_remove",
                        Type: "vector<address>",
                    },
                    {
                        Name: "onramps_to_add",
                        Type: "vector<address>",
                    },
                },
            },
            "assert_is_allowed_offramp": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "assert_is_allowed_offramp",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller",
                        Type: "address",
                    },
                },
            },
            "assert_is_allowed_onramp": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "assert_is_allowed_onramp",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller",
                        Type: "address",
                    },
                },
            },
            "assert_only_owner": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "assert_only_owner",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller",
                        Type: "address",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "ccip",
                Module:     "auth",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
        "fee_quoter": {
            "apply_dest_chain_config_updates": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "apply_dest_chain_config_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "max_number_of_tokens_per_msg",
                        Type: "u16",
                    },
                    {
                        Name: "max_data_bytes",
                        Type: "u32",
                    },
                    {
                        Name: "max_per_msg_gas_limit",
                        Type: "u32",
                    },
                    {
                        Name: "dest_gas_overhead",
                        Type: "u32",
                    },
                    {
                        Name: "dest_gas_per_payload_byte_base",
                        Type: "u8",
                    },
                    {
                        Name: "dest_gas_per_payload_byte_high",
                        Type: "u8",
                    },
                    {
                        Name: "dest_gas_per_payload_byte_threshold",
                        Type: "u16",
                    },
                    {
                        Name: "dest_data_availability_overhead_gas",
                        Type: "u32",
                    },
                    {
                        Name: "dest_gas_per_data_availability_byte",
                        Type: "u16",
                    },
                    {
                        Name: "dest_data_availability_multiplier_bps",
                        Type: "u16",
                    },
                    {
                        Name: "chain_family_selector",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "enforce_out_of_order",
                        Type: "bool",
                    },
                    {
                        Name: "default_token_fee_usd_cents",
                        Type: "u16",
                    },
                    {
                        Name: "default_token_dest_gas_overhead",
                        Type: "u32",
                    },
                    {
                        Name: "default_tx_gas_limit",
                        Type: "u32",
                    },
                    {
                        Name: "gas_multiplier_wei_per_eth",
                        Type: "u64",
                    },
                    {
                        Name: "gas_price_staleness_threshold",
                        Type: "u32",
                    },
                    {
                        Name: "network_fee_usd_cents",
                        Type: "u32",
                    },
                },
            },
            "apply_fee_token_updates": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "apply_fee_token_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "fee_tokens_to_remove",
                        Type: "vector<address>",
                    },
                    {
                        Name: "fee_tokens_to_add",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_premium_multiplier_wei_per_eth_updates": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "apply_premium_multiplier_wei_per_eth_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "tokens",
                        Type: "vector<address>",
                    },
                    {
                        Name: "premium_multiplier_wei_per_eth",
                        Type: "vector<u64>",
                    },
                },
            },
            "apply_token_transfer_fee_config_updates": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "apply_token_transfer_fee_config_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "add_tokens",
                        Type: "vector<address>",
                    },
                    {
                        Name: "add_min_fee_usd_cents",
                        Type: "vector<u32>",
                    },
                    {
                        Name: "add_max_fee_usd_cents",
                        Type: "vector<u32>",
                    },
                    {
                        Name: "add_deci_bps",
                        Type: "vector<u16>",
                    },
                    {
                        Name: "add_dest_gas_overhead",
                        Type: "vector<u32>",
                    },
                    {
                        Name: "add_dest_bytes_overhead",
                        Type: "vector<u32>",
                    },
                    {
                        Name: "add_is_enabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "remove_tokens",
                        Type: "vector<address>",
                    },
                },
            },
            "calc_usd_value_from_token_amount": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "calc_usd_value_from_token_amount",
                Parameters: []FunctionParameter{
                    {
                        Name: "token_amount",
                        Type: "u64",
                    },
                    {
                        Name: "token_price",
                        Type: "u256",
                    },
                },
            },
            "decode_generic_extra_args_v2": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "decode_generic_extra_args_v2",
                Parameters: []FunctionParameter{
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "decode_svm_extra_args": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "decode_svm_extra_args",
                Parameters: []FunctionParameter{
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "decode_svm_extra_args_v1": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "decode_svm_extra_args_v1",
                Parameters: []FunctionParameter{
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "dest_chain_config_values": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "dest_chain_config_values",
                Parameters: []FunctionParameter{
                    {
                        Name: "config",
                        Type: "DestChainConfig",
                    },
                },
            },
            "initialize": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "max_fee_juels_per_msg",
                        Type: "u256",
                    },
                    {
                        Name: "link_token",
                        Type: "address",
                    },
                    {
                        Name: "token_price_staleness_threshold",
                        Type: "u64",
                    },
                    {
                        Name: "fee_tokens",
                        Type: "vector<address>",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "token_transfer_fee_config_values": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "token_transfer_fee_config_values",
                Parameters: []FunctionParameter{
                    {
                        Name: "config",
                        Type: "TokenTransferFeeConfig",
                    },
                },
            },
            "update_prices": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "update_prices",
                Parameters: []FunctionParameter{
                    {
                        Name: "source_tokens",
                        Type: "vector<address>",
                    },
                    {
                        Name: "source_usd_per_token",
                        Type: "vector<u256>",
                    },
                    {
                        Name: "gas_dest_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "gas_usd_per_unit_gas",
                        Type: "vector<u256>",
                    },
                },
            },
            "validate_32byte_address": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "validate_32byte_address",
                Parameters: []FunctionParameter{
                    {
                        Name: "encoded_address",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "min_value",
                        Type: "u256",
                    },
                },
            },
            "validate_dest_family_address": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "validate_dest_family_address",
                Parameters: []FunctionParameter{
                    {
                        Name: "chain_family_selector",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "encoded_address",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "gas_limit",
                        Type: "u256",
                    },
                },
            },
            "validate_evm_address": {
                Package:    "ccip",
                Module:     "fee_quoter",
                Name:       "validate_evm_address",
                Parameters: []FunctionParameter{
                    {
                        Name: "encoded_address",
                        Type: "vector<u8>",
                    },
                },
            },
        },
        "nonce_manager": {
            "get_incremented_outbound_nonce": {
                Package:    "ccip",
                Module:     "nonce_manager",
                Name:       "get_incremented_outbound_nonce",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "sender",
                        Type: "address",
                    },
                },
            },
        },
        "receiver_registry": {
            "finish_receive": {
                Package:    "ccip",
                Module:     "receiver_registry",
                Name:       "finish_receive",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver_address",
                        Type: "address",
                    },
                },
            },
        },
        "rmn_remote": {
            "curse": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "curse",
                Parameters: []FunctionParameter{
                    {
                        Name: "subject",
                        Type: "vector<u8>",
                    },
                },
            },
            "curse_multiple": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "curse_multiple",
                Parameters: []FunctionParameter{
                    {
                        Name: "subjects",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "initialize": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_chain_selector",
                        Type: "u64",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "set_config": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "set_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "rmn_home_contract_config_digest",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signer_onchain_public_keys",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "node_indexes",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "f_sign",
                        Type: "u64",
                    },
                },
            },
            "uncurse": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "uncurse",
                Parameters: []FunctionParameter{
                    {
                        Name: "subject",
                        Type: "vector<u8>",
                    },
                },
            },
            "uncurse_multiple": {
                Package:    "ccip",
                Module:     "rmn_remote",
                Name:       "uncurse_multiple",
                Parameters: []FunctionParameter{
                    {
                        Name: "subjects",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
        },
        "token_admin_registry": {
            "accept_admin_role": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "accept_admin_role",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                },
            },
            "finish_lock_or_burn": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "finish_lock_or_burn",
                Parameters: []FunctionParameter{
                    {
                        Name: "token_pool_address",
                        Type: "address",
                    },
                },
            },
            "finish_release_or_mint": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "finish_release_or_mint",
                Parameters: []FunctionParameter{
                    {
                        Name: "token_pool_address",
                        Type: "address",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "propose_administrator": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "propose_administrator",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                    {
                        Name: "administrator",
                        Type: "address",
                    },
                },
            },
            "set_pool": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "set_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                    {
                        Name: "token_pool_address",
                        Type: "address",
                    },
                },
            },
            "start_lock_or_burn": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "start_lock_or_burn",
                Parameters: []FunctionParameter{
                    {
                        Name: "token_pool_address",
                        Type: "address",
                    },
                    {
                        Name: "sender",
                        Type: "address",
                    },
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "receiver",
                        Type: "vector<u8>",
                    },
                },
            },
            "transfer_admin_role": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "transfer_admin_role",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                    {
                        Name: "new_admin",
                        Type: "address",
                    },
                },
            },
            "unregister_pool": {
                Package:    "ccip",
                Module:     "token_admin_registry",
                Name:       "unregister_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                },
            },
        },
    },
    "ccip_dummy_receiver": {
        "dummy_receiver": {
            "ccip_receive": {
                Package:    "ccip_dummy_receiver",
                Module:     "dummy_receiver",
                Name:       "ccip_receive",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
        },
    },
    "ccip_offramp": {
        "ocr3_base": {
            "deserialize_sequence_bytes": {
                Package:    "ccip_offramp",
                Module:     "ocr3_base",
                Name:       "deserialize_sequence_bytes",
                Parameters: []FunctionParameter{
                    {
                        Name: "sequence_bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "hash_report": {
                Package:    "ccip_offramp",
                Module:     "ocr3_base",
                Name:       "hash_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "config_digest",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "sequence_bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "new": {
                Package:    "ccip_offramp",
                Module:     "ocr3_base",
                Name:       "new",
                Parameters: []FunctionParameter{
                },
            },
            "ocr_plugin_type_commit": {
                Package:    "ccip_offramp",
                Module:     "ocr3_base",
                Name:       "ocr_plugin_type_commit",
                Parameters: []FunctionParameter{
                },
            },
            "ocr_plugin_type_execution": {
                Package:    "ccip_offramp",
                Module:     "ocr3_base",
                Name:       "ocr_plugin_type_execution",
                Parameters: []FunctionParameter{
                },
            },
        },
        "offramp": {
            "accept_ownership": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "apply_source_chain_config_updates": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "apply_source_chain_config_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "source_chains_selector",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "source_chains_is_enabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "source_chains_is_rmn_verification_disabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "source_chains_on_ramp",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "calculate_metadata_hash": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "calculate_metadata_hash",
                Parameters: []FunctionParameter{
                    {
                        Name: "source_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "on_ramp",
                        Type: "vector<u8>",
                    },
                },
            },
            "commit": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "commit",
                Parameters: []FunctionParameter{
                    {
                        Name: "report_context",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "create_dynamic_config": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "create_dynamic_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "permissionless_execution_threshold_seconds",
                        Type: "u32",
                    },
                },
            },
            "create_static_config": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "create_static_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "chain_selector",
                        Type: "u64",
                    },
                },
            },
            "deserialize_commit_report": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "deserialize_commit_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "report_bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "deserialize_execution_report": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "deserialize_execution_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "report_bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "execute": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "execute",
                Parameters: []FunctionParameter{
                    {
                        Name: "report_context",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "report",
                        Type: "vector<u8>",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "get_state_address_internal": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "get_state_address_internal",
                Parameters: []FunctionParameter{
                },
            },
            "initialize": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "permissionless_execution_threshold_seconds",
                        Type: "u32",
                    },
                    {
                        Name: "source_chains_selector",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "source_chains_is_enabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "source_chains_is_rmn_verification_disabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "source_chains_on_ramp",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "manually_execute": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "manually_execute",
                Parameters: []FunctionParameter{
                    {
                        Name: "report_bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "set_dynamic_config": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "set_dynamic_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "permissionless_execution_threshold_seconds",
                        Type: "u32",
                    },
                },
            },
            "set_ocr3_config": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "set_ocr3_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "config_digest",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "ocr_plugin_type",
                        Type: "u8",
                    },
                    {
                        Name: "big_f",
                        Type: "u8",
                    },
                    {
                        Name: "is_signature_verification_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "signers",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "transmitters",
                        Type: "vector<address>",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "ccip_offramp",
                Module:     "offramp",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
    "ccip_onramp": {
        "onramp": {
            "accept_ownership": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "apply_allowlist_updates": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "apply_allowlist_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "dest_chain_allowlist_enabled",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "dest_chain_add_allowed_senders",
                        Type: "vector<vector<address>>",
                    },
                    {
                        Name: "dest_chain_remove_allowed_senders",
                        Type: "vector<vector<address>>",
                    },
                },
            },
            "apply_dest_chain_config_updates": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "apply_dest_chain_config_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "dest_chain_routers",
                        Type: "vector<address>",
                    },
                    {
                        Name: "dest_chain_allowlist_enabled",
                        Type: "vector<bool>",
                    },
                },
            },
            "calculate_metadata_hash": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "calculate_metadata_hash",
                Parameters: []FunctionParameter{
                    {
                        Name: "source_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                },
            },
            "ccip_send": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "ccip_send",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "receiver",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "token_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "token_amounts",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "token_store_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "fee_token",
                        Type: "address",
                    },
                    {
                        Name: "fee_token_store",
                        Type: "address",
                    },
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "get_fee_internal": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "get_fee_internal",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "receiver",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "token_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "token_amounts",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "token_store_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "fee_token",
                        Type: "address",
                    },
                    {
                        Name: "fee_token_store",
                        Type: "address",
                    },
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "get_state_address_internal": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "get_state_address_internal",
                Parameters: []FunctionParameter{
                },
            },
            "initialize": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "fee_aggregator",
                        Type: "address",
                    },
                    {
                        Name: "allowlist_admin",
                        Type: "address",
                    },
                    {
                        Name: "dest_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "dest_chain_routers",
                        Type: "vector<address>",
                    },
                    {
                        Name: "dest_chain_allowlist_enabled",
                        Type: "vector<bool>",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "resolve_fungible_asset": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "resolve_fungible_asset",
                Parameters: []FunctionParameter{
                    {
                        Name: "token",
                        Type: "address",
                    },
                },
            },
            "resolve_fungible_store": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "resolve_fungible_store",
                Parameters: []FunctionParameter{
                    {
                        Name: "owner",
                        Type: "address",
                    },
                    {
                        Name: "token",
                        Type: "address",
                    },
                    {
                        Name: "store_address",
                        Type: "address",
                    },
                },
            },
            "set_dynamic_config": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "set_dynamic_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "fee_aggregator",
                        Type: "address",
                    },
                    {
                        Name: "allowlist_admin",
                        Type: "address",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "withdraw_fee_tokens": {
                Package:    "ccip_onramp",
                Module:     "onramp",
                Name:       "withdraw_fee_tokens",
                Parameters: []FunctionParameter{
                    {
                        Name: "fee_tokens",
                        Type: "vector<address>",
                    },
                },
            },
        },
    },
    "ccip_router": {
        "router": {
            "accept_ownership": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "ccip_send": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "ccip_send",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "receiver",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "token_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "token_amounts",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "token_store_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "fee_token",
                        Type: "address",
                    },
                    {
                        Name: "fee_token_store",
                        Type: "address",
                    },
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "ccip_send_with_message_id": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "ccip_send_with_message_id",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "receiver",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "token_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "token_amounts",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "token_store_addresses",
                        Type: "vector<address>",
                    },
                    {
                        Name: "fee_token",
                        Type: "address",
                    },
                    {
                        Name: "fee_token_store",
                        Type: "address",
                    },
                    {
                        Name: "extra_args",
                        Type: "vector<u8>",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "get_state_address_internal": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "get_state_address_internal",
                Parameters: []FunctionParameter{
                },
            },
            "mcms_entrypoint": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "set_on_ramp_versions": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "set_on_ramp_versions",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "on_ramp_versions",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "ccip_router",
                Module:     "router",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
    "ccip_token_pool": {
        "rate_limiter": {
            "min": {
                Package:    "ccip_token_pool",
                Module:     "rate_limiter",
                Name:       "min",
                Parameters: []FunctionParameter{
                    {
                        Name: "a",
                        Type: "u64",
                    },
                    {
                        Name: "b",
                        Type: "u64",
                    },
                },
            },
            "new": {
                Package:    "ccip_token_pool",
                Module:     "rate_limiter",
                Name:       "new",
                Parameters: []FunctionParameter{
                    {
                        Name: "is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "capacity",
                        Type: "u64",
                    },
                    {
                        Name: "rate",
                        Type: "u64",
                    },
                },
            },
        },
        "token_pool": {
            "destroy_token_pool": {
                Package:    "ccip_token_pool",
                Module:     "token_pool",
                Name:       "destroy_token_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "state",
                        Type: "TokenPoolState",
                    },
                },
            },
            "initialize": {
                Package:    "ccip_token_pool",
                Module:     "token_pool",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_token",
                        Type: "address",
                    },
                    {
                        Name: "allowlist",
                        Type: "vector<address>",
                    },
                },
            },
        },
        "token_pool_rate_limiter": {
            "destroy_rate_limiter": {
                Package:    "ccip_token_pool",
                Module:     "token_pool_rate_limiter",
                Name:       "destroy_rate_limiter",
                Parameters: []FunctionParameter{
                    {
                        Name: "state",
                        Type: "RateLimitState",
                    },
                },
            },
            "new": {
                Package:    "ccip_token_pool",
                Module:     "token_pool_rate_limiter",
                Name:       "new",
                Parameters: []FunctionParameter{
                },
            },
        },
    },
    "data_feeds": {
        "registry": {
            "accept_ownership": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "get_benchmarks": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "get_benchmarks",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "get_benchmarks_unchecked": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "get_benchmarks_unchecked",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "get_reports": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "get_reports",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "get_reports_unchecked": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "get_reports_unchecked",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "get_state_addr": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "get_state_addr",
                Parameters: []FunctionParameter{
                },
            },
            "new_proof": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "new_proof",
                Parameters: []FunctionParameter{
                },
            },
            "new_proof_secondary": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "new_proof_secondary",
                Parameters: []FunctionParameter{
                },
            },
            "on_report": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "on_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "_meta",
                        Type: "address",
                    },
                },
            },
            "on_report_secondary": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "on_report_secondary",
                Parameters: []FunctionParameter{
                    {
                        Name: "_meta",
                        Type: "address",
                    },
                },
            },
            "register_callbacks": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "register_callbacks",
                Parameters: []FunctionParameter{
                },
            },
            "remove_feeds": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "remove_feeds",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "set_feeds": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "set_feeds",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "descriptions",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "config_id",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_feeds_unchecked": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "set_feeds_unchecked",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "descriptions",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "config_id",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_workflow_config": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "set_workflow_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "allowed_workflow_owners",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "allowed_workflow_names",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "to_u256be": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "to_u256be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "to_u32be": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "to_u32be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "update_descriptions": {
                Package:    "data_feeds",
                Module:     "registry",
                Name:       "update_descriptions",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "descriptions",
                        Type: "vector<0x1::string::String>",
                    },
                },
            },
        },
        "router": {
            "accept_ownership": {
                Package:    "data_feeds",
                Module:     "router",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "configure_feeds": {
                Package:    "data_feeds",
                Module:     "router",
                Name:       "configure_feeds",
                Parameters: []FunctionParameter{
                    {
                        Name: "feed_ids",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "descriptions",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "config_id",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "_fee_config_id",
                        Type: "vector<u8>",
                    },
                },
            },
            "get_state_addr": {
                Package:    "data_feeds",
                Module:     "router",
                Name:       "get_state_addr",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "data_feeds",
                Module:     "router",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
    "lock_release_token_pool": {
        "lock_release_token_pool": {
            "accept_ownership": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "add_remote_pool": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "add_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "apply_allowlist_updates": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "apply_allowlist_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "removes",
                        Type: "vector<address>",
                    },
                    {
                        Name: "adds",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_chain_updates": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "apply_chain_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors_to_remove",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_chain_selectors_to_add",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_pool_addresses_to_add",
                        Type: "vector<vector<vector<u8>>>",
                    },
                    {
                        Name: "remote_token_addresses_to_add",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "assert_can_initialize": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "assert_can_initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller_address",
                        Type: "address",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "provide_liquidity": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "provide_liquidity",
                Parameters: []FunctionParameter{
                    {
                        Name: "amount",
                        Type: "u64",
                    },
                },
            },
            "remove_remote_pool": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "remove_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_chain_rate_limiter_config": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "set_chain_rate_limiter_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "outbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_rate",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "inbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_rate",
                        Type: "u64",
                    },
                },
            },
            "set_chain_rate_limiter_configs": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "set_chain_rate_limiter_configs",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "outbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_rates",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "inbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_rates",
                        Type: "vector<u64>",
                    },
                },
            },
            "set_rebalancer": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "set_rebalancer",
                Parameters: []FunctionParameter{
                    {
                        Name: "rebalancer",
                        Type: "address",
                    },
                },
            },
            "store_address": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "store_address",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "withdraw_liquidity": {
                Package:    "lock_release_token_pool",
                Module:     "lock_release_token_pool",
                Name:       "withdraw_liquidity",
                Parameters: []FunctionParameter{
                    {
                        Name: "amount",
                        Type: "u64",
                    },
                },
            },
        },
    },
    "managed_token": {
        "allowlist": {
            "destroy_allowlist": {
                Package:    "managed_token",
                Module:     "allowlist",
                Name:       "destroy_allowlist",
                Parameters: []FunctionParameter{
                    {
                        Name: "state",
                        Type: "AllowlistState",
                    },
                },
            },
            "new": {
                Package:    "managed_token",
                Module:     "allowlist",
                Name:       "new",
                Parameters: []FunctionParameter{
                    {
                        Name: "allowlist",
                        Type: "vector<address>",
                    },
                },
            },
            "new_with_name": {
                Package:    "managed_token",
                Module:     "allowlist",
                Name:       "new_with_name",
                Parameters: []FunctionParameter{
                    {
                        Name: "allowlist",
                        Type: "vector<address>",
                    },
                    {
                        Name: "allowlist_name",
                        Type: "0x1::string::String",
                    },
                },
            },
        },
        "faucet": {
            "drip": {
                Package:    "managed_token",
                Module:     "faucet",
                Name:       "drip",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
        "managed_token": {
            "accept_ownership": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "apply_allowed_burner_updates": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "apply_allowed_burner_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "burners_to_remove",
                        Type: "vector<address>",
                    },
                    {
                        Name: "burners_to_add",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_allowed_minter_updates": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "apply_allowed_minter_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "minters_to_remove",
                        Type: "vector<address>",
                    },
                    {
                        Name: "minters_to_add",
                        Type: "vector<address>",
                    },
                },
            },
            "burn": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "burn",
                Parameters: []FunctionParameter{
                    {
                        Name: "from",
                        Type: "address",
                    },
                    {
                        Name: "amount",
                        Type: "u64",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "initialize": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "max_supply",
                        Type: "0x1::option::Option<u128>",
                    },
                    {
                        Name: "name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "symbol",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "decimals",
                        Type: "u8",
                    },
                    {
                        Name: "icon",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "project",
                        Type: "0x1::string::String",
                    },
                },
            },
            "mint": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "mint",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                    {
                        Name: "amount",
                        Type: "u64",
                    },
                },
            },
            "token_state_address_internal": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "token_state_address_internal",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "managed_token",
                Module:     "managed_token",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
        "ownable": {
            "destroy": {
                Package:    "managed_token",
                Module:     "ownable",
                Name:       "destroy",
                Parameters: []FunctionParameter{
                    {
                        Name: "state",
                        Type: "OwnableState",
                    },
                },
            },
            "new": {
                Package:    "managed_token",
                Module:     "ownable",
                Name:       "new",
                Parameters: []FunctionParameter{
                    {
                        Name: "object_address",
                        Type: "address",
                    },
                },
            },
        },
    },
    "managed_token_pool": {
        "managed_token_pool": {
            "accept_ownership": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "add_remote_pool": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "add_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "apply_allowlist_updates": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "apply_allowlist_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "removes",
                        Type: "vector<address>",
                    },
                    {
                        Name: "adds",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_chain_updates": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "apply_chain_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors_to_remove",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_chain_selectors_to_add",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_pool_addresses_to_add",
                        Type: "vector<vector<vector<u8>>>",
                    },
                    {
                        Name: "remote_token_addresses_to_add",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "remove_remote_pool": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "remove_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_chain_rate_limiter_config": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "set_chain_rate_limiter_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "outbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_rate",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "inbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_rate",
                        Type: "u64",
                    },
                },
            },
            "set_chain_rate_limiter_configs": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "set_chain_rate_limiter_configs",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "outbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_rates",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "inbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_rates",
                        Type: "vector<u64>",
                    },
                },
            },
            "store_address": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "store_address",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "managed_token_pool",
                Module:     "managed_token_pool",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
    "mcms": {
        "mcms": {
            "chain_id": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "chain_id",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "compute_eth_message_hash": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "compute_eth_message_hash",
                Parameters: []FunctionParameter{
                    {
                        Name: "root",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "valid_until",
                        Type: "u64",
                    },
                },
            },
            "create_calls": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "create_calls",
                Parameters: []FunctionParameter{
                    {
                        Name: "targets",
                        Type: "vector<address>",
                    },
                    {
                        Name: "module_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "function_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "datas",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "create_multisig": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "create_multisig",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                },
            },
            "data": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "data",
                Parameters: []FunctionParameter{
                    {
                        Name: "call",
                        Type: "Call",
                    },
                },
            },
            "dispatch_to_timelock": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "dispatch_to_timelock",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "ecdsa_recover_evm_addr": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "ecdsa_recover_evm_addr",
                Parameters: []FunctionParameter{
                    {
                        Name: "eth_signed_message_hash",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signature",
                        Type: "vector<u8>",
                    },
                },
            },
            "execute": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "execute",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                    {
                        Name: "chain_id",
                        Type: "u256",
                    },
                    {
                        Name: "multisig_addr",
                        Type: "address",
                    },
                    {
                        Name: "nonce",
                        Type: "u64",
                    },
                    {
                        Name: "to",
                        Type: "address",
                    },
                    {
                        Name: "module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "proof",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "function_name": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "function_name",
                Parameters: []FunctionParameter{
                    {
                        Name: "function",
                        Type: "Function",
                    },
                },
            },
            "hash_metadata_leaf": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "hash_metadata_leaf",
                Parameters: []FunctionParameter{
                    {
                        Name: "metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "hash_op_leaf": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "hash_op_leaf",
                Parameters: []FunctionParameter{
                    {
                        Name: "domain_separator",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "op",
                        Type: "Op",
                    },
                },
            },
            "hash_operation_batch": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "hash_operation_batch",
                Parameters: []FunctionParameter{
                    {
                        Name: "calls",
                        Type: "vector<Call>",
                    },
                    {
                        Name: "predecessor",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "salt",
                        Type: "vector<u8>",
                    },
                },
            },
            "module_name": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "module_name",
                Parameters: []FunctionParameter{
                    {
                        Name: "function",
                        Type: "Function",
                    },
                },
            },
            "override_previous_root": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "override_previous_root",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "post_op_count": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "post_op_count",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "pre_op_count": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "pre_op_count",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "role": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "role",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "root_metadata_multisig": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "root_metadata_multisig",
                Parameters: []FunctionParameter{
                    {
                        Name: "root_metadata",
                        Type: "RootMetadata",
                    },
                },
            },
            "set_config": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "set_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                    {
                        Name: "signer_addresses",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "signer_groups",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "group_quorums",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "group_parents",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "clear_root",
                        Type: "bool",
                    },
                },
            },
            "set_root": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "set_root",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                    {
                        Name: "root",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "valid_until",
                        Type: "u64",
                    },
                    {
                        Name: "chain_id",
                        Type: "u256",
                    },
                    {
                        Name: "multisig_addr",
                        Type: "address",
                    },
                    {
                        Name: "pre_op_count",
                        Type: "u64",
                    },
                    {
                        Name: "post_op_count",
                        Type: "u64",
                    },
                    {
                        Name: "override_previous_root",
                        Type: "bool",
                    },
                    {
                        Name: "metadata_proof",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "target": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "target",
                Parameters: []FunctionParameter{
                    {
                        Name: "function",
                        Type: "Function",
                    },
                },
            },
            "timelock_after_call": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_after_call",
                Parameters: []FunctionParameter{
                    {
                        Name: "id",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_before_call": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_before_call",
                Parameters: []FunctionParameter{
                    {
                        Name: "id",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "predecessor",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_block_function": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_block_function",
                Parameters: []FunctionParameter{
                    {
                        Name: "target",
                        Type: "address",
                    },
                    {
                        Name: "module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                },
            },
            "timelock_bypasser_execute_batch": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_bypasser_execute_batch",
                Parameters: []FunctionParameter{
                    {
                        Name: "targets",
                        Type: "vector<address>",
                    },
                    {
                        Name: "module_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "function_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "datas",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "timelock_cancel": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_cancel",
                Parameters: []FunctionParameter{
                    {
                        Name: "id",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_dispatch": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_dispatch",
                Parameters: []FunctionParameter{
                    {
                        Name: "target",
                        Type: "address",
                    },
                    {
                        Name: "module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_dispatch_to_account": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_dispatch_to_account",
                Parameters: []FunctionParameter{
                    {
                        Name: "function_name_bytes",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_dispatch_to_deployer": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_dispatch_to_deployer",
                Parameters: []FunctionParameter{
                    {
                        Name: "function_name_bytes",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_dispatch_to_registry": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_dispatch_to_registry",
                Parameters: []FunctionParameter{
                    {
                        Name: "function_name_bytes",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_dispatch_to_self": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_dispatch_to_self",
                Parameters: []FunctionParameter{
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_execute_batch": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_execute_batch",
                Parameters: []FunctionParameter{
                    {
                        Name: "targets",
                        Type: "vector<address>",
                    },
                    {
                        Name: "module_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "function_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "datas",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "predecessor",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "salt",
                        Type: "vector<u8>",
                    },
                },
            },
            "timelock_schedule_batch": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_schedule_batch",
                Parameters: []FunctionParameter{
                    {
                        Name: "targets",
                        Type: "vector<address>",
                    },
                    {
                        Name: "module_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "function_names",
                        Type: "vector<0x1::string::String>",
                    },
                    {
                        Name: "datas",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "predecessor",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "salt",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "delay",
                        Type: "u64",
                    },
                },
            },
            "timelock_unblock_function": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_unblock_function",
                Parameters: []FunctionParameter{
                    {
                        Name: "target",
                        Type: "address",
                    },
                    {
                        Name: "module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "function_name",
                        Type: "0x1::string::String",
                    },
                },
            },
            "timelock_update_min_delay": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "timelock_update_min_delay",
                Parameters: []FunctionParameter{
                    {
                        Name: "new_min_delay",
                        Type: "u64",
                    },
                },
            },
            "verify_merkle_proof": {
                Package:    "mcms",
                Module:     "mcms",
                Name:       "verify_merkle_proof",
                Parameters: []FunctionParameter{
                    {
                        Name: "proof",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "root",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "leaf",
                        Type: "vector<u8>",
                    },
                },
            },
        },
        "mcms_account": {
            "accept_ownership": {
                Package:    "mcms",
                Module:     "mcms_account",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "assert_is_owner": {
                Package:    "mcms",
                Module:     "mcms_account",
                Name:       "assert_is_owner",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "mcms",
                Module:     "mcms_account",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "transfer_ownership_to_self": {
                Package:    "mcms",
                Module:     "mcms_account",
                Name:       "transfer_ownership_to_self",
                Parameters: []FunctionParameter{
                },
            },
        },
        "mcms_deployer": {
            "cleanup_staging_area": {
                Package:    "mcms",
                Module:     "mcms_deployer",
                Name:       "cleanup_staging_area",
                Parameters: []FunctionParameter{
                },
            },
            "cleanup_staging_area_internal": {
                Package:    "mcms",
                Module:     "mcms_deployer",
                Name:       "cleanup_staging_area_internal",
                Parameters: []FunctionParameter{
                },
            },
            "stage_code_chunk": {
                Package:    "mcms",
                Module:     "mcms_deployer",
                Name:       "stage_code_chunk",
                Parameters: []FunctionParameter{
                    {
                        Name: "metadata_chunk",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "code_indices",
                        Type: "vector<u16>",
                    },
                    {
                        Name: "code_chunks",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "stage_code_chunk_and_publish_to_object": {
                Package:    "mcms",
                Module:     "mcms_deployer",
                Name:       "stage_code_chunk_and_publish_to_object",
                Parameters: []FunctionParameter{
                    {
                        Name: "metadata_chunk",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "code_indices",
                        Type: "vector<u16>",
                    },
                    {
                        Name: "code_chunks",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "new_owner_seed",
                        Type: "vector<u8>",
                    },
                },
            },
            "stage_code_chunk_and_upgrade_object_code": {
                Package:    "mcms",
                Module:     "mcms_deployer",
                Name:       "stage_code_chunk_and_upgrade_object_code",
                Parameters: []FunctionParameter{
                    {
                        Name: "metadata_chunk",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "code_indices",
                        Type: "vector<u16>",
                    },
                    {
                        Name: "code_chunks",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "code_object_address",
                        Type: "address",
                    },
                },
            },
        },
        "mcms_executor": {
            "clear_staged_data": {
                Package:    "mcms",
                Module:     "mcms_executor",
                Name:       "clear_staged_data",
                Parameters: []FunctionParameter{
                },
            },
            "stage_data": {
                Package:    "mcms",
                Module:     "mcms_executor",
                Name:       "stage_data",
                Parameters: []FunctionParameter{
                    {
                        Name: "data_chunk",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "partial_proofs",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "stage_data_and_execute": {
                Package:    "mcms",
                Module:     "mcms_executor",
                Name:       "stage_data_and_execute",
                Parameters: []FunctionParameter{
                    {
                        Name: "role",
                        Type: "u8",
                    },
                    {
                        Name: "chain_id",
                        Type: "u256",
                    },
                    {
                        Name: "multisig",
                        Type: "address",
                    },
                    {
                        Name: "nonce",
                        Type: "u64",
                    },
                    {
                        Name: "to",
                        Type: "address",
                    },
                    {
                        Name: "module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "function",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data_chunk",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "partial_proofs",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
        },
        "mcms_registry": {
            "accept_code_object": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "accept_code_object",
                Parameters: []FunctionParameter{
                    {
                        Name: "object_address",
                        Type: "address",
                    },
                },
            },
            "create_owner_for_preexisting_code_object": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "create_owner_for_preexisting_code_object",
                Parameters: []FunctionParameter{
                    {
                        Name: "object_address",
                        Type: "address",
                    },
                },
            },
            "execute_code_object_transfer": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "execute_code_object_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "object_address",
                        Type: "address",
                    },
                    {
                        Name: "new_owner_address",
                        Type: "address",
                    },
                },
            },
            "finish_dispatch": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "finish_dispatch",
                Parameters: []FunctionParameter{
                    {
                        Name: "callback_address",
                        Type: "address",
                    },
                },
            },
            "start_dispatch": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "start_dispatch",
                Parameters: []FunctionParameter{
                    {
                        Name: "callback_address",
                        Type: "address",
                    },
                    {
                        Name: "callback_module_name",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "callback_function",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "transfer_code_object": {
                Package:    "mcms",
                Module:     "mcms_registry",
                Name:       "transfer_code_object",
                Parameters: []FunctionParameter{
                    {
                        Name: "object_address",
                        Type: "address",
                    },
                    {
                        Name: "new_owner_address",
                        Type: "address",
                    },
                },
            },
        },
    },
    "mcms_test": {
        "mcms_user": {
            "function_one": {
                Package:    "mcms_test",
                Module:     "mcms_user",
                Name:       "function_one",
                Parameters: []FunctionParameter{
                    {
                        Name: "arg1",
                        Type: "0x1::string::String",
                    },
                    {
                        Name: "arg2",
                        Type: "vector<u8>",
                    },
                },
            },
            "function_two": {
                Package:    "mcms_test",
                Module:     "mcms_user",
                Name:       "function_two",
                Parameters: []FunctionParameter{
                    {
                        Name: "arg1",
                        Type: "address",
                    },
                    {
                        Name: "arg2",
                        Type: "u128",
                    },
                },
            },
            "mcms_entrypoint": {
                Package:    "mcms_test",
                Module:     "mcms_user",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
        },
    },
    "platform": {
        "forwarder": {
            "accept_ownership": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "clear_config": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "clear_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "don_id",
                        Type: "u32",
                    },
                    {
                        Name: "config_version",
                        Type: "u32",
                    },
                },
            },
            "dispatch": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "dispatch",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "metadata",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "get_state_addr": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "get_state_addr",
                Parameters: []FunctionParameter{
                },
            },
            "report": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "report",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "raw_report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "set_config": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "set_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "don_id",
                        Type: "u32",
                    },
                    {
                        Name: "config_version",
                        Type: "u32",
                    },
                    {
                        Name: "f",
                        Type: "u8",
                    },
                    {
                        Name: "oracles",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "signature_from_bytes": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "signature_from_bytes",
                Parameters: []FunctionParameter{
                    {
                        Name: "bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "to_u16be": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "to_u16be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "to_u32be": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "to_u32be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "transmission_id": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "transmission_id",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "workflow_execution_id",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "report_id",
                        Type: "u16",
                    },
                },
            },
            "validate_and_process_report": {
                Package:    "platform",
                Module:     "forwarder",
                Name:       "validate_and_process_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "raw_report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<Signature>",
                    },
                },
            },
        },
        "storage": {
            "insert": {
                Package:    "platform",
                Module:     "storage",
                Name:       "insert",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "callback_metadata",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "callback_data",
                        Type: "vector<u8>",
                    },
                },
            },
            "migrate_to_v2": {
                Package:    "platform",
                Module:     "storage",
                Name:       "migrate_to_v2",
                Parameters: []FunctionParameter{
                    {
                        Name: "callback_addresses",
                        Type: "vector<address>",
                    },
                },
            },
            "storage_address": {
                Package:    "platform",
                Module:     "storage",
                Name:       "storage_address",
                Parameters: []FunctionParameter{
                },
            },
            "storage_exists": {
                Package:    "platform",
                Module:     "storage",
                Name:       "storage_exists",
                Parameters: []FunctionParameter{
                    {
                        Name: "obj_address",
                        Type: "address",
                    },
                },
            },
        },
    },
    "platform_secondary": {
        "forwarder": {
            "accept_ownership": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "clear_config": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "clear_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "don_id",
                        Type: "u32",
                    },
                    {
                        Name: "config_version",
                        Type: "u32",
                    },
                },
            },
            "dispatch": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "dispatch",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "metadata",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "get_state_addr": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "get_state_addr",
                Parameters: []FunctionParameter{
                },
            },
            "report": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "report",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "raw_report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "set_config": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "set_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "don_id",
                        Type: "u32",
                    },
                    {
                        Name: "config_version",
                        Type: "u32",
                    },
                    {
                        Name: "f",
                        Type: "u8",
                    },
                    {
                        Name: "oracles",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "signature_from_bytes": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "signature_from_bytes",
                Parameters: []FunctionParameter{
                    {
                        Name: "bytes",
                        Type: "vector<u8>",
                    },
                },
            },
            "to_u16be": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "to_u16be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "to_u32be": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "to_u32be",
                Parameters: []FunctionParameter{
                    {
                        Name: "data",
                        Type: "vector<u8>",
                    },
                },
            },
            "transfer_ownership": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "transmission_id": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "transmission_id",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "workflow_execution_id",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "report_id",
                        Type: "u16",
                    },
                },
            },
            "validate_and_process_report": {
                Package:    "platform_secondary",
                Module:     "forwarder",
                Name:       "validate_and_process_report",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "raw_report",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "signatures",
                        Type: "vector<Signature>",
                    },
                },
            },
        },
        "storage": {
            "insert": {
                Package:    "platform_secondary",
                Module:     "storage",
                Name:       "insert",
                Parameters: []FunctionParameter{
                    {
                        Name: "receiver",
                        Type: "address",
                    },
                    {
                        Name: "callback_metadata",
                        Type: "vector<u8>",
                    },
                    {
                        Name: "callback_data",
                        Type: "vector<u8>",
                    },
                },
            },
            "migrate_to_v2": {
                Package:    "platform_secondary",
                Module:     "storage",
                Name:       "migrate_to_v2",
                Parameters: []FunctionParameter{
                    {
                        Name: "callback_addresses",
                        Type: "vector<address>",
                    },
                },
            },
            "storage_address": {
                Package:    "platform_secondary",
                Module:     "storage",
                Name:       "storage_address",
                Parameters: []FunctionParameter{
                },
            },
            "storage_exists": {
                Package:    "platform_secondary",
                Module:     "storage",
                Name:       "storage_exists",
                Parameters: []FunctionParameter{
                    {
                        Name: "obj_address",
                        Type: "address",
                    },
                },
            },
        },
    },
    "usdc_token_pool": {
        "usdc_token_pool": {
            "accept_ownership": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "accept_ownership",
                Parameters: []FunctionParameter{
                },
            },
            "add_remote_pool": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "add_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "apply_allowlist_updates": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "apply_allowlist_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "removes",
                        Type: "vector<address>",
                    },
                    {
                        Name: "adds",
                        Type: "vector<address>",
                    },
                },
            },
            "apply_chain_updates": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "apply_chain_updates",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors_to_remove",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_chain_selectors_to_add",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_pool_addresses_to_add",
                        Type: "vector<vector<vector<u8>>>",
                    },
                    {
                        Name: "remote_token_addresses_to_add",
                        Type: "vector<vector<u8>>",
                    },
                },
            },
            "assert_can_initialize": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "assert_can_initialize",
                Parameters: []FunctionParameter{
                    {
                        Name: "caller_address",
                        Type: "address",
                    },
                },
            },
            "decode_dest_pool_data": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "decode_dest_pool_data",
                Parameters: []FunctionParameter{
                    {
                        Name: "dest_pool_data",
                        Type: "vector<u8>",
                    },
                },
            },
            "encode_dest_pool_data": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "encode_dest_pool_data",
                Parameters: []FunctionParameter{
                    {
                        Name: "local_domain_identifier",
                        Type: "u32",
                    },
                    {
                        Name: "nonce",
                        Type: "u64",
                    },
                },
            },
            "execute_ownership_transfer": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "execute_ownership_transfer",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
            "initialize": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "initialize",
                Parameters: []FunctionParameter{
                },
            },
            "mcms_entrypoint": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "mcms_entrypoint",
                Parameters: []FunctionParameter{
                    {
                        Name: "_metadata",
                        Type: "address",
                    },
                },
            },
            "parse_message_and_attestation": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "parse_message_and_attestation",
                Parameters: []FunctionParameter{
                    {
                        Name: "payload",
                        Type: "vector<u8>",
                    },
                },
            },
            "remove_remote_pool": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "remove_remote_pool",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "remote_pool_address",
                        Type: "vector<u8>",
                    },
                },
            },
            "set_chain_rate_limiter_config": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "set_chain_rate_limiter_config",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selector",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "outbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "outbound_rate",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_is_enabled",
                        Type: "bool",
                    },
                    {
                        Name: "inbound_capacity",
                        Type: "u64",
                    },
                    {
                        Name: "inbound_rate",
                        Type: "u64",
                    },
                },
            },
            "set_chain_rate_limiter_configs": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "set_chain_rate_limiter_configs",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "outbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "outbound_rates",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_is_enableds",
                        Type: "vector<bool>",
                    },
                    {
                        Name: "inbound_capacities",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "inbound_rates",
                        Type: "vector<u64>",
                    },
                },
            },
            "set_domains": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "set_domains",
                Parameters: []FunctionParameter{
                    {
                        Name: "remote_chain_selectors",
                        Type: "vector<u64>",
                    },
                    {
                        Name: "remote_domain_identifiers",
                        Type: "vector<u32>",
                    },
                    {
                        Name: "allowed_remote_callers",
                        Type: "vector<vector<u8>>",
                    },
                    {
                        Name: "enableds",
                        Type: "vector<bool>",
                    },
                },
            },
            "store_address": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "store_address",
                Parameters: []FunctionParameter{
                },
            },
            "transfer_ownership": {
                Package:    "usdc_token_pool",
                Module:     "usdc_token_pool",
                Name:       "transfer_ownership",
                Parameters: []FunctionParameter{
                    {
                        Name: "to",
                        Type: "address",
                    },
                },
            },
        },
    },
}
