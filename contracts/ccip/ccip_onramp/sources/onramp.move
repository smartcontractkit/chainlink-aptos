module ccip_onramp::onramp {
    use std::ascii;
    use std::type_name;

    use sui::address;
    use sui::clock::Clock;
    use sui::balance;
    use sui::coin::{Self, Coin, CoinMetadata};
    use sui::event;
    use sui::hash;
    use std::string::{Self, String};
    use sui::table::{Self, Table};
    use sui::bag::{Self, Bag};
    use sui::package::UpgradeCap;

    use ccip::dynamic_dispatcher as dd;
    use ccip::eth_abi;
    use ccip::fee_quoter;
    use ccip::merkle_proof;
    use ccip::nonce_manager::{Self, NonceManagerCap};
    use ccip::rmn_remote;
    use ccip::state_object::CCIPObjectRef;
    use ccip_onramp::ownable::{Self, OwnerCap, OwnableState};

    use mcms::mcms_registry::{Self, Registry, ExecutingCallbackParams};
    use mcms::mcms_deployer::{Self, DeployerState};
    use mcms::bcs_stream;

    public struct OnRampState has key, store {
        id: UID,
        chain_selector: u64,
        fee_aggregator: address,
        allowlist_admin: address,

        // dest chain selector -> config
        dest_chain_configs: Table<u64, DestChainConfig>,
        // coin metadata address -> Coin
        fee_tokens: Bag,
        nonce_manager_cap: Option<NonceManagerCap>,
        source_transfer_cap: Option<dd::SourceTransferCap>,
        ownable_state: OwnableState,
    }

    public struct OnRampStatePointer has key, store {
        id: UID,
        on_ramp_state_id: address,
        owner_cap_id: address,
    }

    public struct DestChainConfig has store, drop {
        // on EVM, transfers can be stopped by zeroing the router address,
        // since we don't have a router address here, we add an is_enabled flag.
        // ref: https://github.com/smartcontractkit/chainlink/blob/62a9b78e1c32174ccec11f1ed487edf3b0b4e8fd/contracts/src/v0.8/ccip/onRamp/OnRamp.sol#L181
        is_enabled: bool,
        sequence_number: u64,
        allowlist_enabled: bool,
        allowed_senders: vector<address>
    }

    public struct RampMessageHeader has store, drop, copy {
        message_id: vector<u8>,
        source_chain_selector: u64,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64
    }

    public struct Sui2AnyRampMessage has store, drop, copy {
        header: RampMessageHeader,
        sender: address,
        data: vector<u8>,
        receiver: vector<u8>,
        extra_args: vector<u8>,
        fee_token: address,
        fee_token_amount: u64,
        fee_value_juels: u256,
        token_amounts: vector<Sui2AnyTokenTransfer>
    }

    public struct Sui2AnyTokenTransfer has store, drop, copy {
        source_pool_address: address,
        // the token address on the destination chain
        dest_token_address: vector<u8>,
        extra_data: vector<u8>, // random bytes provided by token pool, e.g. encoded decimals
        amount: u64,
        dest_exec_data: vector<u8> // destination gas amount
    }

    public struct StaticConfig has copy, drop {
        chain_selector: u64
    }

    public struct DynamicConfig has copy, drop {
        fee_aggregator: address,
        allowlist_admin: address
    }

    public struct ConfigSet has copy, drop {
        static_config: StaticConfig,
        dynamic_config: DynamicConfig
    }

    public struct DestChainConfigSet has copy, drop {
        dest_chain_selector: u64,
        is_enabled: bool,
        sequence_number: u64,
        allowlist_enabled: bool
    }

    public struct CCIPMessageSent has copy, drop {
        dest_chain_selector: u64,
        sequence_number: u64,
        message: Sui2AnyRampMessage
    }

    public struct AllowlistSendersAdded has copy, drop {
        dest_chain_selector: u64,
        senders: vector<address>
    }

    public struct AllowlistSendersRemoved has copy, drop {
        dest_chain_selector: u64,
        senders: vector<address>
    }

    public struct FeeTokenWithdrawn has copy, drop {
        fee_aggregator: address,
        fee_token: address,
        amount: u64
    }

    const EDestChainArgumentMismatch: u64 = 1;
    const EInvalidDestChainSelector: u64 = 2;
    const EUnknownDestChainSelector: u64 = 3;
    const EDestChainNotEnabled: u64 = 4;
    const ESenderNotAllowed: u64 = 5;
    const EOnlyCallableByAllowlistAdmin: u64 = 6;
    const EInvalidAllowlistRequest: u64 = 7;
    const EInvalidAllowlistAddress: u64 = 8;
    const ECursedByRmn: u64 = 9;
    const EUnexpectedWithdrawAmount: u64 = 10;
    const EFeeAggregatorNotSet: u64 = 11;
    const ENonceManagerCapExists: u64 = 12;
    const ESourceTransferCapExists: u64 = 13;
    const EUnknownFunction: u64 = 14;
    const ECannotSendZeroTokens: u64 = 15;
    const EZeroChainSelector: u64 = 16;

    public fun type_and_version(): String {
        string::utf8(b"OnRamp 1.6.0")
    }

    public struct ONRAMP has drop {}

    fun init(_witness: ONRAMP, ctx: &mut TxContext) {
        let (ownable_state, owner_cap) = ownable::new(ctx);

        let state = OnRampState {
            id: object::new(ctx),
            chain_selector: 0,
            fee_aggregator: @0x0,
            allowlist_admin: @0x0,
            dest_chain_configs: table::new(ctx),
            fee_tokens: bag::new(ctx),
            nonce_manager_cap: option::none(),
            source_transfer_cap: option::none(),
            ownable_state
        };

        let pointer = OnRampStatePointer {
            id: object::new(ctx),
            on_ramp_state_id: object::id_to_address(object::borrow_id(&state)),
            owner_cap_id: object::id_to_address(object::borrow_id(&owner_cap)),
        };

        let tn = type_name::get_with_original_ids<ONRAMP>();
        let package_bytes = ascii::into_bytes(tn.get_address());
        let package_id = address::from_ascii_bytes(&package_bytes);

        transfer::share_object(state);
        transfer::public_transfer(owner_cap, ctx.sender());
        transfer::transfer(pointer, package_id);
    }

    public fun initialize(
        state: &mut OnRampState,
        _: &OwnerCap,
        nonce_manager_cap: NonceManagerCap,
        source_transfer_cap: dd::SourceTransferCap,
        chain_selector: u64,
        fee_aggregator: address,
        allowlist_admin: address,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>,
        _ctx: &mut TxContext
    ) {
        assert!(chain_selector != 0, EZeroChainSelector);
        state.chain_selector = chain_selector;
        assert!(
            state.nonce_manager_cap.is_none(),
            ENonceManagerCapExists
        );
        state.nonce_manager_cap.fill(nonce_manager_cap);
        assert!(
            state.source_transfer_cap.is_none(),
            ESourceTransferCapExists
        );
        state.source_transfer_cap.fill(source_transfer_cap);

        set_dynamic_config_internal(state, fee_aggregator, allowlist_admin);

        apply_dest_chain_config_updates_internal(
            state,
            dest_chain_selectors,
            dest_chain_enabled,
            dest_chain_allowlist_enabled
        );
    }

    public fun is_chain_supported(state: &OnRampState, dest_chain_selector: u64): bool {
        state.dest_chain_configs.contains(dest_chain_selector)
    }

    public fun get_expected_next_sequence_number(state: &OnRampState, dest_chain_selector: u64): u64 {
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            EUnknownDestChainSelector
        );
        let dest_chain_config = &state.dest_chain_configs[dest_chain_selector];
        dest_chain_config.sequence_number + 1
    }

    // TODO: verify withdraw fee tokens
    public fun withdraw_fee_tokens<T>(
        state: &mut OnRampState,
        _: &OwnerCap,
        fee_token_metadata: &CoinMetadata<T>
    ) {
        assert!(state.fee_aggregator != @0x0, EFeeAggregatorNotSet);

        let fee_token_metadata_addr = object::id_to_address(object::borrow_id(fee_token_metadata));

        let coins: Coin<T> = bag::remove(&mut state.fee_tokens, fee_token_metadata_addr);
        let balance = balance::value(coin::balance(&coins));
        transfer::public_transfer(coins, state.fee_aggregator);
        event::emit(
            FeeTokenWithdrawn {
                fee_aggregator: state.fee_aggregator,
                fee_token: fee_token_metadata_addr,
                amount: balance
            }
        );
    }

    fun set_dynamic_config_internal(
        state: &mut OnRampState, fee_aggregator: address, allowlist_admin: address
    ) {
        ccip::address::assert_non_zero_address(fee_aggregator);
        ccip::address::assert_non_zero_address(allowlist_admin);

        state.fee_aggregator = fee_aggregator;
        state.allowlist_admin = allowlist_admin;

        let static_config = StaticConfig { chain_selector: state.chain_selector };
        let dynamic_config = DynamicConfig { fee_aggregator, allowlist_admin };

        event::emit(ConfigSet { static_config, dynamic_config });
    }

    fun apply_dest_chain_config_updates_internal(
        state: &mut OnRampState,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_enabled.length(),
            EDestChainArgumentMismatch
        );
        assert!(
            dest_chains_len == dest_chain_allowlist_enabled.length(),
            EDestChainArgumentMismatch
        );

        let mut i = 0;
        while (i < dest_chains_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            assert!(
                dest_chain_selector != 0,
                EInvalidDestChainSelector
            );

            let is_enabled = dest_chain_enabled[i];
            let allowlist_enabled = dest_chain_allowlist_enabled[i];

            if (!state.dest_chain_configs.contains(dest_chain_selector)) {
                state.dest_chain_configs.add(
                    dest_chain_selector,
                    DestChainConfig {
                        is_enabled: false,
                        sequence_number: 0,
                        allowlist_enabled: false,
                        allowed_senders: vector[]
                    }
                );
            };

            let dest_chain_config =
                table::borrow_mut(
                    &mut state.dest_chain_configs, dest_chain_selector
                );

            dest_chain_config.is_enabled = is_enabled;
            dest_chain_config.allowlist_enabled = allowlist_enabled;

            event::emit(
                DestChainConfigSet {
                    dest_chain_selector,
                    is_enabled,
                    sequence_number: dest_chain_config.sequence_number,
                    allowlist_enabled: dest_chain_config.allowlist_enabled
                }
            );

            i = i + 1;
        };
    }

    public fun get_fee<T>(
        ref: &CCIPObjectRef,
        clock: &Clock,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>, // the token's coin metadata object ids
        token_amounts: vector<u64>,
        fee_token: &CoinMetadata<T>,
        extra_args: vector<u8>
    ): u64 {
        get_fee_internal(
            ref,
            clock,
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            object::id_to_address(object::borrow_id(fee_token)),
            extra_args,
        )
    }

    fun get_fee_internal(
        ref: &CCIPObjectRef,
        clock: &Clock,
        dest_chain_selector: u64,
        receiver: vector<u8>,
        data: vector<u8>,
        token_addresses: vector<address>, // the token's coin metadata object ids
        token_amounts: vector<u64>,
        fee_token: address,
        extra_args: vector<u8>
    ): u64 {
        assert!(
            !rmn_remote::is_cursed_u128(ref, dest_chain_selector as u128),
            ECursedByRmn
        );
        fee_quoter::get_validated_fee(
            ref,
            clock,
            dest_chain_selector,
            receiver,
            data,
            token_addresses,
            token_amounts,
            fee_token,
            extra_args,
        )
    }

    public fun set_dynamic_config(
        state: &mut OnRampState,
        _: &OwnerCap,
        fee_aggregator: address,
        allowlist_admin: address
    ) {
        set_dynamic_config_internal(state, fee_aggregator, allowlist_admin);
    }

    public fun apply_dest_chain_config_updates(
        state: &mut OnRampState,
        _: &OwnerCap,
        dest_chain_selectors: vector<u64>,
        dest_chain_enabled: vector<bool>,
        dest_chain_allowlist_enabled: vector<bool>
    ) {
        apply_dest_chain_config_updates_internal(
            state,
            dest_chain_selectors,
            dest_chain_enabled,
            dest_chain_allowlist_enabled
        )
    }

    public fun get_dest_chain_config(state: &OnRampState, dest_chain_selector: u64): (bool, u64, bool, vector<address>) {
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            EUnknownDestChainSelector
        );

        let dest_chain_config = &state.dest_chain_configs[dest_chain_selector];

        (
            dest_chain_config.is_enabled,
            dest_chain_config.sequence_number,
            dest_chain_config.allowlist_enabled,
            dest_chain_config.allowed_senders,
        )
    }

    public fun get_allowed_senders_list(state: &OnRampState, dest_chain_selector: u64): (bool, vector<address>) {
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            EUnknownDestChainSelector
        );

        let dest_chain_config = &state.dest_chain_configs[dest_chain_selector];

        (dest_chain_config.allowlist_enabled, dest_chain_config.allowed_senders)
    }

    public fun apply_allowlist_updates(
        state: &mut OnRampState,
        _: &OwnerCap,
        dest_chain_selectors: vector<u64>,
        dest_chain_allowlist_enabled: vector<bool>,
        dest_chain_add_allowed_senders: vector<vector<address>>,
        dest_chain_remove_allowed_senders: vector<vector<address>>,
        _ctx: &mut TxContext,
    ) {
        apply_allowlist_updates_internal(
            state,
            dest_chain_selectors,
            dest_chain_allowlist_enabled,
            dest_chain_add_allowed_senders,
            dest_chain_remove_allowed_senders
        );
    }

    public fun apply_allowlist_updates_by_admin(
        state: &mut OnRampState,
        dest_chain_selectors: vector<u64>,
        dest_chain_allowlist_enabled: vector<bool>,
        dest_chain_add_allowed_senders: vector<vector<address>>,
        dest_chain_remove_allowed_senders: vector<vector<address>>,
        ctx: &mut TxContext,
    ) {
        assert!(
            state.allowlist_admin == ctx.sender(),
            EOnlyCallableByAllowlistAdmin
        );

        apply_allowlist_updates_internal(
            state,
            dest_chain_selectors,
            dest_chain_allowlist_enabled,
            dest_chain_add_allowed_senders,
            dest_chain_remove_allowed_senders
        );
    }

    fun apply_allowlist_updates_internal(
        state: &mut OnRampState,
        dest_chain_selectors: vector<u64>,
        dest_chain_allowlist_enabled: vector<bool>,
        dest_chain_add_allowed_senders: vector<vector<address>>,
        dest_chain_remove_allowed_senders: vector<vector<address>>,
    ) {
        let dest_chains_len = dest_chain_selectors.length();
        assert!(
            dest_chains_len == dest_chain_allowlist_enabled.length(),
            EDestChainArgumentMismatch
        );
        assert!(
            dest_chains_len == dest_chain_add_allowed_senders.length(),
            EDestChainArgumentMismatch
        );
        assert!(
            dest_chains_len == dest_chain_remove_allowed_senders.length(),
            EDestChainArgumentMismatch
        );

        let mut i = 0;
        while (i < dest_chains_len) {
            let dest_chain_selector = dest_chain_selectors[i];
            assert!(
                state.dest_chain_configs.contains(dest_chain_selector),
                EUnknownDestChainSelector
            );

            let allowlist_enabled = dest_chain_allowlist_enabled[i];
            let add_allowed_senders = dest_chain_add_allowed_senders[i];
            let remove_allowed_senders = dest_chain_remove_allowed_senders[i];

            let dest_chain_config =
                state.dest_chain_configs.borrow_mut(dest_chain_selector);
            dest_chain_config.allowlist_enabled = allowlist_enabled;

            if (add_allowed_senders.length() > 0) {
                assert!(allowlist_enabled, EInvalidAllowlistRequest);

                vector::do_ref!(
                    &add_allowed_senders,
                    |sender_address| {
                        let sender_address: address = *sender_address;
                        assert!(sender_address != @0x0, EInvalidAllowlistAddress);

                        let (found, _) = vector::index_of(
                            &dest_chain_config.allowed_senders, &sender_address
                        );
                        if (!found) {
                            dest_chain_config.allowed_senders.push_back(sender_address);
                        };
                    }
                );

                event::emit(
                    AllowlistSendersAdded {
                        dest_chain_selector,
                        senders: add_allowed_senders
                    }
                );
            };

            if (remove_allowed_senders.length() > 0) {
                vector::do_ref!(
                    &remove_allowed_senders,
                    |sender_address| {
                        let (found, i) = vector::index_of(
                            &dest_chain_config.allowed_senders, sender_address
                        );
                        if (found) {
                            vector::swap_remove(
                                &mut dest_chain_config.allowed_senders, i
                            );
                        }
                    }
                );

                event::emit(
                    AllowlistSendersRemoved {
                        dest_chain_selector,
                        senders: remove_allowed_senders
                    }
                );
            };
            i = i + 1;
        };
    }

    public fun get_outbound_nonce(
        ref: &CCIPObjectRef, dest_chain_selector: u64, sender: address
    ): u64 {
        nonce_manager::get_outbound_nonce(ref, dest_chain_selector, sender)
    }

    public fun get_static_config(state: &OnRampState): StaticConfig {
        StaticConfig { chain_selector: state.chain_selector }
    }

    public fun get_static_config_fields(cfg: StaticConfig): u64 {
        cfg.chain_selector
    }

    public fun get_dynamic_config(state: &OnRampState): DynamicConfig {
        DynamicConfig {
            fee_aggregator: state.fee_aggregator,
            allowlist_admin: state.allowlist_admin
        }
    }

    public fun get_dynamic_config_fields(cfg: DynamicConfig): (address, address) {
        (cfg.fee_aggregator, cfg.allowlist_admin)
    }

    fun calculate_metadata_hash(
        source_chain_selector: u64, dest_chain_selector: u64, on_ramp_address: address
    ): vector<u8> {
        let mut packed = vector[];
        eth_abi::encode_right_padded_bytes32(
            &mut packed, hash::keccak256(&b"Sui2AnyMessageHashV1")
        );
        eth_abi::encode_u64(&mut packed, source_chain_selector);
        eth_abi::encode_u64(&mut packed, dest_chain_selector);
        eth_abi::encode_address(&mut packed, on_ramp_address);
        hash::keccak256(&packed)
    }

    fun calculate_message_hash(
        message: &Sui2AnyRampMessage, metadata_hash: vector<u8>
    ): vector<u8> {
        let mut outer_hash = vector[];
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, merkle_proof::leaf_domain_separator());
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, metadata_hash);

        let mut inner_hash = vector[];
        eth_abi::encode_address(&mut inner_hash, message.sender);
        eth_abi::encode_u64(&mut inner_hash, message.header.sequence_number);
        eth_abi::encode_u64(&mut inner_hash, message.header.nonce);
        eth_abi::encode_address(&mut inner_hash, message.fee_token);
        eth_abi::encode_u64(&mut inner_hash, message.fee_token_amount);
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&inner_hash));

        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, hash::keccak256(&message.receiver)
        );
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&message.data));

        let mut token_hash = vector[];
        eth_abi::encode_u256(&mut token_hash, message.token_amounts.length() as u256);
        message.token_amounts.do_ref!(
            |token_transfer| {
                let token_transfer: &Sui2AnyTokenTransfer = token_transfer;
                eth_abi::encode_address(
                    &mut token_hash, token_transfer.source_pool_address
                );
                eth_abi::encode_bytes(&mut token_hash, token_transfer.dest_token_address);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.extra_data);
                eth_abi::encode_u64(&mut token_hash, token_transfer.amount);
                eth_abi::encode_bytes(&mut token_hash, token_transfer.dest_exec_data);
            }
        );
        eth_abi::encode_right_padded_bytes32(&mut outer_hash, hash::keccak256(&token_hash));

        eth_abi::encode_right_padded_bytes32(
            &mut outer_hash, hash::keccak256(&message.extra_args)
        );

        hash::keccak256(&outer_hash)
    }

    public fun ccip_send<T>(
        ref: &mut CCIPObjectRef,
        state: &mut OnRampState,
        clock: &Clock,
        receiver: vector<u8>,
        data: vector<u8>,
        token_params: dd::TokenParams,
        fee_token_metadata: &CoinMetadata<T>,
        fee_token: &mut Coin<T>,
        extra_args: vector<u8>,
        ctx: &mut TxContext
    ): vector<u8> {
        // get_fee_internal will check curse status
        let fee_token_metadata_addr = object::id_to_address(object::borrow_id(fee_token_metadata));

        // the hot potato is returned and consumed
        let (dest_chain_selector, params) = dd::deconstruct_token_params(state.source_transfer_cap.borrow(), token_params);

        let mut token_amounts = vector[];
        let mut source_tokens = vector[];
        let mut dest_tokens = vector[];
        let mut dest_pool_datas = vector[];
        let mut token_transfers = vector[];
        let mut i = 0;
        let tokens_len = params.length();

        while (i < tokens_len) {
            let (source_pool, amount, source_token_address, dest_token_address, extra_data) = dd::get_source_token_transfer_data(params[i]);
            assert!(amount > 0, ECannotSendZeroTokens);
            token_transfers.push_back(
                Sui2AnyTokenTransfer {
                    source_pool_address: source_pool,
                    amount,
                    dest_token_address,
                    extra_data: extra_data, // encoded decimals
                    dest_exec_data: vector[] // destination execution gas amount, populated later by fee quoter
                }
            );
            token_amounts.push_back(amount);
            source_tokens.push_back(source_token_address);
            dest_tokens.push_back(dest_token_address);
            dest_pool_datas.push_back(extra_data);

            i = i + 1;
        };

        let fee_token_amount =
            get_fee_internal(
                ref,
                clock,
                dest_chain_selector,
                receiver,
                data,
                source_tokens,
                token_amounts,
                fee_token_metadata_addr,
                extra_args,
            );

        let fee_token_balance = balance::value(coin::balance(fee_token));
        if (fee_token_amount != 0) {
            assert!(
                fee_token_amount <= fee_token_balance,
                EUnexpectedWithdrawAmount
            );
            let paid = coin::split(fee_token, fee_token_amount, ctx);

            if (state.fee_tokens.contains(fee_token_metadata_addr)) {
                let coins: &mut Coin<T> = bag::borrow_mut(&mut state.fee_tokens, fee_token_metadata_addr);
                coins.join(paid);
            } else {
                state.fee_tokens.add(fee_token_metadata_addr, paid);
            };
            // if overpaying, onramp will only take out the amount it needs, leaving the fee token object with the remaining balance
        };
        // if fee_token_amount is 0, the fee_token object is returned to the sender unchanged.

        let sender = ctx.sender();
        verify_sender(state, dest_chain_selector, sender);

        let sequence_number = get_incremented_sequence_number(state, dest_chain_selector);

        let (
            fee_value_juels,
            is_out_of_order_execution,
            converted_extra_args,
            mut dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                ref,
                dest_chain_selector,
                fee_token_metadata_addr,
                fee_token_amount,
                extra_args,
                source_tokens,
                dest_tokens,
                dest_pool_datas
            );

        token_transfers.zip_do_mut!(
            &mut dest_exec_data_per_token,
            |token_amount, dest_exec_data| {
                let token_amount: &mut Sui2AnyTokenTransfer = token_amount;
                token_amount.dest_exec_data = *dest_exec_data;
            }
        );

        let message = construct_message(
            ref,
            state,
            dest_chain_selector,
            is_out_of_order_execution,
            sender,
            sequence_number,
            data,
            receiver,
            converted_extra_args,
            fee_token_metadata_addr,
            fee_token_amount,
            fee_value_juels,
            token_transfers,
            ctx
        );

        event::emit(CCIPMessageSent { dest_chain_selector, sequence_number, message });

        message.header.message_id
    }

    fun verify_sender(state: &OnRampState, dest_chain_selector: u64, sender: address) {
        assert!(
            state.dest_chain_configs.contains(dest_chain_selector),
            EUnknownDestChainSelector
        );

        let dest_chain_config = &state.dest_chain_configs[dest_chain_selector];
        assert!(dest_chain_config.is_enabled, EDestChainNotEnabled);

        if (dest_chain_config.allowlist_enabled) {
            assert!(
                dest_chain_config.allowed_senders.contains(&sender),
                ESenderNotAllowed
            );
        };
    }

    fun get_incremented_sequence_number(
        state: &mut OnRampState, dest_chain_selector: u64
    ): u64 {
        let dest_chain_config = state.dest_chain_configs.borrow_mut(dest_chain_selector);
        dest_chain_config.sequence_number = dest_chain_config.sequence_number + 1;

        dest_chain_config.sequence_number
    }

    fun construct_message(
        ref: &mut CCIPObjectRef,
        state: &OnRampState,
        dest_chain_selector: u64,
        is_out_of_order_execution: bool,
        sender: address,
        sequence_number: u64,
        data: vector<u8>,
        receiver: vector<u8>,
        converted_extra_args: vector<u8>,
        fee_token_metadata: address,
        fee_token_amount: u64,
        fee_value_juels: u256,
        token_transfers: vector<Sui2AnyTokenTransfer>,
        ctx: &mut TxContext
    ): Sui2AnyRampMessage {
        // calculate nonce
        let mut nonce = 0;
        if (!is_out_of_order_execution) {
            nonce = nonce_manager::get_incremented_outbound_nonce(
                ref,
                state.nonce_manager_cap.borrow(),
                dest_chain_selector,
                sender,
                ctx
            );
        };

        // create message
        let mut message = Sui2AnyRampMessage {
            header: RampMessageHeader {
                // populated on completion
                message_id: vector[],
                source_chain_selector: state.chain_selector,
                dest_chain_selector,
                sequence_number,
                nonce
            },
            sender,
            data,
            receiver,
            extra_args: converted_extra_args,
            fee_token: fee_token_metadata,
            fee_token_amount,
            fee_value_juels,
            token_amounts: token_transfers
        };

        // attach message id
        let metadata_hash = calculate_metadata_hash(state.chain_selector, dest_chain_selector, object::id_to_address(&object::id(state)));
        let message_id = calculate_message_hash(&message, metadata_hash);
        message.header.message_id = message_id;

        message
    }

    public fun get_ccip_package_id(): address {
        @ccip
    }

    // ================================================================
    // |                      CCIP Ownable Functions                    |
    // ================================================================

    public fun owner(state: &OnRampState): address {
        ownable::owner(&state.ownable_state)
    }

    public fun has_pending_transfer(state: &OnRampState): bool {
        ownable::has_pending_transfer(&state.ownable_state)
    }

    public fun pending_transfer_from(state: &OnRampState): Option<address> {
        ownable::pending_transfer_from(&state.ownable_state)
    }

    public fun pending_transfer_to(state: &OnRampState): Option<address> {
        ownable::pending_transfer_to(&state.ownable_state)
    }

    public fun pending_transfer_accepted(state: &OnRampState): Option<bool> {
        ownable::pending_transfer_accepted(&state.ownable_state)
    }

    public entry fun transfer_ownership(
        state: &mut OnRampState,
        owner_cap: &OwnerCap,
        new_owner: address,
        ctx: &mut TxContext,
    ) {
        ownable::transfer_ownership(owner_cap, &mut state.ownable_state, new_owner, ctx);
    }

    public entry fun accept_ownership(
        state: &mut OnRampState,
        ctx: &mut TxContext,
    ) {
        ownable::accept_ownership(&mut state.ownable_state, ctx);
    }

    public fun accept_ownership_from_object(
        state: &mut OnRampState,
        from: &mut UID,
        ctx: &mut TxContext,
    ) {
        ownable::accept_ownership_from_object(&mut state.ownable_state, from, ctx);
    }

    public fun execute_ownership_transfer(
        owner_cap: OwnerCap,
        ownable_state: &mut OwnableState,
        to: address,
        ctx: &mut TxContext,
    ) {
        ownable::execute_ownership_transfer(owner_cap, ownable_state, to, ctx);
    }

    public fun mcms_register_entrypoint(
        registry: &mut Registry,
        state: &mut OnRampState,
        owner_cap: OwnerCap,
        mcms: address,
        ctx: &mut TxContext,
    ) {
        ownable::set_owner(&owner_cap, &mut state.ownable_state, mcms, ctx);

        mcms_registry::register_entrypoint(
            registry,
            McmsCallback {},
            option::some(owner_cap),
            ctx,
        );
    }

    public fun mcms_register_upgrade_cap(
        upgrade_cap: UpgradeCap,
        registry: &mut Registry,
        state: &mut DeployerState,
        ctx: &mut TxContext,
    ) {
        mcms_deployer::register_upgrade_cap(
            state,
            registry,
            upgrade_cap,
            ctx,
        );
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    public struct McmsCallback has drop {}

    public fun mcms_entrypoint(
        state: &mut OnRampState,
        registry: &mut Registry,
        params: ExecutingCallbackParams, // hot potato
        ctx: &mut TxContext,
    ) {
        let (owner_cap, function, data) = mcms_registry::get_callback_params<
            McmsCallback,
            OwnerCap,
        >(
            registry,
            McmsCallback {},
            params,
        );

        let function_bytes = *function.as_bytes();
        let mut stream = bcs_stream::new(data);

        if (function_bytes == b"set_dynamic_config") {
            let fee_aggregator = bcs_stream::deserialize_address(&mut stream);
            let allowlist_admin = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_dynamic_config(state, owner_cap, fee_aggregator, allowlist_admin);
        } else if (function_bytes == b"apply_dest_chain_config_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_enabled =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            apply_dest_chain_config_updates(state, owner_cap, dest_chain_selectors, dest_chain_enabled, dest_chain_allowlist_enabled);
        } else if (function_bytes == b"apply_allowlist_updates") {
            let dest_chain_selectors =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_u64(stream)
                );
            let dest_chain_allowlist_enabled =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_bool(stream)
                );
            let dest_chain_add_allowed_senders =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector!(
                        stream,
                        |stream| bcs_stream::deserialize_address(stream)
                    )
                );
            let dest_chain_remove_allowed_senders =
                bcs_stream::deserialize_vector!(
                    &mut stream,
                    |stream| bcs_stream::deserialize_vector!(
                        stream,
                        |stream| bcs_stream::deserialize_address(stream)
                    )
                );
            apply_allowlist_updates(state, owner_cap, dest_chain_selectors, dest_chain_allowlist_enabled, dest_chain_add_allowed_senders, dest_chain_remove_allowed_senders, ctx);
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            transfer_ownership(state, owner_cap, to, ctx);
        } else if (function_bytes == b"accept_ownership_as_mcms") {
            // TODO: This may not be needed as we call `mcms_registry::register_entrypoint` with the `OwnerCap`
            let mcms = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            ownable::accept_ownership_as_mcms(&mut state.ownable_state, mcms, ctx);
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            let owner_cap = mcms_registry::release_cap(registry, McmsCallback {});
            execute_ownership_transfer(owner_cap, &mut state.ownable_state, to , ctx);
        } else {
            abort EUnknownFunction
        };
    }

    // ============================== Test Functions ============================== //

    #[test_only]
    public fun test_init(ctx: &mut TxContext) {
        init(ONRAMP{}, ctx);
    }
}
