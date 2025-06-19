module lock_release_token_pool::lock_release_token_pool;

use std::string::{Self, String};
use std::type_name::{Self, TypeName};

use sui::bag::{Self, Bag};
use sui::clock::Clock;
use sui::coin::{Self, Coin, CoinMetadata, TreasuryCap};

use ccip::dynamic_dispatcher as dd;
use ccip::eth_abi;
use ccip::offramp_state_helper as osh;
use ccip::state_object::CCIPObjectRef;
use ccip::token_admin_registry;

use ccip_token_pool::token_pool::{Self, TokenPoolState};

public struct OwnerCap has key, store {
    id: UID,
    state_id: ID,
}

// TODO: ownership model
public struct LockReleaseTokenPoolState has key {
    id: UID,
    // ownable_state: ownable::OwnableState,
    token_pool_state: TokenPoolState,
    coin_store: Bag, // use Bag to avoid type param, but it's also trivial to use a single Coin<T>
    rebalancer: address,
}

const COIN_STORE: vector<u8> = b"CoinStore";

const EInvalidCoinMetadata: u64 = 1;
const EInvalidArguments: u64 = 2;
const ETokenPoolBalanceTooLow: u64 = 3;
const EUnauthorized: u64 = 4;
const EInvalidOwnerCap: u64 = 5;

// ================================================================
// |                             Init                             |
// ================================================================

public fun type_and_version(): String {
    string::utf8(b"LockReleaseTokenPool 1.6.0")
}

public fun initialize<T: drop>(
    ref: &mut CCIPObjectRef,
    coin_metadata: &CoinMetadata<T>,
    treasury_cap: &TreasuryCap<T>,
    token_pool_package_id: address,
    token_pool_administrator: address,
    rebalancer: address,
    ctx: &mut TxContext,
) {
    let (_, token_pool_state_address, _, _) =
        initialize_internal(coin_metadata, rebalancer, ctx);

    token_admin_registry::register_pool(
        ref,
        treasury_cap,
        coin_metadata,
        token_pool_package_id,
        token_pool_state_address,
        string::utf8(b"lock_release_token_pool"),
        token_pool_administrator,
        TypeProof {},
    );
}

public fun initialize_by_ccip_admin<T: drop>(
    ref: &mut CCIPObjectRef,
    coin_metadata: &CoinMetadata<T>,
    token_pool_package_id: address,
    token_pool_administrator: address,
    rebalancer: address,
    ctx: &mut TxContext,
) {
    let (coin_metadata_address, token_pool_state_address, token_type_name, type_proof_type_name) =
        initialize_internal(coin_metadata, rebalancer, ctx);

    token_admin_registry::register_pool_by_admin(
        ref,
        coin_metadata_address,
        token_pool_package_id,
        token_pool_state_address,
        string::utf8(b"lock_release_token_pool"),
        token_type_name.into_string(),
        token_pool_administrator,
        type_proof_type_name.into_string(),
        ctx,
    );
}

#[allow(lint(self_transfer))]
fun initialize_internal<T: drop>(
    coin_metadata: &CoinMetadata<T>,
    rebalancer: address,
    ctx: &mut TxContext,
): (address, address, TypeName, TypeName) {
    let coin_metadata_address: address = object::id_to_address(&object::id(coin_metadata));
    assert!(
        coin_metadata_address == @lock_release_token_coin_metadata,
        EInvalidCoinMetadata
    );

    let mut lock_release_token_pool = LockReleaseTokenPoolState {
        id: object::new(ctx),
        token_pool_state: token_pool::initialize(coin_metadata_address, coin_metadata.get_decimals(), vector[], ctx),
        coin_store: bag::new(ctx),
        rebalancer: @0x0,
    };
    set_rebalancer_internal(&mut lock_release_token_pool, rebalancer);
    lock_release_token_pool.coin_store.add(COIN_STORE, coin::zero<T>(ctx));
    let token_type_name = type_name::get<T>();
    let type_proof_type_name = type_name::get<TypeProof>();
    let token_pool_state_address = object::uid_to_address(&lock_release_token_pool.id);

    let owner_cap = OwnerCap {
        id: object::new(ctx),
        state_id: object::id(&lock_release_token_pool),
    };

    transfer::share_object(lock_release_token_pool);
    transfer::transfer(owner_cap, ctx.sender());

    (coin_metadata_address, token_pool_state_address, token_type_name, type_proof_type_name)
}

// ================================================================
// |                 Exposing token_pool functions                |
// ================================================================

// this now returns the address of coin metadata
public fun get_token(state: &LockReleaseTokenPoolState): address {
    token_pool::get_token(&state.token_pool_state)
}

public fun get_router(): address {
    token_pool::get_router()
}

public fun get_token_decimals(state: &LockReleaseTokenPoolState): u8 {
    state.token_pool_state.get_local_decimals()
}

public fun get_remote_pools(
    state: &LockReleaseTokenPoolState,
    remote_chain_selector: u64
): vector<vector<u8>> {
    token_pool::get_remote_pools(&state.token_pool_state, remote_chain_selector)
}

public fun is_remote_pool(
    state: &LockReleaseTokenPoolState,
    remote_chain_selector: u64,
    remote_pool_address: vector<u8>
): bool {
    token_pool::is_remote_pool(
        &state.token_pool_state,
        remote_chain_selector,
        remote_pool_address
    )
}

public fun get_remote_token(
    state: &LockReleaseTokenPoolState, remote_chain_selector: u64
): vector<u8> {
    token_pool::get_remote_token(&state.token_pool_state, remote_chain_selector)
}

public fun add_remote_pool(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    remote_chain_selector: u64,
    remote_pool_address: vector<u8>,
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    token_pool::add_remote_pool(
        &mut state.token_pool_state, remote_chain_selector, remote_pool_address
    );
}

public fun remove_remote_pool(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    remote_chain_selector: u64,
    remote_pool_address: vector<u8>,
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    token_pool::remove_remote_pool(
        &mut state.token_pool_state, remote_chain_selector, remote_pool_address
    );
}

public fun is_supported_chain(
    state: &LockReleaseTokenPoolState,
    remote_chain_selector: u64
): bool {
    token_pool::is_supported_chain(&state.token_pool_state, remote_chain_selector)
}

public fun get_supported_chains(state: &LockReleaseTokenPoolState): vector<u64> {
    token_pool::get_supported_chains(&state.token_pool_state)
}

public fun apply_chain_updates(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    remote_chain_selectors_to_remove: vector<u64>,
    remote_chain_selectors_to_add: vector<u64>,
    remote_pool_addresses_to_add: vector<vector<vector<u8>>>,
    remote_token_addresses_to_add: vector<vector<u8>>
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    token_pool::apply_chain_updates(
        &mut state.token_pool_state,
        remote_chain_selectors_to_remove,
        remote_chain_selectors_to_add,
        remote_pool_addresses_to_add,
        remote_token_addresses_to_add
    );
}

public fun get_allowlist_enabled(state: &LockReleaseTokenPoolState): bool {
    token_pool::get_allowlist_enabled(&state.token_pool_state)
}

public fun get_allowlist(state: &LockReleaseTokenPoolState): vector<address> {
    token_pool::get_allowlist(&state.token_pool_state)
}

public fun apply_allowlist_updates(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    removes: vector<address>,
    adds: vector<address>
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    token_pool::apply_allowlist_updates(&mut state.token_pool_state, removes, adds);
}

// ================================================================
// |                         Burn/Mint                            |
// ================================================================

public struct TypeProof has drop {}

public fun lock_or_burn<T>(
    ref: &CCIPObjectRef,
    clock: &Clock,
    state: &mut LockReleaseTokenPoolState,
    c: Coin<T>,
    token_params: dd::TokenParams,
    ctx: &mut TxContext
): dd::TokenParams {
    let amount = c.value();
    let sender = ctx.sender();
    let remote_chain_selector = dd::get_destination_chain_selector(&token_params);

    // This metod validates various aspects of the lock or burn operation. If any of the
    // validations fail, the transaction will abort.
    let dest_token_address =
        token_pool::validate_lock_or_burn(
            ref,
            clock,
            &mut state.token_pool_state,
            sender,
            remote_chain_selector,
            amount,
        );

    let stored_coin: &mut Coin<T> = state.coin_store.borrow_mut(COIN_STORE);
    stored_coin.join(c);

    let mut extra_data = vector[];
    eth_abi::encode_u8(&mut extra_data, state.token_pool_state.get_local_decimals());

    token_pool::emit_locked_or_burned(&mut state.token_pool_state, amount, remote_chain_selector);

    // update hot potato token params
    dd::add_source_token_transfer(
        ref,
        token_params,
        amount,
        state.token_pool_state.get_token(),
        dest_token_address,
        extra_data,
        TypeProof {},
    )
}

public fun release_or_mint<T>(
    ref: &CCIPObjectRef,
    clock: &Clock,
    pool: &mut LockReleaseTokenPoolState,
    receiver_params: osh::ReceiverParams,
    index: u64,
    ctx: &mut TxContext
): osh::ReceiverParams {
    let remote_chain_selector = osh::get_source_chain_selector(&receiver_params);
    let (receiver, source_amount, dest_token_address, source_pool_address, source_pool_data, _) = osh::get_token_param_data(&receiver_params, index);
    let local_decimals = pool.token_pool_state.get_local_decimals();
    let remote_decimals = token_pool::parse_remote_decimals(source_pool_data, local_decimals);
    let local_amount = token_pool::calculate_local_amount(source_amount as u256, remote_decimals, local_decimals);

    token_pool::validate_release_or_mint(
        ref,
        clock,
        &mut pool.token_pool_state,
        remote_chain_selector,
        dest_token_address,
        source_pool_address,
        local_amount
    );

    // split the coin to be released
    let stored_coin: &mut Coin<T> = pool.coin_store.borrow_mut(COIN_STORE);
    assert!(
        stored_coin.value() >= local_amount,
        ETokenPoolBalanceTooLow
    );
    let c: Coin<T> = stored_coin.split(local_amount, ctx);

    token_pool::emit_released_or_minted(
        &mut pool.token_pool_state,
        receiver,
        local_amount,
        remote_chain_selector,
    );

    osh::complete_token_transfer_new(
        ref,
        receiver_params,
        index,
        c,
        TypeProof {},
    )
}

// ================================================================
// |                    Rate limit config                         |
// ================================================================

public fun set_chain_rate_limiter_configs(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    clock: &Clock,
    remote_chain_selectors: vector<u64>,
    outbound_is_enableds: vector<bool>,
    outbound_capacities: vector<u64>,
    outbound_rates: vector<u64>,
    inbound_is_enableds: vector<bool>,
    inbound_capacities: vector<u64>,
    inbound_rates: vector<u64>
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    let number_of_chains = remote_chain_selectors.length();

    assert!(
        number_of_chains == outbound_is_enableds.length()
            && number_of_chains == outbound_capacities.length()
            && number_of_chains == outbound_rates.length()
            && number_of_chains == inbound_is_enableds.length()
            && number_of_chains == inbound_capacities.length()
            && number_of_chains == inbound_rates.length(),
        EInvalidArguments
    );

    let mut i = 0;
    while (i < number_of_chains) {
        token_pool::set_chain_rate_limiter_config(
            clock,
            &mut state.token_pool_state,
            remote_chain_selectors[i],
            outbound_is_enableds[i],
            outbound_capacities[i],
            outbound_rates[i],
            inbound_is_enableds[i],
            inbound_capacities[i],
            inbound_rates[i]
        );
        i = i + 1;
    };
}

public fun set_chain_rate_limiter_config(
    state: &mut LockReleaseTokenPoolState,
    owner_cap: &OwnerCap,
    clock: &Clock,
    remote_chain_selector: u64,
    outbound_is_enabled: bool,
    outbound_capacity: u64,
    outbound_rate: u64,
    inbound_is_enabled: bool,
    inbound_capacity: u64,
    inbound_rate: u64
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    token_pool::set_chain_rate_limiter_config(
        clock,
        &mut state.token_pool_state,
        remote_chain_selector,
        outbound_is_enabled,
        outbound_capacity,
        outbound_rate,
        inbound_is_enabled,
        inbound_capacity,
        inbound_rate
    );
}

// ================================================================
// |                    Liquidity Management                      |
// ================================================================

public fun provide_liquidity<T>(
    state: &mut LockReleaseTokenPoolState,
    c: Coin<T>,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == state.rebalancer, EUnauthorized);
    let amount = c.value();

    let stored_coin: &mut Coin<T> = state.coin_store.borrow_mut(COIN_STORE);
    stored_coin.join(c);

    token_pool::emit_liquidity_added(
        &mut state.token_pool_state, state.rebalancer, amount
    );
}

public fun withdraw_liquidity<T>(
    state: &mut LockReleaseTokenPoolState,
    amount: u64,
    ctx: &mut TxContext,
): Coin<T> {
    assert!(ctx.sender() == state.rebalancer, EUnauthorized);

    let stored_coin: &mut Coin<T> = state.coin_store.borrow_mut(COIN_STORE);
    assert!(stored_coin.value() >= amount, ETokenPoolBalanceTooLow);

    token_pool::emit_liquidity_removed(&mut state.token_pool_state, state.rebalancer, amount);
    stored_coin.split(amount, ctx)
}

public fun set_rebalancer(
    owner_cap: &OwnerCap,
    state: &mut LockReleaseTokenPoolState,
    rebalancer: address,
) {
    assert!(owner_cap.state_id == object::id(state), EInvalidOwnerCap);
    set_rebalancer_internal(state, rebalancer);
}

fun set_rebalancer_internal(
    state: &mut LockReleaseTokenPoolState,
    rebalancer: address,
) {
    token_pool::emit_rebalancer_set(
        &mut state.token_pool_state,
        state.rebalancer,
        rebalancer,
    );
    state.rebalancer = rebalancer;
}

public fun get_rebalancer(state: &LockReleaseTokenPoolState): address {
    state.rebalancer
}

public fun get_balance<T>(state: &LockReleaseTokenPoolState): u64 {
    let stored_coin: &Coin<T> = state.coin_store.borrow(COIN_STORE);
    stored_coin.value()
}

// destroy the lock release token pool state and the owner cap, return the remaining balance to the owner
// this should only be called after unregistering the pool from the token admin registry
public fun destroy_token_pool<T>(
    state: LockReleaseTokenPoolState,
    owner_cap: OwnerCap,
    _ctx: &mut TxContext,
): Coin<T> {
    assert!(owner_cap.state_id == object::id(&state), EInvalidOwnerCap);

    let LockReleaseTokenPoolState {
        id: state_id,
        token_pool_state,
        mut coin_store,
        rebalancer: _,
    } = state;
    token_pool::destroy_token_pool(token_pool_state);
    object::delete(state_id);

    let OwnerCap {
        id: owner_cap_id,
        state_id: _,
    } = owner_cap;
    object::delete(owner_cap_id);

    let c: Coin<T> = coin_store.remove(COIN_STORE);
    coin_store.destroy_empty();

    c
}
