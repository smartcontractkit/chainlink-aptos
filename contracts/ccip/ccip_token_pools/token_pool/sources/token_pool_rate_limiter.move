module ccip_token_pool::token_pool_rate_limiter {
    use sui::clock::Clock;
    use sui::event;
    use sui::table::{Self, Table};

    use ccip_token_pool::rate_limiter::{Self, TokenBucket};

    public struct RateLimitState has store {
        outbound_rate_limiter_config: Table<u64, TokenBucket>,
        inbound_rate_limiter_config: Table<u64, TokenBucket>
    }

    public struct TokensConsumed has copy, drop {
        remote_chain_selector: u64,
        tokens: u64
    }

    public struct ConfigChanged has copy, drop {
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    }

    const E_BUCKET_NOT_FOUND: u64 = 1;

    public fun new(ctx: &mut TxContext): RateLimitState {
        RateLimitState {
            outbound_rate_limiter_config: table::new<u64, TokenBucket>(ctx),
            inbound_rate_limiter_config: table::new<u64, TokenBucket>(ctx)
        }
    }

    public fun consume_inbound(
        clock: &Clock, state: &mut RateLimitState, dest_chain_selector: u64, requested_tokens: u64
    ) {
        consume_from_bucket(
            clock,
            &mut state.inbound_rate_limiter_config,
            dest_chain_selector,
            requested_tokens
        );
    }

    public fun consume_outbound(
        clock: &Clock, state: &mut RateLimitState, dest_chain_selector: u64, requested_tokens: u64
    ) {
        consume_from_bucket(
            clock,
            &mut state.outbound_rate_limiter_config,
            dest_chain_selector,
            requested_tokens
        );
    }

    fun consume_from_bucket(
        clock: &Clock,
        rate_limiter: &mut Table<u64, TokenBucket>,
        dest_chain_selector: u64,
        requested_tokens: u64
    ) {
        assert!(
            rate_limiter.contains(dest_chain_selector),
            E_BUCKET_NOT_FOUND
        );

        let bucket = rate_limiter.borrow_mut(dest_chain_selector);
        rate_limiter::consume(clock, bucket, requested_tokens);

        event::emit(
            TokensConsumed {
                remote_chain_selector: dest_chain_selector,
                tokens: requested_tokens
            }
        );
    }

    public fun set_chain_rate_limiter_config(
        clock: &Clock,
        state: &mut RateLimitState,
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    ) {
        if (!state.outbound_rate_limiter_config.contains(remote_chain_selector)) {
            state.outbound_rate_limiter_config.add(
                remote_chain_selector,
                rate_limiter::new(clock, false, 0, 0)
            );
        };
        let outbound_config = state.outbound_rate_limiter_config.borrow_mut(remote_chain_selector);
        rate_limiter::set_token_bucket_config(
            clock,
            outbound_config,
            outbound_is_enabled,
            outbound_capacity,
            outbound_rate
        );

        if (!state.inbound_rate_limiter_config.contains(remote_chain_selector)) {
            state.inbound_rate_limiter_config.add(
                remote_chain_selector,
                rate_limiter::new(clock, false, 0, 0)
            );
        };
        let inbound_config = state.inbound_rate_limiter_config.borrow_mut(remote_chain_selector);
        rate_limiter::set_token_bucket_config(
            clock,
            inbound_config,
            inbound_is_enabled,
            inbound_capacity,
            inbound_rate
        );

        event::emit(
            ConfigChanged {
                remote_chain_selector,
                outbound_is_enabled,
                outbound_capacity,
                outbound_rate,
                inbound_is_enabled,
                inbound_capacity,
                inbound_rate
            }
        );
    }

    public fun destroy_rate_limiter(state: RateLimitState) {
        let RateLimitState {
            outbound_rate_limiter_config,
            inbound_rate_limiter_config
        } = state;

        outbound_rate_limiter_config.drop();
        inbound_rate_limiter_config.drop();
    }
}
