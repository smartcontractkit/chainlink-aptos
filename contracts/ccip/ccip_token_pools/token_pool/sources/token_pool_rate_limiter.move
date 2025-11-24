module ccip_token_pool::token_pool_rate_limiter {
    use std::smart_table;
    use std::smart_table::SmartTable;
    use std::account;
    use std::error;
    use std::event;
    use std::event::EventHandle;

    use ccip_token_pool::rate_limiter;

    struct RateLimitState has store {
        outbound_rate_limiter_config: SmartTable<u64, rate_limiter::TokenBucket>,
        inbound_rate_limiter_config: SmartTable<u64, rate_limiter::TokenBucket>,
        tokens_consumed_events: EventHandle<TokensConsumed>,
        config_changed_events: EventHandle<ConfigChanged>
    }

    #[event]
    struct TokensConsumed has store, drop {
        remote_chain_selector: u64,
        tokens: u64
    }

    #[event]
    struct ConfigChanged has store, drop {
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    }

    const E_BUCKET_NOT_FOUND: u64 = 1;

    public fun new(event_account: &signer): RateLimitState {
        RateLimitState {
            outbound_rate_limiter_config: smart_table::new(),
            inbound_rate_limiter_config: smart_table::new(),
            tokens_consumed_events: account::new_event_handle(event_account),
            config_changed_events: account::new_event_handle(event_account)
        }
    }

    public fun consume_inbound(
        state: &mut RateLimitState, dest_chain_selector: u64, requested_tokens: u64
    ) {
        consume_from_bucket(
            &mut state.tokens_consumed_events,
            &mut state.inbound_rate_limiter_config,
            dest_chain_selector,
            requested_tokens
        );
    }

    public fun consume_outbound(
        state: &mut RateLimitState, dest_chain_selector: u64, requested_tokens: u64
    ) {
        consume_from_bucket(
            &mut state.tokens_consumed_events,
            &mut state.outbound_rate_limiter_config,
            dest_chain_selector,
            requested_tokens
        );
    }

    inline fun consume_from_bucket(
        tokens_consumed_events: &mut EventHandle<TokensConsumed>,
        rate_limiter: &mut SmartTable<u64, rate_limiter::TokenBucket>,
        dest_chain_selector: u64,
        requested_tokens: u64
    ) {
        assert!(
            rate_limiter.contains(dest_chain_selector),
            error::invalid_argument(E_BUCKET_NOT_FOUND)
        );

        let bucket = rate_limiter.borrow_mut(dest_chain_selector);
        rate_limiter::consume(bucket, requested_tokens);

        event::emit_event(
            tokens_consumed_events,
            TokensConsumed {
                remote_chain_selector: dest_chain_selector,
                tokens: requested_tokens
            }
        );
    }

    public fun set_chain_rate_limiter_config(
        state: &mut RateLimitState,
        remote_chain_selector: u64,
        outbound_is_enabled: bool,
        outbound_capacity: u64,
        outbound_rate: u64,
        inbound_is_enabled: bool,
        inbound_capacity: u64,
        inbound_rate: u64
    ) {
        let outbound_config =
            state.outbound_rate_limiter_config.borrow_mut_with_default(
                remote_chain_selector,
                rate_limiter::new(false, 0, 0)
            );
        rate_limiter::set_token_bucket_config(
            outbound_config,
            outbound_is_enabled,
            outbound_capacity,
            outbound_rate
        );

        let inbound_config =
            state.inbound_rate_limiter_config.borrow_mut_with_default(
                remote_chain_selector,
                rate_limiter::new(false, 0, 0)
            );
        rate_limiter::set_token_bucket_config(
            inbound_config,
            inbound_is_enabled,
            inbound_capacity,
            inbound_rate
        );

        event::emit_event(
            &mut state.config_changed_events,
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

    public fun get_current_inbound_rate_limiter_state(
        state: &RateLimitState, remote_chain_selector: u64
    ): rate_limiter::TokenBucket {
        rate_limiter::get_current_token_bucket_state(
            state.inbound_rate_limiter_config.borrow(remote_chain_selector)
        )
    }

    public fun get_current_outbound_rate_limiter_state(
        state: &RateLimitState, remote_chain_selector: u64
    ): rate_limiter::TokenBucket {
        rate_limiter::get_current_token_bucket_state(
            state.outbound_rate_limiter_config.borrow(remote_chain_selector)
        )
    }

    public fun destroy_rate_limiter(state: RateLimitState) {
        let RateLimitState {
            outbound_rate_limiter_config,
            inbound_rate_limiter_config,
            tokens_consumed_events,
            config_changed_events
        } = state;

        outbound_rate_limiter_config.destroy();
        inbound_rate_limiter_config.destroy();
        event::destroy_handle(tokens_consumed_events);
        event::destroy_handle(config_changed_events);
    }
}
