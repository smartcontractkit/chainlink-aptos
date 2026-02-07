module ccip_token_pool::rate_limiter {
    use std::error;
    use std::timestamp;

    struct TokenBucket has store, drop {
        tokens: u64,
        last_updated: u64,
        is_enabled: bool,
        capacity: u64,
        rate: u64
    }

    const E_TOKEN_MAX_CAPACITY_EXCEEDED: u64 = 1;
    const E_TOKEN_RATE_LIMIT_REACHED: u64 = 2;

    public fun new(is_enabled: bool, capacity: u64, rate: u64): TokenBucket {
        TokenBucket {
            tokens: 0,
            last_updated: timestamp::now_seconds(),
            is_enabled,
            capacity,
            rate
        }
    }

    public fun get_current_token_bucket_state(state: &TokenBucket): TokenBucket {
        TokenBucket {
            tokens: calculate_refill(
                state, timestamp::now_seconds() - state.last_updated
            ),
            last_updated: timestamp::now_seconds(),
            is_enabled: state.is_enabled,
            capacity: state.capacity,
            rate: state.rate
        }
    }

    public fun consume(bucket: &mut TokenBucket, requested_tokens: u64) {
        if (!bucket.is_enabled || requested_tokens == 0) { return };

        update_bucket(bucket);

        assert!(
            requested_tokens <= bucket.capacity,
            error::invalid_argument(E_TOKEN_MAX_CAPACITY_EXCEEDED)
        );

        assert!(
            requested_tokens <= bucket.tokens,
            error::invalid_argument(E_TOKEN_RATE_LIMIT_REACHED)
        );

        bucket.tokens -= requested_tokens;
    }

    /// We allow 0 rate and/or 0 capacity rate limits to effectively disable value transfer.
    public fun set_token_bucket_config(
        bucket: &mut TokenBucket, is_enabled: bool, capacity: u64, rate: u64
    ) {
        update_bucket(bucket);

        bucket.tokens = min(bucket.tokens, capacity);
        bucket.capacity = capacity;
        bucket.rate = rate;
        bucket.is_enabled = is_enabled;
    }

    inline fun update_bucket(bucket: &mut TokenBucket) {
        let time_now_seconds = timestamp::now_seconds();
        let time_diff = time_now_seconds - bucket.last_updated;

        if (time_diff > 0) {
            bucket.tokens = calculate_refill(bucket, time_diff);
            bucket.last_updated = time_now_seconds;
        };
    }

    inline fun calculate_refill(bucket: &TokenBucket, time_diff: u64): u64 {
        min(
            bucket.capacity, bucket.tokens + time_diff * bucket.rate
        )
    }

    inline fun min(a: u64, b: u64): u64 {
        if (a > b) b else a
    }
}
