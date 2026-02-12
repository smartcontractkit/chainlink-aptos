module test::counter {
    struct Counter has key, store, drop {
        value: u64
    }

    public entry fun initialize(account: &signer) {
        move_to(account, Counter { value: 0 });
    }

    public entry fun increment(_account: &signer, counter_address: address) acquires Counter {
        let counter = borrow_global_mut<Counter>(counter_address);
        counter.value = counter.value + 1;
    }

    public entry fun increment_mult(
        _account: &signer, counter_address: address, a: u64, b: u64
    ) acquires Counter {
        let counter = borrow_global_mut<Counter>(counter_address);
        counter.value = counter.value + (a * b);
    }
}
