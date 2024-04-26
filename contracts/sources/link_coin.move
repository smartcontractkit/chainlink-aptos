module chainlink::link_coin {
    use std::managed_coin;
    use std::signer;

    struct LinkCoin has key {}

    // TODO: simple coin module - update this.
    fun init_module(resource_account: &signer) {
        managed_coin::initialize<LinkCoin>(
            resource_account,
            b"Chainlink Coin",
            b"LINK",
            8, // decimals - defaulting to 8 as per AptosCoin
            true, // monitor_supply
        );

        managed_coin::register<LinkCoin>(resource_account);

        // TODO: this mints an arbitrary amount of coin.
        managed_coin::mint<LinkCoin>(resource_account, signer::address_of(resource_account), 1000000);
    }
}
