script {
    use aptos_framework::primary_fungible_store;
    use stablecoin::treasury;


    fun mint(caller: &signer, amount: u64, mint_recipient: address) {
        let fa = treasury::mint(caller, amount);
        primary_fungible_store::deposit(mint_recipient, fa);
    }
}
