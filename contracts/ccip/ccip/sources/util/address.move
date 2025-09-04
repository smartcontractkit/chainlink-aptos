module ccip::address {

    const E_ZERO_ADDRESS_NOT_ALLOWED: u64 = 1;

    public fun assert_non_zero_address_vector(addr: &vector<u8>) {
        assert!(!addr.is_empty(), E_ZERO_ADDRESS_NOT_ALLOWED);

        let is_zero_address = addr.all(|byte| *byte == 0);
        assert!(!is_zero_address, E_ZERO_ADDRESS_NOT_ALLOWED);
    }

    public fun assert_non_zero_address(addr: address) {
        assert!(addr != @0x0, E_ZERO_ADDRESS_NOT_ALLOWED);
    }
}
