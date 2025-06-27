module ccip::address {

    const EZeroAddressNotAllowed: u64 = 1;

    public fun assert_non_zero_address_vector(addr: &vector<u8>) {
        assert!(!addr.is_empty(), EZeroAddressNotAllowed);

        let is_zero_address = addr.all!(|byte| *byte == 0);
        assert!(!is_zero_address, EZeroAddressNotAllowed);
    }

    public fun assert_non_zero_address(addr: address) {
        assert!(addr != @0x0, EZeroAddressNotAllowed);
    }
}