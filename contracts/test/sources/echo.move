module test::echo {
    use std::string::String;

    #[view]
    public fun echo_u64(val: u64): u64 {
        val
    }

    #[view]
    public fun echo_u256(val: u256): u256 {
        val
    }

    #[view]
    public fun echo_u32_u64_tuple(val1: u32, val2: u64): (u32, u64) {
        (val1, val2)
    }

    #[view]
    public fun echo_string(val: String): String {
        val
    }

    #[view]
    public fun echo_byte_vector(val: vector<u8>): vector<u8> {
        val
    }

    #[view]
    public fun echo_byte_vector_vector(val: vector<vector<u8>>): vector<vector<u8>> {
        val
    }
}
