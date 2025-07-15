module mcms::params {
    use std::bcs;

    const E_CMP_VECTORS_DIFF_LEN: u64 = 1;
    const E_INPUT_TOO_LARGE_FOR_NUM_BYTES: u64 = 2;

    public inline fun encode_uint<T: drop>(input: T, num_bytes: u64): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&input);

        let len = bcs_bytes.length();
        assert!(len <= num_bytes, E_INPUT_TOO_LARGE_FOR_NUM_BYTES);

        if (len < num_bytes) {
            let bytes_to_pad = num_bytes - len;
            for (i in 0..bytes_to_pad) {
                bcs_bytes.push_back(0);
            };
        };

        // little endian to big endian
        bcs_bytes.reverse();

        bcs_bytes
    }

    public inline fun right_pad_vec(v: &mut vector<u8>, num_bytes: u64) {
        let len = v.length();
        if (len < num_bytes) {
            let bytes_to_pad = num_bytes - len;
            for (i in 0..bytes_to_pad) {
                v.push_back(0);
            };
        };
    }

    /// compares two vectors of equal length, returns true if a > b, false otherwise.
    public fun vector_u8_gt(a: &vector<u8>, b: &vector<u8>): bool {
        let len = a.length();
        assert!(len == b.length(), E_CMP_VECTORS_DIFF_LEN);

        if (len == 0) {
            return false
        };

        // compare each byte until not equal
        for (i in 0..len) {
            let byte_a = a[i];
            let byte_b = b[i];
            if (byte_a > byte_b) {
                return true
            } else if (byte_a < byte_b) {
                return false
            };
        };

        // vectors are equal, a == b
        false
    }
}
