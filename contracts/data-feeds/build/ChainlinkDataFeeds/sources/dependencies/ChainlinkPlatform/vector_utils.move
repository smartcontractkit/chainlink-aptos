/// Utility module for vector operations not available in the standard library
module chainlink_platform::vector_utils {
    use std::vector;

    /// Extracts a slice from a vector from start_index (inclusive) to end_index (exclusive)
    public fun slice<T: copy>(v: &vector<T>, start_index: u64, end_index: u64): vector<T> {
        let result = vector::empty<T>();
        let i = start_index;
        
        while (i < end_index && i < vector::length(v)) {
            vector::push_back(&mut result, *vector::borrow(v, i));
            i = i + 1;
        };
        
        result
    }
    
    /// Converts a big-endian byte array to u16
    public fun to_u16_be(data: &vector<u8>): u16 {
        assert!(vector::length(data) >= 2, 0);
        let value = 0u16;
        
        value = value + ((*vector::borrow(data, 0) as u16) << 8);
        value = value + (*vector::borrow(data, 1) as u16);
        
        value
    }
    
    /// Converts a big-endian byte array to u32
    public fun to_u32_be(data: &vector<u8>): u32 {
        assert!(vector::length(data) >= 4, 0);
        let value = 0u32;
        
        value = value + ((*vector::borrow(data, 0) as u32) << 24);
        value = value + ((*vector::borrow(data, 1) as u32) << 16);
        value = value + ((*vector::borrow(data, 2) as u32) << 8);
        value = value + (*vector::borrow(data, 3) as u32);
        
        value
    }
}
