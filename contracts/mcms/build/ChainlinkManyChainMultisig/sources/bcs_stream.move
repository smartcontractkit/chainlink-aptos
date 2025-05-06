/// BCS stream utility module for MCMS
module chainlink_mcms::bcs_stream {
    use std::vector;
    
    struct BCSStream has drop {
        data: vector<u8>,
        cursor: u64
    }
    
    public fun new(data: vector<u8>): BCSStream {
        BCSStream { data, cursor: 0 }
    }
    
    public fun cursor(stream: &BCSStream): u64 {
        stream.cursor
    }
    
    public fun set_cursor(stream: &mut BCSStream, cursor: u64) {
        stream.cursor = cursor;
    }
    
    public fun peek_byte(stream: &BCSStream): u8 {
        *vector::borrow(&stream.data, stream.cursor)
    }
    
    public fun read_byte(stream: &mut BCSStream): u8 {
        let b = peek_byte(stream);
        stream.cursor = stream.cursor + 1;
        b
    }
    
    public fun read_bytes(stream: &mut BCSStream, len: u64): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        while (i < len) {
            vector::push_back(&mut result, read_byte(stream));
            i = i + 1;
        };
        result
    }
    
    public fun read_u16(stream: &mut BCSStream): u16 {
        let bytes = read_bytes(stream, 2);
        // Conversion logic assuming little-endian
        (((*vector::borrow(&bytes, 1) as u16) << 8) | (*vector::borrow(&bytes, 0) as u16))
    }
    
    public fun read_u32(stream: &mut BCSStream): u32 {
        let bytes = read_bytes(stream, 4);
        // Conversion logic assuming little-endian
        (((*vector::borrow(&bytes, 3) as u32) << 24) | 
         ((*vector::borrow(&bytes, 2) as u32) << 16) | 
         ((*vector::borrow(&bytes, 1) as u32) << 8) | 
         (*vector::borrow(&bytes, 0) as u32))
    }
    
    public fun read_u64(stream: &mut BCSStream): u64 {
        let bytes = read_bytes(stream, 8);
        // Conversion logic assuming little-endian
        (((*vector::borrow(&bytes, 7) as u64) << 56) | 
         ((*vector::borrow(&bytes, 6) as u64) << 48) | 
         ((*vector::borrow(&bytes, 5) as u64) << 40) | 
         ((*vector::borrow(&bytes, 4) as u64) << 32) |
         ((*vector::borrow(&bytes, 3) as u64) << 24) | 
         ((*vector::borrow(&bytes, 2) as u64) << 16) | 
         ((*vector::borrow(&bytes, 1) as u64) << 8) | 
         (*vector::borrow(&bytes, 0) as u64))
    }
    
    public fun read_u128(stream: &mut BCSStream): u128 {
        let bytes = read_bytes(stream, 16);
        // Conversion logic assuming little-endian
        (((*vector::borrow(&bytes, 15) as u128) << 120) | 
         ((*vector::borrow(&bytes, 14) as u128) << 112) | 
         ((*vector::borrow(&bytes, 13) as u128) << 104) | 
         ((*vector::borrow(&bytes, 12) as u128) << 96) |
         ((*vector::borrow(&bytes, 11) as u128) << 88) | 
         ((*vector::borrow(&bytes, 10) as u128) << 80) | 
         ((*vector::borrow(&bytes, 9) as u128) << 72) | 
         ((*vector::borrow(&bytes, 8) as u128) << 64) |
         ((*vector::borrow(&bytes, 7) as u128) << 56) | 
         ((*vector::borrow(&bytes, 6) as u128) << 48) | 
         ((*vector::borrow(&bytes, 5) as u128) << 40) | 
         ((*vector::borrow(&bytes, 4) as u128) << 32) |
         ((*vector::borrow(&bytes, 3) as u128) << 24) | 
         ((*vector::borrow(&bytes, 2) as u128) << 16) | 
         ((*vector::borrow(&bytes, 1) as u128) << 8) | 
         (*vector::borrow(&bytes, 0) as u128))
    }
    
    public fun read_u256(stream: &mut BCSStream): u256 {
        let bytes = read_bytes(stream, 32);
        // Convert 32 bytes to u256
        // First 16 bytes for lower, last 16 bytes for upper (little-endian)
        let lower = 0u128;
        let upper = 0u128;
        
        // Read lower 16 bytes (little-endian)
        let i = 0;
        while (i < 16) {
            lower = lower | ((*vector::borrow(&bytes, i) as u128) << ((i * 8) as u8));
            i = i + 1;
        };
        
        // Read upper 16 bytes (little-endian)
        let i = 0;
        while (i < 16) {
            upper = upper | ((*vector::borrow(&bytes, i + 16) as u128) << ((i * 8) as u8));
            i = i + 1;
        };
        
        // Combine into u256
        ((upper as u256) << 128) | (lower as u256)
    }
    
    public fun read_bool(stream: &mut BCSStream): bool {
        read_byte(stream) != 0
    }
    
    public fun read_address(stream: &mut BCSStream): address {
        let _bytes = read_bytes(stream, 32);
        // Convert bytes to address - simplified implementation
        // In a real implementation, we would convert the bytes to an address
        @0x0
    }
    
    public fun read_string(stream: &mut BCSStream): vector<u8> {
        let len = read_uleb128(stream);
        read_bytes(stream, len)
    }
    
    public fun read_uleb128(stream: &mut BCSStream): u64 {
        let value: u64 = 0;
        let shift: u8 = 0;
        
        loop {
            let byte = read_byte(stream);
            value = value | (((byte & 0x7f) as u64) << shift);
            if ((byte & 0x80) == 0) {
                break
            };
            shift = shift + 7;
        };
        
        value
    }
}
