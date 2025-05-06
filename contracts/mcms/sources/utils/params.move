/// Parameters utility module for MCMS
module chainlink_mcms::params {
    use std::vector;
    use std::string::{Self, String};
    
    use chainlink_mcms::bcs_stream::{Self, BCSStream};
    
    struct Params has drop {
        stream: BCSStream
    }
    
    public fun new(data: vector<u8>): Params {
        Params { stream: bcs_stream::new(data) }
    }
    
    public fun read_bool(params: &mut Params): bool {
        bcs_stream::read_bool(&mut params.stream)
    }
    
    public fun read_u8(params: &mut Params): u8 {
        bcs_stream::read_byte(&mut params.stream)
    }
    
    public fun read_u16(params: &mut Params): u16 {
        bcs_stream::read_u16(&mut params.stream)
    }
    
    public fun read_u32(params: &mut Params): u32 {
        bcs_stream::read_u32(&mut params.stream)
    }
    
    public fun read_u64(params: &mut Params): u64 {
        bcs_stream::read_u64(&mut params.stream)
    }
    
    public fun read_u128(params: &mut Params): u128 {
        bcs_stream::read_u128(&mut params.stream)
    }
    
    public fun read_u256(params: &mut Params): u256 {
        bcs_stream::read_u256(&mut params.stream)
    }
    
    public fun read_address(params: &mut Params): address {
        bcs_stream::read_address(&mut params.stream)
    }
    
    public fun read_string(params: &mut Params): String {
        let bytes = bcs_stream::read_string(&mut params.stream);
        string::utf8(bytes)
    }
    
    public fun read_bytes(params: &mut Params): vector<u8> {
        let len = bcs_stream::read_uleb128(&mut params.stream);
        bcs_stream::read_bytes(&mut params.stream, len)
    }
}
