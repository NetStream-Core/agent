pub const MAX_QUERY_LENGTH: usize = 255;

pub fn xxh64_hash(data: &[u8]) -> u64 {
    let mut hash = 0x9e3779b97f4a7c15u64;
    let prime = 0x100000001b3u64;
    for &byte in data.iter().take(MAX_QUERY_LENGTH) {
        if byte == 0 {
            break;
        }
        hash ^= byte as u64;
        hash = hash.wrapping_mul(prime);
        hash = (hash << 23) | (hash >> 41);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc2b2ae35u64);
    hash ^= hash >> 29;
    hash
}
