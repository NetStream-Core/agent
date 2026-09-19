const HASH_BASE: u64 = 0x9e3779b97f4a7c15;
const MAX_NAME_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;

fn finalize(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

fn wire_format(name: &str) -> Result<Vec<u8>, &'static str> {
    let name = name.trim();
    let name = name.strip_suffix('.').unwrap_or(name);

    if name.is_empty() {
        return Err("empty domain name");
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err("domain name is longer than 253 bytes");
    }
    if !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("domain name must be printable ASCII without spaces");
    }

    let mut wire = Vec::with_capacity(name.len() + 1);
    for label in name.split('.') {
        if label.is_empty() {
            return Err("domain name has an empty label");
        }
        if label.len() > MAX_LABEL_LENGTH {
            return Err("domain label is longer than 63 bytes");
        }
        wire.push(label.len() as u8);
        wire.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    Ok(wire)
}

pub fn domain_hash(name: &str) -> Result<u64, &'static str> {
    let wire = wire_format(name)?;
    let h = wire.iter().fold(0u64, |h, &b| {
        h.wrapping_mul(HASH_BASE).wrapping_add(b as u64)
    });
    Ok(finalize(h))
}

pub fn normalize(name: &str) -> String {
    let name = name.trim();
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}
