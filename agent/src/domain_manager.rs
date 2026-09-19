use crate::utils::hash::xxh64_hash;
use anyhow::{Result, anyhow};
use log::info;
use std::collections::HashMap;
use std::path::Path;

pub struct DomainManager {
    domains: HashMap<u64, String>,
}

fn encode_dns_qname(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(domain.len() + 1);
    for label in domain.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded
}

impl DomainManager {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u64>> {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read domains file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        let mut hashes = Vec::new();
        self.domains.clear();

        for line in content.lines() {
            let domain = line.trim();
            if domain.is_empty() || domain.starts_with('#') {
                continue;
            }

            let wire_form = encode_dns_qname(domain);
            let hash = xxh64_hash(&wire_form);
            self.domains.insert(hash, domain.to_string());
            hashes.push(hash);
        }

        info!(
            "DomainManager: loaded {} domains from file",
            self.domains.len()
        );
        Ok(hashes)
    }

    pub fn get_domain_name(&self, hash: u64) -> Option<&String> {
        self.domains.get(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_dns_qname_matches_wire_format() {
        assert_eq!(
            encode_dns_qname("google.com"),
            vec![6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm']
        );
    }

    #[test]
    fn hash_of_wire_format_differs_from_hash_of_plain_string() {
        let plain_hash = xxh64_hash("google.com".as_bytes());
        let wire_hash = xxh64_hash(&encode_dns_qname("google.com"));
        assert_ne!(plain_hash, wire_hash);
        assert_eq!(wire_hash, 0xc61aac2d962ef56e);
    }

    #[test]
    fn load_from_file_computes_wire_format_hash() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().expect("tmp file");
        writeln!(file, "# comment, should be skipped").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "google.com").unwrap();

        let mut mgr = DomainManager::new();
        let hashes = mgr.load_from_file(file.path()).expect("load ok");

        assert_eq!(hashes, vec![0xc61aac2d962ef56e]);
        assert_eq!(
            mgr.get_domain_name(0xc61aac2d962ef56e),
            Some(&"google.com".to_string())
        );
    }
}
