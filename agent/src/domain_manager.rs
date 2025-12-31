use crate::utils::hash::xxh64_hash;
use anyhow::{Result, anyhow};
use log::info;
use std::collections::HashMap;
use std::path::Path;

pub struct DomainManager {
    domains: HashMap<u64, String>,
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

            let hash = xxh64_hash(domain.as_bytes());
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
