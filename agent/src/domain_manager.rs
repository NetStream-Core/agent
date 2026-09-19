use crate::utils::hash::{domain_hash, normalize};
use anyhow::{Result, anyhow};
use log::{info, warn};
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
        let mut skipped = 0;
        self.domains.clear();

        for (index, line) in content.lines().enumerate() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }

            let hash = match domain_hash(entry) {
                Ok(hash) => hash,
                Err(reason) => {
                    warn!("Skipping line {}: {} ({:?})", index + 1, reason, entry);
                    skipped += 1;
                    continue;
                }
            };

            let name = normalize(entry);
            match self.domains.get(&hash) {
                Some(existing) if *existing == name => continue,
                Some(existing) => warn!(
                    "Hash collision between {} and {}, keeping the first",
                    existing, name
                ),
                None => {
                    self.domains.insert(hash, name);
                    hashes.push(hash);
                }
            }
        }

        info!(
            "DomainManager: loaded {} domains from file, skipped {} invalid lines",
            self.domains.len(),
            skipped
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
    use std::io::Write;

    const GOOGLE_COM: u64 = 4282548222659472292;
    const COM: u64 = 17442394860103835407;

    fn load(content: &str) -> (DomainManager, Vec<u64>) {
        let mut file = tempfile::NamedTempFile::new().expect("tmp file");
        write!(file, "{content}").unwrap();

        let mut mgr = DomainManager::new();
        let hashes = mgr.load_from_file(file.path()).expect("load ok");
        (mgr, hashes)
    }

    #[test]
    fn hashes_match_the_values_computed_by_the_bpf_code() {
        assert_eq!(domain_hash("google.com"), Ok(GOOGLE_COM));
        assert_eq!(domain_hash("com"), Ok(COM));
    }

    #[test]
    fn suffix_hashes_match_the_values_computed_by_the_bpf_code() {
        let expected = [
            ("example", 2306238607482248458),
            ("blocked-test.example", 10599123911636125748),
            ("sub.blocked-test.example", 3691398819404742162),
            ("www.sub.blocked-test.example", 4388018530618295000),
        ];
        for (name, hash) in expected {
            assert_eq!(domain_hash(name), Ok(hash), "{name}");
        }
    }

    #[test]
    fn hash_ignores_case_and_trailing_dot() {
        assert_eq!(domain_hash("GoOgLe.CoM."), Ok(GOOGLE_COM));
        assert_eq!(domain_hash("  google.com  "), Ok(GOOGLE_COM));
    }

    #[test]
    fn invalid_names_are_rejected() {
        for name in [
            "",
            ".",
            "a..b",
            ".a.com",
            "bad name.com",
            "münchen.de",
            &"a".repeat(64),
            &format!("{}.com", "a".repeat(64)),
            &vec!["a".repeat(60); 5].join("."),
        ] {
            assert!(domain_hash(name).is_err(), "{name:?} must be rejected");
        }
    }

    #[test]
    fn longest_valid_labels_are_accepted() {
        assert!(domain_hash(&format!("{}.com", "a".repeat(63))).is_ok());
    }

    #[test]
    fn load_from_file_normalizes_and_skips_invalid_lines() {
        let (mgr, hashes) = load("# comment\n\nGoogle.COM\ngoogle.com.\nbad name.com\na..b\ncom\n");

        assert_eq!(hashes, vec![GOOGLE_COM, COM]);
        assert_eq!(
            mgr.get_domain_name(GOOGLE_COM),
            Some(&"google.com".to_string())
        );
        assert_eq!(mgr.get_domain_name(COM), Some(&"com".to_string()));
    }

    #[test]
    fn unknown_hash_has_no_name() {
        let (mgr, _) = load("google.com\n");
        assert_eq!(mgr.get_domain_name(1), None);
    }
}
