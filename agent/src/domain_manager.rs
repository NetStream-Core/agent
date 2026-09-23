use crate::utils::hash::{domain_hash, normalize};
use anyhow::{Result, anyhow};
use log::{info, warn};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadDelta {
    pub added: Vec<u64>,
    pub removed: Vec<u64>,
}

impl ReloadDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

pub struct DomainManager {
    domains: HashMap<u64, String>,
}

impl DomainManager {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    fn parse_file<P: AsRef<Path>>(path: P) -> Result<(Vec<u64>, HashMap<u64, String>, usize)> {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read domains file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        let mut hashes = Vec::new();
        let mut domains = HashMap::new();
        let mut skipped = 0;

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
            match domains.get(&hash) {
                Some(existing) if *existing == name => continue,
                Some(existing) => warn!(
                    "Hash collision between {} and {}, keeping the first",
                    existing, name
                ),
                None => {
                    domains.insert(hash, name);
                    hashes.push(hash);
                }
            }
        }

        Ok((hashes, domains, skipped))
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u64>> {
        let (hashes, domains, skipped) = Self::parse_file(path)?;
        self.domains = domains;

        info!(
            "DomainManager: loaded {} domains from file, skipped {} invalid lines",
            self.domains.len(),
            skipped
        );
        Ok(hashes)
    }

    /// Reloads the domain list from `path` and reports which hashes were
    /// added or removed relative to what was loaded before, so the caller
    /// can update the eBPF map incrementally instead of clearing it (which
    /// would open a window where nothing is blocked).
    pub fn reload_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<ReloadDelta> {
        let (_, fresh, skipped) = Self::parse_file(path)?;

        let mut added: Vec<u64> = fresh
            .keys()
            .filter(|hash| !self.domains.contains_key(hash))
            .copied()
            .collect();
        let mut removed: Vec<u64> = self
            .domains
            .keys()
            .filter(|hash| !fresh.contains_key(hash))
            .copied()
            .collect();
        added.sort_unstable();
        removed.sort_unstable();

        let previous_len = self.domains.len();
        self.domains = fresh;

        info!(
            "DomainManager: reloaded {} domains ({} added, {} removed, {} skipped, was {})",
            self.domains.len(),
            added.len(),
            removed.len(),
            skipped,
            previous_len
        );
        Ok(ReloadDelta { added, removed })
    }

    pub fn get_domain_name(&self, hash: u64) -> Option<&String> {
        self.domains.get(&hash)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const GOOGLE_COM: u64 = 4282548222659472292;
    const COM: u64 = 17442394860103835407;

    fn load(content: &str) -> (DomainManager, Vec<u64>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{content}").unwrap();

        let mut mgr = DomainManager::new();
        let hashes = mgr.load_from_file(file.path()).unwrap();
        (mgr, hashes)
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

    #[test]
    fn reload_reports_only_what_changed() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "google.com\nexample.com\n").unwrap();

        let mut mgr = DomainManager::new();
        mgr.load_from_file(file.path()).unwrap();

        let mut same_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(file.path())
            .unwrap();
        write!(same_file, "google.com\nother.com\n").unwrap();
        drop(same_file);

        let delta = mgr.reload_from_file(file.path()).unwrap();

        let example_com = domain_hash("example.com").unwrap();
        let other_com = domain_hash("other.com").unwrap();

        assert_eq!(delta.added, vec![other_com]);
        assert_eq!(delta.removed, vec![example_com]);
        assert!(mgr.get_domain_name(other_com).is_some());
        assert!(mgr.get_domain_name(example_com).is_none());
    }

    #[test]
    fn reload_of_an_unchanged_file_reports_no_delta() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "google.com").unwrap();

        let mut mgr = DomainManager::new();
        mgr.load_from_file(file.path()).unwrap();
        let delta = mgr.reload_from_file(file.path()).unwrap();

        assert!(delta.is_empty());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn reload_from_a_missing_file_fails_and_keeps_the_previous_list() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "google.com").unwrap();

        let mut mgr = DomainManager::new();
        mgr.load_from_file(file.path()).unwrap();

        assert!(mgr.reload_from_file("/no/such/file").is_err());
        assert_eq!(mgr.len(), 1);
        assert!(mgr.get_domain_name(GOOGLE_COM).is_some());
    }
}
