use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Default)]
pub struct PublicSuffixList {
    rules: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

impl PublicSuffixList {
    pub fn parse(source: &str) -> Self {
        let mut list = Self::default();

        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            if let Some(rest) = line.strip_prefix('!') {
                list.exceptions.insert(rest.to_ascii_lowercase());
            } else if let Some(rest) = line.strip_prefix("*.") {
                list.wildcards.insert(rest.to_ascii_lowercase());
            } else {
                list.rules.insert(line.to_ascii_lowercase());
            }
        }

        list
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read public suffix list {}", path.display()))?;
        Ok(Self::parse(&content))
    }

    /// Splits `name` into (subdomain, registered_domain) using the public
    /// suffix algorithm: the registered domain is the public suffix plus one
    /// label, and everything above it is the subdomain.
    pub fn split_registered_domain(&self, name: &str) -> (String, String) {
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < 2 {
            return (String::new(), name.to_string());
        }

        let suffix_len = self.suffix_label_count(&labels);
        let registered_len = (suffix_len + 1).min(labels.len());
        let split_at = labels.len() - registered_len;

        (labels[..split_at].join("."), labels[split_at..].join("."))
    }

    /// Number of trailing labels that make up the public suffix, using the
    /// longest matching rule; the implicit `*` rule falls back to one label.
    fn suffix_label_count(&self, labels: &[&str]) -> usize {
        let n = labels.len();
        for take in (1..=n).rev() {
            let candidate = labels[n - take..].join(".").to_ascii_lowercase();
            if self.exceptions.contains(&candidate) {
                return take - 1;
            }
            if self.rules.contains(&candidate) {
                return take;
            }
            if take >= 2 {
                let wildcard_base = labels[n - take + 1..].join(".").to_ascii_lowercase();
                if self.wildcards.contains(&wildcard_base) {
                    return take;
                }
            }
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> PublicSuffixList {
        PublicSuffixList::parse(
            "com\n\
             co.uk\n\
             com.au\n\
             *.ck\n\
             !www.ck\n\
             *.kobe.jp\n\
             !city.kobe.jp\n",
        )
    }

    #[test]
    fn plain_tld_rule_splits_one_label_above_it() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("www.example.com"),
            ("www".to_string(), "example.com".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("example.com"),
            (String::new(), "example.com".to_string())
        );
    }

    #[test]
    fn two_label_rule_keeps_the_whole_registrable_domain() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("example.co.uk"),
            (String::new(), "example.co.uk".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("www.example.co.uk"),
            ("www".to_string(), "example.co.uk".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("a.b.example.com.au"),
            ("a.b".to_string(), "example.com.au".to_string())
        );
    }

    #[test]
    fn wildcard_rule_covers_one_arbitrary_label() {
        let psl = list();
        // "*.ck" makes the label right above "ck" part of the suffix (like a
        // second-level TLD), so a name with exactly that shape is itself the
        // whole registered domain, with nothing left over as a subdomain.
        assert_eq!(
            psl.split_registered_domain("example.ck"),
            (String::new(), "example.ck".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("www.example.ck"),
            (String::new(), "www.example.ck".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("a.www.example.ck"),
            ("a".to_string(), "www.example.ck".to_string())
        );
    }

    #[test]
    fn exception_rule_removes_one_label_from_the_wildcard_match() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("www.ck"),
            (String::new(), "www.ck".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("city.kobe.jp"),
            (String::new(), "city.kobe.jp".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("a.city.kobe.jp"),
            ("a".to_string(), "city.kobe.jp".to_string())
        );
    }

    #[test]
    fn unknown_tld_falls_back_to_the_implicit_single_label_rule() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("a.b.example.unknowntld"),
            ("a.b".to_string(), "example.unknowntld".to_string())
        );
    }

    #[test]
    fn single_label_names_have_no_subdomain() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("localhost"),
            (String::new(), "localhost".to_string())
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let psl = PublicSuffixList::parse("// comment\n\ncom\n// another\n");
        assert_eq!(
            psl.split_registered_domain("example.com"),
            (String::new(), "example.com".to_string())
        );
    }

    #[test]
    fn the_bundled_file_parses_and_splits_real_multi_level_suffixes() {
        let psl =
            PublicSuffixList::load_from_file(std::path::Path::new("../public_suffix_list.dat"))
                .expect("the bundled public_suffix_list.dat should load");

        assert_eq!(
            psl.split_registered_domain("www.bbc.co.uk"),
            ("www".to_string(), "bbc.co.uk".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("example.com.au"),
            (String::new(), "example.com.au".to_string())
        );
        assert_eq!(
            psl.split_registered_domain("a.b.example.co.uk"),
            ("a.b".to_string(), "example.co.uk".to_string())
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        let psl = list();
        assert_eq!(
            psl.split_registered_domain("WWW.Example.CO.UK"),
            ("WWW".to_string(), "Example.CO.UK".to_string())
        );
    }
}
