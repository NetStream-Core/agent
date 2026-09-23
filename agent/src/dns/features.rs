use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::suffixes::PublicSuffixList;

const MAX_LABEL_LENGTH: usize = 63;

pub fn decode_qname(wire: &[u8]) -> Option<String> {
    let mut name = String::with_capacity(wire.len());
    let mut position = 0;

    while position < wire.len() {
        let length = wire[position] as usize;
        if length == 0 || length > MAX_LABEL_LENGTH {
            return None;
        }
        let label = wire.get(position + 1..position + 1 + length)?;

        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&byte| {
            if byte.is_ascii_graphic() {
                byte.to_ascii_lowercase() as char
            } else {
                '?'
            }
        }));
        position += 1 + length;
    }

    (!name.is_empty()).then_some(name)
}

pub fn qtype_label(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "other",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryFeatures {
    pub length: usize,
    pub label_count: usize,
    pub longest_label: usize,
    pub entropy: f64,
    pub digit_ratio: f64,
}

pub fn features(name: &str) -> QueryFeatures {
    let labels: Vec<&str> = name.split('.').collect();
    let characters: Vec<u8> = labels.iter().flat_map(|label| label.bytes()).collect();

    let mut counts = [0usize; 256];
    for &byte in &characters {
        counts[byte as usize] += 1;
    }
    let total = characters.len() as f64;
    let entropy = if characters.is_empty() {
        0.0
    } else {
        counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / total;
                -p * p.log2()
            })
            .sum()
    };
    let digits = characters.iter().filter(|b| b.is_ascii_digit()).count();

    QueryFeatures {
        length: name.len(),
        label_count: labels.len(),
        longest_label: labels.iter().map(|label| label.len()).max().unwrap_or(0),
        entropy,
        digit_ratio: if characters.is_empty() {
            0.0
        } else {
            digits as f64 / total
        },
    }
}

pub struct SubdomainTracker {
    window: Duration,
    max_domains: usize,
    max_subdomains: usize,
    psl: Arc<PublicSuffixList>,
    domains: HashMap<String, HashMap<String, Instant>>,
}

impl SubdomainTracker {
    pub fn new(
        window: Duration,
        max_domains: usize,
        max_subdomains: usize,
        psl: Arc<PublicSuffixList>,
    ) -> Self {
        Self {
            window,
            max_domains,
            max_subdomains,
            psl,
            domains: HashMap::new(),
        }
    }

    pub fn observe(&mut self, now: Instant, name: &str) -> usize {
        let (subdomain, registered) = self.psl.split_registered_domain(name);
        let window = self.window;

        if self.domains.len() >= self.max_domains && !self.domains.contains_key(&registered) {
            self.domains
                .retain(|_, seen| seen.values().any(|&at| now.duration_since(at) <= window));
            if self.domains.len() >= self.max_domains {
                self.domains.clear();
            }
        }

        let seen = self.domains.entry(registered).or_default();
        seen.retain(|_, &mut at| now.duration_since(at) <= window);

        if seen.len() < self.max_subdomains || seen.contains_key(&subdomain) {
            seen.insert(subdomain, now);
        }
        seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(name: &str) -> Vec<u8> {
        name.split('.')
            .flat_map(|label| {
                let mut bytes = vec![label.len() as u8];
                bytes.extend(label.bytes());
                bytes
            })
            .collect()
    }

    #[test]
    fn qname_is_decoded_and_lowercased() {
        assert_eq!(
            decode_qname(&wire("WWW.Example.COM")),
            Some("www.example.com".to_string())
        );
        assert_eq!(decode_qname(&wire("a")), Some("a".to_string()));
    }

    #[test]
    fn malformed_qnames_are_rejected() {
        assert_eq!(decode_qname(&[]), None);
        assert_eq!(decode_qname(&[3, b'a', b'b']), None);
        assert_eq!(decode_qname(&[64]), None);
        assert_eq!(decode_qname(&[0]), None);
        assert_eq!(decode_qname(&[2, b'a', b'b', 5]), None);
    }

    #[test]
    fn non_printable_bytes_are_replaced() {
        assert_eq!(
            decode_qname(&[3, b'a', 0x01, b'b']),
            Some("a?b".to_string())
        );
    }

    #[test]
    fn qtypes_have_labels() {
        assert_eq!(qtype_label(1), "A");
        assert_eq!(qtype_label(16), "TXT");
        assert_eq!(qtype_label(10), "NULL");
        assert_eq!(qtype_label(28), "AAAA");
        assert_eq!(qtype_label(4242), "other");
    }

    #[test]
    fn features_of_a_plain_name() {
        let f = features("www.example.com");

        assert_eq!(f.length, 15);
        assert_eq!(f.label_count, 3);
        assert_eq!(f.longest_label, 7);
        assert_eq!(f.digit_ratio, 0.0);
        assert!(
            (f.entropy - 3.0269868333592873).abs() < 1e-9,
            "{}",
            f.entropy
        );
    }

    #[test]
    fn entropy_of_uniform_and_constant_names() {
        assert_eq!(features("aaaa.aa").entropy, 0.0);
        assert!((features("abcd").entropy - 2.0).abs() < 1e-12);
    }

    #[test]
    fn random_looking_names_have_higher_entropy_and_digit_ratio() {
        let plain = features("mail.google.com");
        let encoded = features("nb2xgzlsmvzgs3tfebzgk4tp.t.tunnel.test");

        assert!(encoded.entropy > plain.entropy);
        assert!(encoded.longest_label >= 24);

        let digits = features("a1b2c3d4.test");
        assert!((digits.digit_ratio - 4.0 / 12.0).abs() < 1e-12);
    }

    fn empty_psl() -> Arc<PublicSuffixList> {
        Arc::new(PublicSuffixList::default())
    }

    #[test]
    fn tracker_groups_subdomains_by_the_public_suffix_list_registered_domain() {
        let psl = Arc::new(PublicSuffixList::parse("co.uk\ncom\n"));
        let mut tracker = SubdomainTracker::new(Duration::from_secs(60), 100, 100, psl);
        let now = Instant::now();

        assert_eq!(tracker.observe(now, "a.example.co.uk"), 1);
        assert_eq!(tracker.observe(now, "b.example.co.uk"), 2);
        assert_eq!(tracker.observe(now, "a.other.com"), 1);
    }

    #[test]
    fn unique_subdomains_are_counted_per_registered_domain() {
        let mut tracker = SubdomainTracker::new(Duration::from_secs(60), 100, 100, empty_psl());
        let now = Instant::now();

        assert_eq!(tracker.observe(now, "a.tunnel.test"), 1);
        assert_eq!(tracker.observe(now, "b.tunnel.test"), 2);
        assert_eq!(tracker.observe(now, "a.tunnel.test"), 2);
        assert_eq!(tracker.observe(now, "x.y.tunnel.test"), 3);
        assert_eq!(tracker.observe(now, "www.other.test"), 1);
    }

    #[test]
    fn subdomains_expire_after_the_window() {
        let mut tracker = SubdomainTracker::new(Duration::from_secs(10), 100, 100, empty_psl());
        let start = Instant::now();

        tracker.observe(start, "a.tunnel.test");
        tracker.observe(start, "b.tunnel.test");

        let later = start + Duration::from_secs(11);
        assert_eq!(tracker.observe(later, "c.tunnel.test"), 1);
    }

    #[test]
    fn memory_is_bounded_per_domain_and_overall() {
        let mut tracker = SubdomainTracker::new(Duration::from_secs(60), 3, 2, empty_psl());
        let now = Instant::now();

        tracker.observe(now, "a.tunnel.test");
        tracker.observe(now, "b.tunnel.test");
        assert_eq!(tracker.observe(now, "c.tunnel.test"), 2);

        for domain in ["one.test", "two.test", "three.test", "four.test"] {
            tracker.observe(now, &format!("x.{domain}"));
        }
        assert!(tracker.domains.len() <= 3);
    }
}
