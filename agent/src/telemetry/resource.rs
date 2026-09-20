use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;

pub const SERVICE_NAME: &str = "netstream-monitor-agent";

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn resolve_host_id(
    configured: Option<String>,
    machine_id: Option<String>,
    hostname: Option<String>,
) -> String {
    non_empty(configured)
        .or_else(|| non_empty(machine_id))
        .or_else(|| non_empty(hostname))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn build(configured_host_id: Option<String>, interface: &str) -> Resource {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    let machine_id = std::fs::read_to_string("/etc/machine-id").ok();
    let host_id = resolve_host_id(configured_host_id, machine_id, hostname.clone());

    let mut attributes = vec![
        KeyValue::new("service.name", SERVICE_NAME),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("host.id", host_id),
        KeyValue::new("network.interface.name", interface.to_string()),
    ];
    if let Some(name) = non_empty(hostname) {
        attributes.push(KeyValue::new("host.name", name));
    }

    Resource::builder().with_attributes(attributes).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::Key;

    #[test]
    fn configured_host_id_wins_over_machine_id_and_hostname() {
        assert_eq!(
            resolve_host_id(
                Some("sensor-1".into()),
                Some("abc".into()),
                Some("box".into())
            ),
            "sensor-1"
        );
    }

    #[test]
    fn machine_id_is_used_before_hostname_and_whitespace_is_trimmed() {
        assert_eq!(
            resolve_host_id(None, Some("abc123\n".into()), Some("box".into())),
            "abc123"
        );
        assert_eq!(
            resolve_host_id(Some("  ".into()), None, Some("box\n".into())),
            "box"
        );
    }

    #[test]
    fn unknown_is_the_last_resort() {
        assert_eq!(resolve_host_id(None, None, None), "unknown");
        assert_eq!(resolve_host_id(None, Some("".into()), None), "unknown");
    }

    #[test]
    fn resource_carries_the_identity_attributes() {
        let resource = build(Some("sensor-1".into()), "eth0");
        let get = |key: &'static str| resource.get(&Key::from_static_str(key));

        assert_eq!(get("service.name").unwrap().as_str(), SERVICE_NAME);
        assert_eq!(get("host.id").unwrap().as_str(), "sensor-1");
        assert_eq!(get("network.interface.name").unwrap().as_str(), "eth0");
        assert!(get("service.version").is_some());
    }
}
