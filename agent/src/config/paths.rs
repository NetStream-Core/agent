use std::path::PathBuf;

pub fn bpf_object() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("bpf")
        .join("prog.bpf.o")
}

pub fn malware_domains() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("malware_domains.txt")
}
