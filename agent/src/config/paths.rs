use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn bpf_object() -> PathBuf {
    project_root().join("bpf/prog.bpf.o")
}

pub fn malware_domains() -> PathBuf {
    project_root().join("malware_domains.txt")
}
