use std::path::{Path, PathBuf};
use std::process::Command;

fn find_include(header: &str, search_paths: &[&str]) -> Option<PathBuf> {
    for path in search_paths {
        let candidate = Path::new(path).join(header);
        if candidate.exists() {
            return Some(path.into());
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../bpf/prog.bpf.c");
    println!("cargo:rerun-if-changed=proto/metrics.proto");

    let system_paths = [
        "/usr/include",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/libbpf",
        "/usr/include/linux",
        "/usr/local/include",
    ];

    let needed_headers = ["asm/types.h", "linux/bpf.h", "linux/types.h"];

    let mut include_paths = vec![];
    for header in &needed_headers {
        if let Some(path) = find_include(header, &system_paths)
            && !include_paths.contains(&path)
        {
            include_paths.push(path);
        }
    }

    if include_paths.is_empty() {
        panic!("Cannot find required eBPF headers on this system!");
    }

    let mut args = vec![
        "-O2",
        "-target",
        "bpf",
        "-g",
        "-c",
        "../bpf/prog.bpf.c",
        "-o",
        "../bpf/prog.bpf.o",
    ];

    for path in &include_paths {
        args.push("-I");
        args.push(path.to_str().unwrap());
    }

    let status = Command::new("clang")
        .args(&args)
        .status()
        .expect("Failed to spawn clang for eBPF");

    if !status.success() {
        panic!("eBPF compilation failed");
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["./proto/metrics.proto"], &["proto"])?;

    Ok(())
}
