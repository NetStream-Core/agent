use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/prog.bpf.c");
    Command::new("clang")
        .args(&[
            "-O2",
            "-target",
            "bpf",
            "-c",
            "bpf/prog.bpf.c",
            "-o",
            "bpf/prog.bpf.o",
        ])
        .status()
        .expect("Failed to compile eBPF program");
}
