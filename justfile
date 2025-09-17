clean:
    cargo clean
    rm ./bpf/prog.bpf.o
    rm ./proto/metrics.rs

run:
    sudo RUST_LOG=info ./target/debug/network-monitor-agent
