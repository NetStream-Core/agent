clean:
    rm ./bpf/prog.bpf.o
    cargo clean

run:
    sudo RUST_LOG=info ./target/debug/network-monitor-agent
