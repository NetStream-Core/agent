clean:
    cargo clean
    rm ./bpf/prog.bpf.o
    rm ./proto/metrics.rs

run:
    sudo RUST_LOG=info ./target/debug/network-monitor-agent

update:
    git submodule update --init --remote

format:
    cargo fmt
    find . -name "*.c" -exec clang-format -i {} \; -exec echo "Formatted: {}" \;

tidy:
    find . -name "*.c" ! -path "./bpf/*" -exec clang-tidy -checks='clang-analyzer-*,bugprone-*' {} -- -I. \;
