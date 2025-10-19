clean:
    cargo clean
    rm ./bpf/prog.bpf.o
    rm ./proto/metrics.rs

run:
    sudo RUST_LOG=info ./target/debug/network-monitor-agent

update:
    git submodule update --init --remote

format:
    find . -name "*.c" -o -name "*.h" -type f | xargs clang-format -i -style=file

tidy:
    find . -name "*.c" -type f | xargs -I {} clang-tidy -config-file=.clang-tidy {} -- -I.
