default:
  just --list

clean:
    cargo clean
    rm -f ./bpf/prog.bpf.o
    rm -f ./proto/metrics.rs
    rm -rf target

build *ARGS:
  cargo build {{ARGS}}

test:
    cargo test

run:
    sudo RUST_LOG=info ./target/debug/network-monitor-agent

update:
    git submodule update --init --remote

format:
    cargo fmt
    find . -name "*.c" -exec clang-format -i {} \; -exec echo "Formatted: {}" \;

tidy:
    cargo clippy -- -D warnings
    find . -name "*.c" ! -path "./bpf/*" -exec clang-tidy -checks='clang-analyzer-*,bugprone-*' {} -- -I. \;

all: format tidy build test
