default: # Основные команды
  just --list

clean: # Очистить сгенерированные файлы и сборки
    cargo clean
    rm -f ./bpf/prog.bpf.o
    rm -rf target

build *ARGS: # Собрать проект
  cargo build {{ARGS}}

test: # Запустить тесты
    cargo test

test-c:
    mkdir -p target
    clang -Wall -Wno-unused-function -I bpf/include -o target/test_helpers bpf/tests/test_helpers.c
    ./target/test_helpers

run: # Запустить приложение
    sudo RUST_LOG=debug ./target/debug/network-monitor-agent

format: # Форматировать код
    cargo fmt
    find . -name "*.c" ! -path "./target/*" -exec clang-format -i {} \; -exec echo "Formatted: {}" \;

lint:
    cargo clippy -- -D warnings
    find . -name "*.c" ! -path "./bpf/*" ! -path "./target/*" -exec clang-tidy -checks='clang-analyzer-*,bugprone-*' {} -- -I. \;

audit:
    cargo audit
    cargo deny check

tidy: lint audit

all: format tidy build test test-c # Полный цикл: форматирование, проверка, сборка и тесты
