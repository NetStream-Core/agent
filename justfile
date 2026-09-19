default: # Основные команды
  just --list

clean: # Очистить сгенерированные файлы и сборки
    cargo clean
    rm -f ./bpf/prog.bpf.o
    rm -f ./proto/metrics.rs
    rm -rf target

build *ARGS: # Собрать проект
  cargo build {{ARGS}}

test: # Запустить тесты
    cargo test

run: # Запустить приложение
    sudo RUST_LOG=debug ./target/debug/network-monitor-agent

update: # Обновить сабмодули
    git submodule update --init --remote

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

all: format tidy build test # Полный цикл: форматирование, проверка, сборка и тесты
