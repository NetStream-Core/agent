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
    sudo RUST_LOG=info ./target/debug/network-monitor-agent

update: # Обновить сабмодули
    git submodule update --init --remote

format: # Форматировать код
    cargo fmt
    find . -name "*.c" -exec clang-format -i {} \; -exec echo "Formatted: {}" \;

tidy: # Проверить код линтерами
    cargo audit
    cargo deny check
    cargo clippy -- -D warnings
    find . -name "*.c" ! -path "./bpf/*" -exec clang-tidy -checks='clang-analyzer-*,bugprone-*' {} -- -I. \;

all: format tidy build test # Полный цикл: форматирование, проверка, сборка и тесты
