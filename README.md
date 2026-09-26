# NetStream Agent

Сенсор сетевого трафика на eBPF. XDP-программа на входе и TC-программа на выходе интерфейса считают потоки и разбирают DNS-запросы в ядре, пользовательская часть на Rust периодически снимает счётчики и отправляет их по OTLP.

- Потоки (`netstream.flow`), DNS-запросы (`netstream.dns.query`) и срабатывания блоклиста (`netstream.blocklist.hit`) уходят как OTLP-логи.
- Агрегированные счётчики (`netstream_*`) уходят как OTLP-метрики.
- Домены из чёрного списка обнаруживаются в DNS-запросах; в зависимости от режима запрос только фиксируется, отбрасывается или приводит к карантину источника.

Контракт атрибутов событий и схемы хранилища описаны в репозитории `deploy`.

## Структура

| Путь | Содержимое |
|---|---|
| `agent/` | пользовательская часть на Rust: загрузка программ, чтение карт, телеметрия, health-сервер |
| `bpf/` | eBPF-программы на C (`prog.bpf.c`, заголовки в `bpf/include`, тесты хелперов в `bpf/tests`) |
| `common/` | структуры, общие для ядра и пользовательской части |
| `malware_domains.txt` | чёрный список доменов по умолчанию |
| `public_suffix_list.dat` | список публичных суффиксов (publicsuffix.org, раздел ICANN) для группировки DNS-запросов по зарегистрированному домену |

## Требования

- Linux с поддержкой XDP и TC (проверено на 6.x), права `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (обычно запуск от root).
- Rust (edition 2024), `clang`, `llvm`, `libbpf-dev`, заголовки ядра. Объект eBPF собирается `agent/build.rs` при `cargo build`.
- [`just`](https://github.com/casey/just) для команд из `justfile` (необязательно).

## Сборка и запуск

```bash
cargo build --release
sudo RUST_LOG=info ./target/release/network-monitor-agent
```

eBPF-объект собирается `agent/build.rs` при `cargo build` и встраивается прямо в бинарник (`include_bytes_aligned!`) — отдельного `.o`-файла разворачивать не нужно, `network-monitor-agent` самодостаточен.

В режиме отладки (`cargo build`) eBPF-объект собирается с `-DDEBUG` и пишет в `trace_pipe` (`sudo cat /sys/kernel/debug/tracing/trace_pipe`).

### Docker

```bash
docker build -t netstream-agent .
docker run --rm \
    --cap-add=BPF --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
    --cap-drop=ALL \
    -e NETWORK_INTERFACE=eth0 \
    netstream-agent
```

Образ — многоступенчатая сборка (`rust:1-bookworm` → `debian:bookworm-slim`), в финальном слое только бинарник, чёрный список и список публичных суффиксов из репозитория по умолчанию (`/etc/netstream/`) — переопределяются volume-монтированием поверх тех же путей и не требуют пересборки образа. `--privileged` не нужен: перечисленных возможностей достаточно для загрузки XDP/TC-программ и создания карт. `CAP_SYS_ADMIN` шире, чем хотелось бы, но на многих ядрах его требует seccomp-профиль Docker по умолчанию для самого системного вызова `bpf()`, независимо от того, что просит агент — без него загрузка программы падает с `EPERM` ещё до входа в верификатор. Здесь по-прежнему предпочтительнее «свободный» `--cap-add` над `--privileged`: не отключается seccomp/AppArmor целиком, не открывается доступ к устройствам хоста, не выдаются остальные возможности.

DNS проверяется на входе (XDP) и на выходе (TC).

Агент прикрепляется к интерфейсу с маршрутом по умолчанию (для `sudo` учитывается `SUDO_UID`) либо к `NETWORK_INTERFACE`. Для интерфейсов без Ethernet-заголовка (tun, wireguard) режим L3 выбирается автоматически.

Остановка по `SIGINT` и `SIGTERM`: программы отсоединяются, метрики выгружаются.

## Конфигурация

Все настройки задаются переменными окружения. Неверное значение приводит к ошибке при старте.

| Переменная | По умолчанию | Значение и эффект |
|---|---|---|
| `NETWORK_INTERFACE` | интерфейс маршрута по умолчанию | Интерфейс, к которому прикрепляются XDP и TC |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://127.0.0.1:4317` | Адрес OTLP/gRPC-приёмника для метрик и логов |
| `REPORT_INTERVAL_MS` | `1000` | Период снятия счётчиков и отправки, больше нуля |
| `EXPORT_LOGS` | `true` | `false` отключает отправку OTLP-логов, метрики остаются |
| `HOST_ID` | нет | Значение `host.id` в ресурсе; без него берётся `/etc/machine-id`, затем имя хоста, затем `unknown` |
| `HEALTH_HOST` | `127.0.0.1` | Адрес health-сервера |
| `HEALTH_PORT` | `8081` | Порт health-сервера |
| `MALWARE_DOMAINS_FILE` | `malware_domains.txt` рядом с исходниками | Файл чёрного списка, один домен в строке, `#` начинает комментарий; сопоставление идёт по суффиксу (`evil.com` ловит `a.b.evil.com`) |
| `RELOAD_POLL_MS` | `5000` | Как часто агент проверяет `MALWARE_DOMAINS_FILE` на изменения; перезагрузку также можно вызвать сразу сигналом `SIGHUP`. В карту eBPF добавляются только новые домены и удаляются только пропавшие, без очистки и без перезапуска агента; счётчики срабатываний (`netstream_blocklist_hits_total`) при этом не сбрасываются |
| `PUBLIC_SUFFIX_LIST_FILE` | `public_suffix_list.dat` рядом с исходниками | Список публичных суффиксов (формат publicsuffix.org, раздел ICANN, обновляется вручную заменой файла) для группировки DNS-запросов по зарегистрированному домену; при отсутствии файла агент откатывается на правило «последние два уровня» и пишет предупреждение |
| `DNS_EVENTS` | `true` | `false` отключает события `netstream.dns.query` и метрики `netstream_dns_qname_*`, проверка блоклиста продолжает работать |
| `RESPONSE_MODE` | `monitor` | Реакция на домен из блоклиста, см. ниже |
| `QUARANTINE_TTL_SECS` | `60` | Время карантина источника в режиме `gateway`, больше нуля |
| `QUARANTINE_ALLOWLIST` | пусто | Адреса и префиксы через запятую (`10.0.0.1, 192.168.0.0/16`), которые не помещаются в карантин |
| `COLLAPSE_EPHEMERAL_PORTS` | `true` | Сворачивать эфемерный порт в 0, если эфемерна ровно одна из сторон потока (диапазон берётся из `/proc/sys/net/ipv4/ip_local_port_range`) |
| `FLOW_TABLE_ENTRIES` | `10240` | Размер таблицы потоков в ядре, не меньше `1024` |
| `FLOW_LOG_TOP_N` | `2000` | Сколько потоков за интервал уходит логами отдельно, остальные сливаются в агрегированные записи; `0` отключает ограничение |
| `FLOW_NEW_PER_SECOND` | `100` | Бюджет новых потоков в секунду на ядро CPU, не меньше `10`; сверх бюджета потоки агрегируются |
| `BPF_STATS` | `true` | Включает статистику выполнения eBPF-программ (`BPF_ENABLE_STATS`, нужен `CAP_SYS_ADMIN`, ядро 5.8+); `false` отключает метрики `netstream_bpf_*`, чтобы измерять агент без собственных накладных расходов |
| `RUST_LOG` | `error` | Уровень логирования (`info`, `debug`) |

### Режимы реагирования

| Режим | DNS-запрос к домену из блоклиста | Когда использовать |
|---|---|---|
| `monitor` | пропускается, фиксируется событие `action=observed` | наблюдение и сбор данных, безопасно на любой машине |
| `enforce` | отбрасывается, событие `action=dropped` | защита самого хоста |
| `gateway` | отбрасывается, источник попадает в карантин на `QUARANTINE_TTL_SECS`, входящий трафик от него и к нему отбрасывается; событие `action=quarantined` | шлюз или маршрутизатор, защищающий сеть за собой |

В режиме `gateway` в разрешённый список автоматически входят адреса самой машины, серверы из `/etc/resolv.conf` и шлюз по умолчанию, поэтому сенсор не блокирует сам себя. Дополнительные адреса задаются `QUARANTINE_ALLOWLIST`.

## Агрегация потоков

Ключ потока: `(src_ip, dst_ip, src_port, dst_port, protocol, direction, flags)`.

Чтобы флуд не переполнял таблицу, ядро выдаёт каждому CPU бюджет новых потоков (`FLOW_NEW_PER_SECOND`). Сверх бюджета пакеты попадают в агрегированные записи:

| `netstream.flow.aggregated` | Смысл |
|---|---|
| `0` | обычный поток с полным ключом |
| `1` | порт источника обнулён |
| `2` | оба порта обнулены |

Счётчики пакетов и байтов при агрегации не теряются.

## Телеметрия

### Метрики

| Метрика | Тип | Атрибуты |
|---|---|---|
| `netstream_packets_total` | counter | `direction`, `transport` |
| `netstream_payload_bytes_total` | counter | `direction`, `transport` |
| `netstream_ip_bytes_total` | counter | `direction`, `transport` |
| `netstream_tcp_flags_total` | counter | `direction`, `flag` |
| `netstream_flow_table_entries` | gauge | нет |
| `netstream_flow_active` | gauge | нет |
| `netstream_flow_overflow_packets_total` | counter | нет |
| `netstream_flow_logs_merged_total` | counter | нет |
| `netstream_bpf_run_time_ns_total` | counter | `program` (`xdp_monitor`, `tc_dns_monitor`) |
| `netstream_bpf_run_count_total` | counter | `program` |
| `netstream_agent_cpu_seconds_total` | counter | `mode` (`user`, `system`) |
| `netstream_agent_memory_rss_bytes` | gauge | нет |
| `netstream_dns_queries_total` | counter | `direction`, `qtype` |
| `netstream_dns_events_lost_total` | counter | нет |
| `netstream_blocklist_hits_total` | counter | `action` |
| `netstream_dns_qname_length`, `netstream_dns_qname_entropy`, `netstream_dns_unique_subdomains` | histogram | `direction` |

DNS-запросы разбираются и по UDP, и по TCP/53. Событие `netstream.dns.query` несёт атрибут `network.transport` (`tcp` или `udp`); метрика `netstream_dns_queries_total` по транспорту не разбита. DNS-over-TCP разбирается только если весь запрос (2-байтовая длина и сообщение) поместился в один TCP-сегмент; запрос, разбитый на несколько сегментов, тихо пропускается — пересборка TCP-потока в eBPF не реализована.

`netstream_dns_unique_subdomains` и одноимённый атрибут события считают уникальные поддомены зарегистрированного домена (`PUBLIC_SUFFIX_LIST_FILE`), а не «последних двух меток»: для `a.b.example.co.uk` это `example.co.uk`, а не `co.uk`. В список входит только раздел ICANN; частные домены вроде `github.io` или `herokuapp.com` не размечены, поэтому для них группировка совпадает со старым поведением (по последним двум меткам общего доменного имени платформы, а не по-настоящему зарегистрированного домена конкретного пользователя).

### Ресурс

`service.name`, `service.version`, `host.id`, `host.name`, `network.interface.name`, `service.instance.id`.

`service.instance.id` (`boot_id`) — случайное 64-битное значение, сгенерированное один раз при старте процесса, общее для всех событий и метрик этого запуска. `host.id` не меняется между перезапусками агента на одной машине, а `service.instance.id` — меняется всегда: по нему видно, что после падения/перезапуска начался новый «boot», даже если счётчики метрик и последовательность событий начались заново с нуля.

### Идентичность события

Каждое событие (`netstream.flow`, `netstream.dns.query`, `netstream.blocklist.hit`) дополнительно несёт:

| Атрибут | Значение |
|---|---|
| `netstream.event.sequence` | Монотонно растущий счётчик, общий для всех типов событий одного запуска агента, начинается с 0 |
| `netstream.event.id` | `"{service.instance.id}-{sequence}"` — уникален в пределах всей истории агента, не только текущего запуска |

Оба поля собираются с намеренным минимумом: `event_id` не отдельный случайный UUID, а производное от уже уникальной пары `(boot_id, sequence)` — этого достаточно, чтобы отличить повтор одного и того же события (Kafka retry, повторная доставка) от двух разных событий, и не требует ни генератора UUID, ни синхронизации между потоками сверх одного атомарного счётчика. `event_time` — это `Timestamp` записи, момент, когда агент сформировал и отправил событие (для `netstream.flow` — конец интервала съёма, а не момент прихода конкретного пакета); `ingest_time` (когда событие попало в хранилище) агент не проставляет — это поле добавляется на стороне `deploy` при записи в ClickHouse.

## Health-сервер

| Путь | Ответ |
|---|---|
| `GET /health` | `200`, `{"status":"ok","version":"..."}` |
| `GET /ready` | `200 ready` после загрузки программ, иначе `503 not ready`; при остановке снова `503` |

## Разработка

```bash
just test
just test-c
just lint
just format
just all
```

- `just test` запускает тесты Rust.
- `just test-c` собирает и запускает тесты C-хелперов (`bpf/tests`) на хосте, без ядра.
- `just lint` запускает `clippy -D warnings` и `clang-tidy`.
- `just all` выполняет форматирование, проверки, сборку и все тесты.

Проверка загрузки в ядро требует прав root и выполняется в лаборатории репозитория `deploy` (`just lab-e2e`).
