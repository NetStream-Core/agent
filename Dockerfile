FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --bin network-monitor-agent

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/network-monitor-agent /usr/local/bin/network-monitor-agent
COPY malware_domains.txt public_suffix_list.dat /etc/netstream/

ENV MALWARE_DOMAINS_FILE=/etc/netstream/malware_domains.txt
ENV PUBLIC_SUFFIX_LIST_FILE=/etc/netstream/public_suffix_list.dat

ENTRYPOINT ["/usr/local/bin/network-monitor-agent"]
