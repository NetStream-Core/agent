use aya::Ebpf;
use aya::sys::{Stats, enable_stats};
use log::{info, warn};
use opentelemetry::metrics::{Counter, Gauge};
use opentelemetry::{KeyValue, global};
use std::os::fd::OwnedFd;
use tokio::sync::Mutex;

const PROGRAMS: [&str; 2] = ["xdp_monitor", "tc_dns_monitor"];
const USER_HZ: f64 = 100.0;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProgramSample {
    run_time_ns: u64,
    run_count: u64,
}

impl ProgramSample {
    fn since(self, previous: Self) -> Self {
        Self {
            run_time_ns: self.run_time_ns.saturating_sub(previous.run_time_ns),
            run_count: self.run_count.saturating_sub(previous.run_count),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CpuTicks {
    user: u64,
    system: u64,
}

impl CpuTicks {
    fn since(self, previous: Self) -> Self {
        Self {
            user: self.user.saturating_sub(previous.user),
            system: self.system.saturating_sub(previous.system),
        }
    }
}

fn parse_cpu_ticks(stat: &str) -> Option<CpuTicks> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_name.split_whitespace();
    let user = fields.nth(11)?.parse().ok()?;
    let system = fields.next()?.parse().ok()?;
    Some(CpuTicks { user, system })
}

fn parse_rss_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

fn read_cpu_ticks() -> Option<CpuTicks> {
    parse_cpu_ticks(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

fn read_rss_bytes() -> Option<u64> {
    parse_rss_bytes(&std::fs::read_to_string("/proc/self/status").ok()?)
}

pub struct OverheadReporter {
    stats_fd: Option<OwnedFd>,
    programs: Vec<(&'static str, ProgramSample)>,
    cpu: CpuTicks,
    run_time: Counter<u64>,
    run_count: Counter<u64>,
    cpu_seconds: Counter<f64>,
    rss_bytes: Gauge<u64>,
}

impl OverheadReporter {
    pub fn new(collect_program_stats: bool) -> Self {
        let stats_fd = if collect_program_stats {
            match enable_stats(Stats::RunTime) {
                Ok(fd) => {
                    info!("BPF program run statistics enabled");
                    Some(fd)
                }
                Err(e) => {
                    warn!("BPF program run statistics unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

        let meter = global::meter("netstream_agent");
        Self {
            stats_fd,
            programs: Vec::new(),
            cpu: read_cpu_ticks().unwrap_or_default(),
            run_time: meter
                .u64_counter("netstream_bpf_run_time_ns_total")
                .with_description("Time spent executing eBPF programs")
                .with_unit("ns")
                .build(),
            run_count: meter
                .u64_counter("netstream_bpf_run_count_total")
                .with_description("Executions of eBPF programs")
                .build(),
            cpu_seconds: meter
                .f64_counter("netstream_agent_cpu_seconds_total")
                .with_description("CPU time consumed by the agent process")
                .with_unit("s")
                .build(),
            rss_bytes: meter
                .u64_gauge("netstream_agent_memory_rss_bytes")
                .with_description("Resident memory of the agent process")
                .with_unit("By")
                .build(),
        }
    }

    pub async fn report(&mut self, bpf: &Mutex<Ebpf>) {
        if self.stats_fd.is_some() {
            self.report_programs(bpf).await;
        }
        self.report_process();
    }

    async fn report_programs(&mut self, bpf: &Mutex<Ebpf>) {
        let bpf = bpf.lock().await;
        for name in PROGRAMS {
            let Some(info) = bpf.program(name).and_then(|p| p.info().ok()) else {
                continue;
            };
            let current = ProgramSample {
                run_time_ns: info.run_time().as_nanos() as u64,
                run_count: info.run_count(),
            };
            let previous = match self.programs.iter_mut().find(|(n, _)| *n == name) {
                Some((_, sample)) => std::mem::replace(sample, current),
                None => {
                    self.programs.push((name, current));
                    ProgramSample::default()
                }
            };
            let delta = current.since(previous);
            let attributes = [KeyValue::new("program", name)];
            self.run_time.add(delta.run_time_ns, &attributes);
            self.run_count.add(delta.run_count, &attributes);
        }
    }

    fn report_process(&mut self) {
        if let Some(current) = read_cpu_ticks() {
            let delta = current.since(self.cpu);
            self.cpu = current;
            self.cpu_seconds.add(
                delta.user as f64 / USER_HZ,
                &[KeyValue::new("mode", "user")],
            );
            self.cpu_seconds.add(
                delta.system as f64 / USER_HZ,
                &[KeyValue::new("mode", "system")],
            );
        }
        if let Some(rss) = read_rss_bytes() {
            self.rss_bytes.record(rss, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "4242 (network-monitor) S 1 4242 4242 0 -1 4194560 1200 0 0 0 350 120 0 0 20 0 9 0 5000 100000000 2500 18446744073709551615";

    #[test]
    fn parses_user_and_system_ticks() {
        assert_eq!(
            parse_cpu_ticks(STAT),
            Some(CpuTicks {
                user: 350,
                system: 120
            })
        );
    }

    #[test]
    fn process_names_with_spaces_and_parentheses_do_not_shift_fields() {
        let stat = STAT.replace("(network-monitor)", "(a b) (c)");
        assert_eq!(
            parse_cpu_ticks(&stat),
            Some(CpuTicks {
                user: 350,
                system: 120
            })
        );
    }

    #[test]
    fn truncated_stat_is_rejected() {
        assert_eq!(parse_cpu_ticks("4242 (x) S 1 2"), None);
        assert_eq!(parse_cpu_ticks("garbage"), None);
    }

    #[test]
    fn parses_resident_memory() {
        let status = "Name:\tagent\nVmPeak:\t  90000 kB\nVmRSS:\t   20480 kB\nThreads:\t9\n";
        assert_eq!(parse_rss_bytes(status), Some(20480 * 1024));
        assert_eq!(parse_rss_bytes("Name:\tagent\n"), None);
    }

    #[test]
    fn deltas_never_go_backwards() {
        let previous = ProgramSample {
            run_time_ns: 900,
            run_count: 30,
        };
        let restarted = ProgramSample {
            run_time_ns: 100,
            run_count: 5,
        };
        assert_eq!(restarted.since(previous), ProgramSample::default());

        let grown = ProgramSample {
            run_time_ns: 1500,
            run_count: 42,
        };
        assert_eq!(
            grown.since(previous),
            ProgramSample {
                run_time_ns: 600,
                run_count: 12
            }
        );
    }

    #[test]
    fn cpu_deltas_never_go_backwards() {
        let previous = CpuTicks {
            user: 10,
            system: 5,
        };
        let current = CpuTicks { user: 8, system: 9 };
        assert_eq!(current.since(previous), CpuTicks { user: 0, system: 4 });
    }
}
