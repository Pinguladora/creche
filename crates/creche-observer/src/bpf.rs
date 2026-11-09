//! Loading and attaching the BPF programs.

use anyhow::{Context as _, Result, anyhow};
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, FEntry, Lsm, Program};
use aya::{Btf, Ebpf, EbpfLoader};

/// Byte buffer with an alignment the ELF parser can rely on.
#[repr(C, align(32))]
struct Aligned<B: ?Sized>(B);

static OBJECT: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/observer.bpf.o")));

/// The compiled BPF object (built from `bpf/observer.bpf.c` by `build.rs`).
#[must_use]
pub fn object() -> &'static [u8] {
    &OBJECT.0
}

/// Process lifecycle hooks: program name and the tracepoint it attaches to.
const TRACEPOINTS: [(&str, &str); 3] = [
    ("on_exec", "sched_process_exec"),
    ("on_fork", "sched_process_fork"),
    ("on_exit", "sched_process_exit"),
];

/// Optional hooks, which need fentry support: program name and kernel function.
const FENTRIES: [(&str, &str); 2] = [
    ("on_connect", "tcp_connect"),
    ("on_open", "security_file_open"),
];

/// How far the programs go, for measuring where the overhead comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stage {
    /// Everything (the normal mode).
    #[default]
    Full,
    /// Attached, but every program returns at once.
    Attach,
    /// Everything but writing to the ring buffer.
    Logic,
}

impl Stage {
    const fn code(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Attach => 1,
            Self::Logic => 2,
        }
    }
}

/// The attached programs and the maps the observer reads.
pub struct Probes {
    /// Owns the programs. Dropping it detaches them.
    ebpf: Ebpf,
    /// Records produced by the programs.
    pub events: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    /// See [`Probes::resync_tasks`].
    epoch: Array<MapData, u32>,
    /// Only exec, fork and exit are reported (the kernel lacks fentry support).
    pub process_only: bool,
    /// Connects to the guarded port the guard has seen, when it is attached.
    guard_seen: Option<Array<MapData, u64>>,
}

impl Probes {
    /// Loads the object into the running kernel and attaches every program.
    ///
    /// # Errors
    ///
    /// When the kernel has no BTF, rejects the object, or cannot attach the
    /// process hooks. Missing fentry support only disables connect and
    /// file-write events. Missing BPF LSM support only leaves `port` unguarded.
    ///
    /// With a `port`, guards it: no other guest process may connect to the host
    /// on that vsock port. [`Probes::guarded`] tells whether the guard runs.
    pub fn load(dedup: bool, stage: Stage, port: Option<u32>) -> Result<Self> {
        // Parsed once and shared: the loader needs it for the CO-RE relocations
        // and the programs to find their attach targets. Each parse of the
        // kernel's BTF costs milliseconds of startup in the guest.
        let btf = Btf::from_sys_fs().context("reading kernel BTF from /sys/kernel/btf/vmlinux")?;
        let dedup = u8::from(dedup);
        // The guard is off while its process is 0.
        let guard_tgid = port.map_or(0, |_| std::process::id());
        let guard_port = port.unwrap_or(0);
        let mut ebpf = EbpfLoader::new()
            .btf(&btf)
            .override_global("dedup_enabled", &dedup, true)
            .override_global("stage", &stage.code(), true)
            .override_global("guard_tgid", &guard_tgid, true)
            .override_global("guard_port", &guard_port, true)
            .load(object())
            .context("loading the BPF object")?;

        for (name, tracepoint) in TRACEPOINTS {
            let prog: &mut BtfTracePoint = program(&mut ebpf, name)?.try_into()?;
            prog.load(tracepoint, &btf)
                .with_context(|| format!("loading {name}"))?;
            prog.attach().with_context(|| format!("attaching {name}"))?;
        }
        let mut process_only = false;
        for (name, function) in FENTRIES {
            let attached = program(&mut ebpf, name)
                .and_then(|p| Ok(<&mut FEntry>::try_from(p)?))
                .and_then(|prog| {
                    prog.load(function, &btf)?;
                    prog.attach()?;
                    Ok(())
                });
            if let Err(e) = attached {
                eprintln!(
                    "creche-observer: {name} unavailable ({e:#}), reporting process events only"
                );
                process_only = true;
            }
        }

        let guard_seen = if port.is_some() && guard(&mut ebpf, &btf) {
            Some(Array::try_from(take_map(&mut ebpf, "guard_seen")?)?)
        } else {
            None
        };

        let events = RingBuf::try_from(take_map(&mut ebpf, "events")?)?;
        let drops = PerCpuArray::try_from(take_map(&mut ebpf, "drops")?)?;
        let epoch = Array::try_from(take_map(&mut ebpf, "epoch")?)?;
        Ok(Self {
            ebpf,
            events,
            drops,
            epoch,
            process_only,
            guard_seen,
        })
    }

    /// Whether only this process can connect to the host on the guarded port:
    /// the guard is attached and has seen a connect, the observer's own among
    /// them. An LSM program attaches even when BPF LSM is not among the
    /// kernel's active LSMs, and then never runs, so attaching alone proves
    /// nothing.
    #[must_use]
    pub fn guarded(&self) -> bool {
        self.guard_seen
            .as_ref()
            .is_some_and(|seen| seen.get(&0, 0).is_ok_and(|n| n > 0))
    }

    /// Makes every process send its context again with its next record. Call
    /// it whenever the host may have missed a task record: on a new connection
    /// or when the forwarding queue dropped records.
    ///
    /// # Errors
    ///
    /// When the epoch map cannot be read or written.
    pub fn resync_tasks(&mut self) -> Result<()> {
        // Not atomic with the kernel's own bump on a drop, but either way the
        // epoch ends up different from the one every process was synced in.
        let now = self.epoch.get(&0, 0)?;
        self.epoch.set(0, &now.wrapping_add(1), 0)?;
        Ok(())
    }

    /// Records the programs could not queue because the ring buffer was full.
    #[must_use]
    pub fn ringbuf_drops(&self) -> u64 {
        self.drops.get(&0, 0).map_or(0, |per_cpu| {
            per_cpu.iter().fold(0_u64, |sum, n| sum.saturating_add(*n))
        })
    }

    /// Total kernel time spent in the programs and their number of runs. Both
    /// stay 0 unless run-time stats are enabled (`aya::sys::enable_stats`).
    #[must_use]
    pub fn run_stats(&self) -> (u64, u64) {
        self.ebpf
            .programs()
            .filter_map(|(_, prog)| prog.info().ok())
            .fold((0, 0), |(ns, count), info| {
                let run_ns = u64::try_from(info.run_time().as_nanos()).unwrap_or(u64::MAX);
                (
                    ns.saturating_add(run_ns),
                    count.saturating_add(info.run_count()),
                )
            })
    }
}

/// Attaches the vsock guard. Whether it attached.
fn guard(ebpf: &mut Ebpf, btf: &Btf) -> bool {
    let attached = program(ebpf, "guard_connect")
        .and_then(|p| Ok(<&mut Lsm>::try_from(p)?))
        .and_then(|prog| {
            prog.load("socket_connect", btf)?;
            prog.attach()?;
            Ok(())
        });
    if let Err(e) = &attached {
        eprintln!("creche-observer: guard unavailable ({e:#}), the vsock port is unguarded");
    }
    attached.is_ok()
}

fn program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Program> {
    ebpf.program_mut(name)
        .ok_or_else(|| anyhow!("program {name} missing from the BPF object"))
}

fn take_map(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map> {
    ebpf.take_map(name)
        .ok_or_else(|| anyhow!("map {name} missing from the BPF object"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya_obj::Object;

    // The wire layout is checked against creche-wire at build time (build.rs
    // generates C static assertions), so a mismatch fails the build.

    #[test]
    fn object_has_every_program_and_map() {
        let object = Object::parse(object()).unwrap();
        for name in TRACEPOINTS
            .iter()
            .chain(&FENTRIES)
            .map(|(name, _)| *name)
            .chain(["guard_connect"])
        {
            assert!(object.programs.contains_key(name), "missing program {name}");
        }
        for map in [
            "events",
            "drops",
            "scratch_map",
            "dedup",
            "sent",
            "epoch",
            "guard_seen",
        ] {
            assert!(object.maps.contains_key(map), "missing map {map}");
        }
        assert!(
            object.btf.is_some(),
            "object has no BTF, so no CO-RE relocations"
        );
        assert_eq!(object.license.to_str().unwrap(), "Dual BSD/GPL");
    }
}
