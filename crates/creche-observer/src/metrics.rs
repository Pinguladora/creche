//! The observer's own cost, reported in heartbeats.

use std::fs;

use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::time::TimeValLike as _;
use nix::time::{ClockId, clock_gettime};
use nix::unistd::{SysconfVar, sysconf};

/// Resident set size in KiB (0 if unknown).
#[must_use]
pub fn rss_kb() -> u64 {
    let pages = fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .unwrap_or(0);
    let page_kb = sysconf(SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .and_then(|size| u64::try_from(size).ok())
        .map_or(4, |size| size / 1024);
    pages.saturating_mul(page_kb)
}

/// User plus system CPU time in milliseconds (0 if unknown).
#[must_use]
pub fn cpu_ms() -> u64 {
    getrusage(UsageWho::RUSAGE_SELF)
        .ok()
        .and_then(|usage| {
            let ms = usage
                .user_time()
                .num_milliseconds()
                .saturating_add(usage.system_time().num_milliseconds());
            u64::try_from(ms).ok()
        })
        .unwrap_or(0)
}

/// Boot-time clock in nanoseconds, the clock the BPF records use.
#[must_use]
pub fn boottime_ns() -> u64 {
    clock_gettime(ClockId::CLOCK_BOOTTIME)
        .ok()
        .and_then(|t| u64::try_from(t.num_nanoseconds()).ok())
        .unwrap_or(0)
}
