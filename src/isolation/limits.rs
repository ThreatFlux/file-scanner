//! Limits of one sandboxed run: the worker's startup footprint (so a limit it
//! cannot even load under is refused deterministically), the resource limits
//! and descriptor control applied between fork and exec, and the reading of an
//! out-of-memory failure.

use std::{io::Read, path::Path};

use super::MIB;

/// Address space for the loader, libc, the stack and the heap of a starting
/// worker, on top of the executable's loadable segments.
pub(super) const STARTUP_MARGIN: u64 = 48 * MIB;

/// `e_ident` of a little-endian ELF64 file (magic, class 2, data 1).
const ELF64_LE: &[u8] = b"\x7FELF\x02\x01";
/// Program-header type of a loadable segment.
const PT_LOAD: u32 = 1;
/// Bytes of the executable read for its headers.
const HEADER_READ: u64 = 64 * 1024;

/// What the worker executable needs to start: its loadable segments plus
/// [`STARTUP_MARGIN`], or 0 when its headers are not little-endian ELF64.
pub(super) fn startup_bytes(worker_exe: &Path) -> u64 {
    let mut head = Vec::new();
    let read = std::fs::File::open(worker_exe)
        .and_then(|file| file.take(HEADER_READ).read_to_end(&mut head));
    read.ok()
        .and_then(|_| elf_load_span(&head))
        .map_or(0, |span| span.saturating_add(STARTUP_MARGIN))
}

/// The span of the PT_LOAD segments of a little-endian ELF64 executable, from
/// its first bytes; `None` for anything else or a header past `head`.
fn elf_load_span(head: &[u8]) -> Option<u64> {
    let segments = program_header_offsets(head)?
        .map(|at| load_segment(head, at?))
        .collect::<Option<Vec<_>>>()?;
    let (low, high) = segments
        .into_iter()
        .flatten()
        .fold((u64::MAX, 0), |(low, high), (start, end)| {
            (low.min(start), high.max(end))
        });
    (high > low).then(|| high - low)
}

/// `N` bytes at `at`, or `None` past the end.
fn bytes_at<const N: usize>(head: &[u8], at: usize) -> Option<[u8; N]> {
    head.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Offsets of the program-header entries (`None` for one that overflows).
fn program_header_offsets(head: &[u8]) -> Option<impl Iterator<Item = Option<usize>>> {
    if head.get(..ELF64_LE.len())? != ELF64_LE {
        return None;
    }
    let table = usize::try_from(u64::from_le_bytes(bytes_at(head, 0x20)?)).ok()?;
    let entry = usize::from(u16::from_le_bytes(bytes_at(head, 0x36)?));
    let count = usize::from(u16::from_le_bytes(bytes_at(head, 0x38)?));
    Some((0..count).map(move |index| table.checked_add(index.checked_mul(entry)?)))
}

/// `Some((start, end))` of the PT_LOAD entry at `at`, `Some(None)` for an
/// entry of another type, `None` when the entry is cut off or overflows.
fn load_segment(head: &[u8], at: usize) -> Option<Option<(u64, u64)>> {
    if u32::from_le_bytes(bytes_at(head, at)?) != PT_LOAD {
        return Some(None);
    }
    let start = u64::from_le_bytes(bytes_at(head, at.checked_add(0x10)?)?);
    let size = u64::from_le_bytes(bytes_at(head, at.checked_add(0x28)?)?);
    Some(Some((start, start.checked_add(size)?)))
}

/// Whether a failed worker ran out of address space: an allocation failure
/// (Rust aborts with this text), or an exec or loader that could not map.
pub(super) fn out_of_memory(detail: &str, signal: Option<i32>) -> bool {
    const SIGABRT: i32 = 6;
    let detail = detail.to_ascii_lowercase();
    [
        "memory allocation of",
        "cannot allocate memory",
        "out of memory",
        "failed to map segment",
    ]
    .iter()
    .any(|needle| detail.contains(needle))
        || (signal == Some(SIGABRT) && detail.contains("memory"))
}

/// The resource argument type of `setrlimit` (it differs between C libraries).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
type Resource = libc::c_int;

/// Runs in the child between fork and exec, so it may only make
/// async-signal-safe system calls and must not allocate: the address-space,
/// CPU-time and core limits, then every descriptor above stderr marked
/// close-on-exec, so bubblewrap and the worker inherit stdin, stdout and
/// stderr only.
#[cfg(target_os = "linux")]
pub(super) fn limit_child(memory: u64, cpu_seconds: u64) -> std::io::Result<()> {
    set_limit(libc::RLIMIT_AS, memory)?;
    set_limit(libc::RLIMIT_CPU, cpu_seconds)?;
    set_limit(libc::RLIMIT_CORE, 0)?;
    mark_extra_descriptors_close_on_exec()
}

/// `setrlimit(resource, {value, value})`: soft and hard limit alike, so the
/// child cannot raise it again.
#[cfg(target_os = "linux")]
fn set_limit(resource: Resource, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit(2) only reads the `rlimit` it is given, which lives
    // on this stack frame for the whole call; it is async-signal-safe and
    // touches no memory the forked child shares with the parent.
    let status = unsafe { libc::setrlimit(resource, &limit) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` (Linux 5.11): mark every
/// descriptor above stderr close-on-exec. Marking, not closing, keeps the
/// standard library's own exec-error pipe working until exec.
#[cfg(target_os = "linux")]
fn mark_extra_descriptors_close_on_exec() -> std::io::Result<()> {
    const FIRST_EXTRA_FD: libc::c_uint = 3;
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    // SAFETY: close_range(2) takes three integers and dereferences no
    // pointer. With CLOSE_RANGE_CLOEXEC it closes nothing, so no descriptor a
    // Rust object owns becomes invalid; the flags only take effect at exec.
    let status = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_EXTRA_FD,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 LE header with the given PT_LOAD entries at 0x40.
    fn elf_with_loads(loads: &[(u64, u64)]) -> Vec<u8> {
        let mut head = vec![0_u8; 0x40 + loads.len() * 0x38];
        head[..6].copy_from_slice(ELF64_LE);
        head[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        head[0x36..0x38].copy_from_slice(&0x38_u16.to_le_bytes());
        head[0x38..0x3A].copy_from_slice(&(loads.len() as u16).to_le_bytes());
        for (index, (start, size)) in loads.iter().enumerate() {
            let at = 0x40 + index * 0x38;
            head[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            head[at + 0x10..at + 0x18].copy_from_slice(&start.to_le_bytes());
            head[at + 0x28..at + 0x30].copy_from_slice(&size.to_le_bytes());
        }
        head
    }

    #[test]
    fn the_startup_footprint_is_read_from_the_program_headers() {
        let head = elf_with_loads(&[(0x1000, 0x2000), (0x10_0000, 0x500)]);
        assert_eq!(elf_load_span(&head), Some(0x10_0500 - 0x1000));
        assert_eq!(elf_load_span(b"MZ not an ELF"), None);
        // The second field of the first entry is cut off.
        assert_eq!(elf_load_span(&head[..0x50]), None);
        // A segment whose end overflows is not a footprint.
        assert_eq!(elf_load_span(&elf_with_loads(&[(u64::MAX, 2)])), None);
        // Entries of another type are skipped; none left means no span.
        let mut other = elf_with_loads(&[(0x1000, 0x2000)]);
        other[0x40..0x44].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(elf_load_span(&other), None);
    }

    #[test]
    fn out_of_memory_is_recognised_from_the_diagnostic() {
        assert!(out_of_memory(
            "memory allocation of 1048576 bytes failed",
            Some(6)
        ));
        assert!(out_of_memory(
            "bwrap: execvp /file-scanner-worker: Cannot allocate memory",
            None
        ));
        assert!(!out_of_memory(
            "bwrap: No permissions to create new namespace",
            None
        ));
    }
}
