//! `--isolation` (#316): the command-line preflight on the real binary, and,
//! where bubblewrap can run, the sandboxed `analyze_file` metadata section end
//! to end: result, cache provenance, refusals, deadline, memory classification
//! and cancellation. Admission (`openat2` beneath the roots, links, renames,
//! FIFOs) is unit-tested in `src/isolation.rs` without bubblewrap.
//!
//! The sandbox tests skip with a note when bubblewrap cannot run on the host,
//! unless `REQUIRE_BWRAP_TESTS=1` (set in CI on Linux), where they fail.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use file_scanner::{
    isolation::{MetadataError, Sandbox, WorkerError},
    mcp_server::{FileScannerMcp, ServerState, StateConfig},
    mcp_transport::rest::{call_tool_direct, ToolCallParams},
};
use serde_json::{json, Value};
use serial_test::serial;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_file-scanner");
const MIB: u64 = 1024 * 1024;

/// Run `file-scanner <args>` with stdin closed and a private cache directory,
/// killed after 60 s (a server that started would otherwise wait on HTTP).
/// Returns the output and whether it had to be killed.
fn run(args: &[&str], envs: &[(&str, &str)]) -> (Output, bool) {
    let cache = TempDir::new().unwrap();
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env("FILE_SCANNER_CACHE_DIR", cache.path().join("cache"))
        .env_remove("FILE_SCANNER_ISOLATION")
        .env_remove("FILE_SCANNER_ALLOWED_ROOTS")
        .env_remove("FILE_SCANNER_AUTH_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut killed = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            killed = true;
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = Output {
        status,
        stdout: out_reader.join().unwrap(),
        stderr: err_reader.join().unwrap(),
    };
    (output, killed)
}

fn bwrap_required() -> bool {
    std::env::var("REQUIRE_BWRAP_TESTS").is_ok_and(|value| value == "1")
}

/// A verified sandbox for the real worker binary with `root` as its one
/// allowed root, or `None` (skip) when this host cannot run bubblewrap and CI
/// does not require it.
async fn sandbox(root: &Path) -> Option<Sandbox> {
    match Sandbox::detect(Path::new(BIN), &[root.to_path_buf()]).await {
        Ok(sandbox) => Some(sandbox),
        Err(error) => {
            assert!(!bwrap_required(), "bubblewrap is required here: {error}");
            eprintln!("skipping the sandbox test: {error}");
            None
        }
    }
}

fn server(sandbox: Sandbox, cache: &Path) -> FileScannerMcp {
    FileScannerMcp::with_state(Arc::new(ServerState::new(StateConfig {
        cache_dir: cache.to_path_buf(),
        sandbox: Some(Arc::new(sandbox)),
        ..StateConfig::default()
    })))
}

async fn call(mcp: &FileScannerMcp, name: &str, arguments: Value) -> Value {
    call_tool_direct(
        mcp,
        ToolCallParams {
            name: name.to_string(),
            arguments: arguments.as_object().cloned().unwrap_or_default(),
        },
    )
    .await
    .unwrap()
}

fn text(reply: &Value) -> String {
    reply["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A benign file: an ELF magic number followed by fixed text, with a
/// modification time well in the past (a just-written file is not
/// remembered by its stat identity, so its result could not be a cache hit).
fn benign_file(dir: &Path) -> PathBuf {
    let path = dir.join("benign.bin");
    let mut bytes = b"\x7FELF\x02\x01\x01\x00".to_vec();
    bytes.extend_from_slice(&b"benign isolation fixture ".repeat(64));
    std::fs::write(&path, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000))
        .unwrap();
    path
}

/// A sparse file of `bytes` zeros (no disk space used).
fn sparse_file(dir: &Path, bytes: u64) -> PathBuf {
    let path = dir.join("sparse.bin");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(bytes)
        .unwrap();
    path
}

/// Sandboxed workers still running anywhere on the host (their command name
/// is the mount point `/file-scanner-worker`, cut to 15 characters).
fn live_workers() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("stat")).ok())
        .filter(|stat| {
            let state = stat.rsplit_once(") ").map(|(_, rest)| rest.chars().next());
            stat.contains("(file-scanner-wo)") && state != Some(Some('Z'))
        })
        .count()
}

fn wait_for_no_workers() {
    let deadline = Instant::now() + Duration::from_secs(15);
    while live_workers() > 0 {
        assert!(
            Instant::now() < deadline,
            "a sandboxed worker outlived its call"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

#[test]
fn none_is_the_default_and_serves_as_before() {
    for args in [
        &["mcp-stdio"][..],
        &["mcp-stdio", "--isolation", "none"][..],
    ] {
        let (output, killed) = run(args, &[]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!killed && output.status.success(), "{args:?}: {stderr}");
        assert!(!stderr.contains("--isolation"), "{args:?}: {stderr}");
    }
}

#[test]
fn an_unknown_profile_is_a_usage_error_that_lists_the_choices() {
    let (output, _) = run(&["mcp-stdio", "--isolation", "process"], &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("none") && stderr.contains("bwrap"),
        "{stderr}"
    );
    let (output, _) = run(&["mcp-stdio"], &[("FILE_SCANNER_ISOLATION", "sandbox")]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// Without an allowed root there is nothing to open files beneath: the
/// server refuses to start, whether bubblewrap is installed or not.
#[test]
fn bwrap_without_an_allowed_root_does_not_start() {
    let (output, killed) = run(&["mcp-stdio", "--isolation", "bwrap"], &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!killed, "{stderr}");
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(output.stdout.is_empty());
    let expected = if cfg!(target_os = "linux") {
        "needs at least one --allow-root"
    } else {
        "Linux only"
    };
    assert!(stderr.contains(expected), "{stderr}");
}

/// `--isolation bwrap` with a root either starts with a verified sandbox (and
/// says so) or stops before serving with the typed reason; the environment
/// variable does the same.
#[test]
#[serial]
fn bwrap_starts_only_with_a_verified_sandbox() {
    let root = TempDir::new().unwrap();
    let root_string = root.path().to_string_lossy().into_owned();
    let root_arg = root_string.as_str();
    let usable = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(Sandbox::detect(
            Path::new(BIN),
            &[root.path().to_path_buf()],
        ));
    for (args, envs) in [
        (
            &[
                "mcp-stdio",
                "--isolation",
                "bwrap",
                "--allow-root",
                root_arg,
            ][..],
            &[][..],
        ),
        (
            &["mcp-stdio", "--allow-root", root_arg][..],
            &[("FILE_SCANNER_ISOLATION", "bwrap")][..],
        ),
    ] {
        let (output, killed) = run(args, envs);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!killed, "{stderr}");
        match &usable {
            Ok(_) => {
                assert!(output.status.success(), "{stderr}");
                assert!(stderr.contains("runs, in a sandbox"), "{stderr}");
            }
            Err(error) => {
                assert!(!bwrap_required(), "bubblewrap is required here: {error}");
                assert_eq!(output.status.code(), Some(1), "{stderr}");
                assert!(stderr.contains("--isolation bwrap"), "{stderr}");
                assert!(stderr.contains("did not start"), "{stderr}");
                assert!(output.stdout.is_empty());
                if !cfg!(target_os = "linux") {
                    assert!(stderr.contains("Linux only"), "{stderr}");
                }
            }
        }
    }
}

#[test]
fn help_lists_the_isolation_flag_for_every_mcp_subcommand() {
    for sub in ["mcp-stdio", "mcp-http", "mcp-sse"] {
        let output = Command::new(BIN).args([sub, "--help"]).output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("--isolation"), "{sub}: {text}");
        assert!(text.contains("FILE_SCANNER_ISOLATION"), "{sub}: {text}");
    }
}

// ---------------------------------------------------------------------------
// Sandbox, end to end
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn the_metadata_section_runs_in_the_sandbox_and_matches_in_process() {
    let dir = TempDir::new().unwrap();
    let Some(sandbox) = sandbox(dir.path()).await else {
        return;
    };
    let sample = benign_file(dir.path());
    let path = sample.to_string_lossy().into_owned();

    // The same section in-process, with the SAME cache directory: its stored
    // result must never be served as a sandboxed one.
    let cache_dir = dir.path().join("cache");
    let plain = FileScannerMcp::with_state(Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.clone(),
        ..StateConfig::default()
    })));
    let expected = call(
        &plain,
        "analyze_file",
        json!({"file_path": path, "sections": ["metadata"]}),
    )
    .await;
    let expected: Value = serde_json::from_str(&text(&expected)).unwrap();
    assert!(expected.get("isolation").is_none(), "{expected}");

    let mcp = server(sandbox, &cache_dir);
    let reply = call(
        &mcp,
        "analyze_file",
        json!({"file_path": path, "sections": ["metadata"]}),
    )
    .await;
    assert_ne!(reply["isError"], true, "{reply}");
    let answer: Value = serde_json::from_str(&text(&reply)).unwrap();
    // Computed by the worker even though an in-process result is stored.
    assert_eq!(answer["cache"], "miss", "{answer}");
    assert_eq!(answer["isolation"]["profile"], "bwrap", "{answer}");
    assert_eq!(answer["isolation"]["provenance"], "bwrap-v1", "{answer}");
    // `accessed` is left out: reading the file may move its access time.
    for key in [
        "file_path",
        "file_name",
        "file_size",
        "modified",
        "permissions",
        "is_executable",
        "owner_uid",
        "group_gid",
        "mime_type",
    ] {
        assert_eq!(
            answer["metadata"][key], expected["metadata"][key],
            "{key}: {answer}\n{expected}"
        );
    }
    assert_eq!(
        answer["metadata"]["mime_type"], "application/x-elf",
        "{answer}"
    );
    assert_eq!(answer["sha256"], expected["sha256"]);

    // The same unchanged file again: the sandboxed result, from the cache.
    let again = call(
        &mcp,
        "analyze_file",
        json!({"file_path": path, "metadata": true}),
    )
    .await;
    let again: Value = serde_json::from_str(&text(&again)).unwrap();
    assert_eq!(again["cache"], "hit", "{again}");
    assert_eq!(again["isolation"]["provenance"], "bwrap-v1", "{again}");

    // Anything else is refused, and the cache tools still answer.
    let refused = call(&mcp, "disassemble", json!({"file_path": path})).await;
    assert_eq!(refused["isError"], true);
    assert!(
        text(&refused).starts_with("disassemble is refused"),
        "{refused}"
    );
    let overview = call(&mcp, "analyze_file", json!({"file_path": path})).await;
    assert!(text(&overview).contains("is refused"), "{overview}");
    let status = call(&mcp, "cache_status", json!({})).await;
    assert_ne!(status["isError"], true, "{status}");
    wait_for_no_workers();
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn a_file_outside_the_root_is_refused_before_any_worker() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let Some(sandbox) = sandbox(&root).await else {
        return;
    };
    let outside = benign_file(dir.path());
    std::os::unix::fs::symlink(&outside, root.join("link.bin")).unwrap();
    let mcp = server(sandbox, &dir.path().join("cache"));
    for (file, expected) in [
        (outside.clone(), "not spelled under an allowed root"),
        (root.join("link.bin"), "leaves the allowed root"),
    ] {
        let reply = call(
            &mcp,
            "analyze_file",
            json!({"file_path": file.to_string_lossy(), "metadata": true}),
        )
        .await;
        assert_eq!(reply["isError"], true, "{reply}");
        assert!(text(&reply).contains(expected), "{reply}");
    }
}

#[tokio::test]
#[serial]
async fn the_deadline_stops_the_worker_and_the_server_keeps_answering() {
    let dir = TempDir::new().unwrap();
    let Some(sandbox) = sandbox(dir.path()).await else {
        return;
    };
    let big = sparse_file(dir.path(), 512 * MIB);
    let memory = sandbox.memory_bytes();
    let tight = sandbox.with_limits(Duration::from_millis(200), memory);
    let mcp = server(tight, &dir.path().join("cache"));
    let started = Instant::now();
    let reply = call(
        &mcp,
        "analyze_file",
        json!({"file_path": big.to_string_lossy(), "sections": ["metadata"]}),
    )
    .await;
    assert_eq!(reply["isError"], true, "{reply}");
    let message = text(&reply);
    assert!(
        message.contains("within its 0.2 s deadline and was killed"),
        "{message}"
    );
    assert!(message.contains("server is still running"), "{message}");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    wait_for_no_workers();
    let status = call(&mcp, "cache_status", json!({})).await;
    assert_ne!(status["isError"], true, "{status}");
}

/// Startup memory refusal (deterministic, no worker is launched): an
/// address-space limit below what the worker executable's loadable segments
/// need is refused as exactly that, not as a generic failure. A worker that
/// runs out of memory while running is `WorkerError::Memory`, recognised from
/// its allocation-failure diagnostic.
#[tokio::test]
#[serial]
async fn a_limit_below_the_worker_footprint_is_a_startup_memory_refusal() {
    let dir = TempDir::new().unwrap();
    let Some(sandbox) = sandbox(dir.path()).await else {
        return;
    };
    let sample = benign_file(dir.path());
    let starved = sandbox.with_limits(Duration::from_secs(60), 16 * MIB);
    let admitted = starved.admit(&sample.to_string_lossy()).unwrap();
    let error = starved.metadata_of(admitted).await.unwrap_err();
    assert!(
        matches!(
            &error,
            MetadataError::Worker(WorkerError::MemoryBelowStartup { memory_bytes, .. })
                if *memory_bytes == 16 * MIB
        ),
        "{error:?}"
    );
    assert_eq!(live_workers(), 0, "no worker may be launched");

    let mcp = server(starved, &dir.path().join("cache"));
    let reply = call(
        &mcp,
        "analyze_file",
        json!({"file_path": sample.to_string_lossy(), "sections": ["metadata"]}),
    )
    .await;
    assert_eq!(reply["isError"], true, "{reply}");
    let message = text(&reply);
    assert!(
        message.contains("startup memory refusal") && message.contains("its 16 MiB memory limit"),
        "{message}"
    );
    let status = call(&mcp, "cache_status", json!({})).await;
    assert_ne!(status["isError"], true, "{status}");
}

/// Dropping the call (a cancelled request, a server shutting down) kills the
/// live sandbox; no worker survives it.
#[tokio::test]
#[serial]
async fn a_cancelled_call_leaves_no_worker_behind() {
    let dir = TempDir::new().unwrap();
    let Some(sandbox) = sandbox(dir.path()).await else {
        return;
    };
    // Under the byte cap, and slow enough to hash that the call is live.
    let big = sparse_file(dir.path(), 2000 * MIB);
    let memory = sandbox.memory_bytes();
    let slow = sandbox.with_limits(Duration::from_secs(600), memory);
    let admitted = slow.admit(&big.to_string_lossy()).unwrap();
    // Boxed, so dropping it drops the future (and its child) right here.
    let mut run = Box::pin(slow.metadata_of(admitted));
    let first = tokio::time::timeout(Duration::from_millis(1500), &mut run).await;
    assert!(first.is_err(), "the input finished early: {first:?}");
    assert!(
        live_workers() > 0,
        "the worker should be running before the cancel"
    );
    drop(run);
    wait_for_no_workers();
}

#[tokio::test]
#[serial]
async fn a_direct_run_reports_a_typed_deadline() {
    let dir = TempDir::new().unwrap();
    let Some(sandbox) = sandbox(dir.path()).await else {
        return;
    };
    let big = sparse_file(dir.path(), 512 * MIB);
    let memory = sandbox.memory_bytes();
    let tight = sandbox.with_limits(Duration::from_millis(100), memory);
    let admitted = tight.admit(&big.to_string_lossy()).unwrap();
    let error = tight.metadata_of(admitted).await.unwrap_err();
    assert!(
        matches!(&error, MetadataError::Worker(WorkerError::Deadline { .. })),
        "{error:?}"
    );
    wait_for_no_workers();
}
