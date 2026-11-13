//! The cache and string services through the real binary on stdio: the cache
//! lives in a private directory, is complete when the session ends, serves a
//! later session, degrades to memory when its directory is unusable, and can
//! be switched off.

use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_file-scanner");

struct Session {
    replies: Vec<Value>,
    stderr: String,
    code: Option<i32>,
}

impl Session {
    fn reply(&self, id: u64) -> &Value {
        self.replies
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no reply {id}: {:?}\n{}", self.replies, self.stderr))
    }

    /// The JSON the tool call `id` returned.
    fn tool_json(&self, id: u64) -> Value {
        let text = self.reply(id)["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no text in {:?}", self.reply(id)));
        serde_json::from_str(text).unwrap_or(Value::String(text.to_string()))
    }
}

/// Run one `mcp-stdio` session: initialize, then each tool call (ids 2..),
/// then close stdin and wait for the process to exit.
fn session(extra_args: &[&str], envs: &[(&str, &Path)], calls: &[(&str, Value)]) -> Session {
    let mut command = Command::new(BIN);
    command
        .arg("mcp-stdio")
        .args(extra_args)
        .env_remove("FILE_SCANNER_CACHE_DIR")
        .env_remove("FILE_SCANNER_ALLOWED_ROOTS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn");
    let mut stdin = child.stdin.take().unwrap();
    let mut send = |value: Value| {
        writeln!(stdin, "{value}").unwrap();
    };
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "cache-test", "version": "1"}}}),
    );
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    for (i, (name, arguments)) in calls.iter().enumerate() {
        send(
            json!({"jsonrpc": "2.0", "id": i as u64 + 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}),
        );
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    Session {
        replies: String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code(),
    }
}

fn sample(dir: &Path) -> String {
    let path = dir.join("sample.bin");
    std::fs::write(
        &path,
        b"\0\0\0\0http://evil.example.com/beacon\0\0hello world, plain text\0",
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn the_cache_is_complete_when_the_session_ends_and_serves_the_next_session() {
    let work = tempfile::tempdir().unwrap();
    let cache = work.path().join("cache");
    let path = sample(work.path());
    let cache_arg = cache.to_string_lossy().into_owned();

    let first = session(
        &["--cache-dir", &cache_arg],
        &[],
        &[
            (
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            ),
            ("analyze_file", json!({"file_path": path, "hashes": true})),
        ],
    );
    assert_eq!(first.code, Some(0), "{}", first.stderr);
    assert_eq!(first.tool_json(2)["cache"], "miss");
    assert_eq!(first.tool_json(2)["items"][0]["offset"], 4);

    // Everything the session wrote is whole: parseable, private, no temp files.
    let mut files = 0;
    for entry in walk(&cache) {
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains(".tmp-"), "left over: {name}");
        if name.ends_with(".json") {
            let _: Value = serde_json::from_slice(&std::fs::read(&entry).unwrap())
                .unwrap_or_else(|e| panic!("{name} is not whole JSON: {e}"));
        }
        files += 1;
    }
    assert!(files >= 3, "index, entry and section files: {files}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&cache), 0o700);
        for entry in walk(&cache) {
            assert_eq!(mode(&entry), 0o600, "{}", entry.display());
        }
    }

    // A new process: the string index and the history come from disk.
    let second = session(
        &["--cache-dir", &cache_arg],
        &[],
        &[
            (
                "search_strings",
                json!({"file_path": path, "query": "hello"}),
            ),
            ("cache_status", json!({"action": "list"})),
        ],
    );
    assert_eq!(second.code, Some(0), "{}", second.stderr);
    assert_eq!(second.tool_json(2)["cache"], "hit", "{:?}", second.reply(2));
    assert_eq!(second.tool_json(3)["total"], 1, "{:?}", second.reply(3));
    assert!(second.stderr.is_empty() || !second.stderr.contains("not usable"));

    // A changed file is a miss again.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(&path, b"\0\0\0\0completely different content\0").unwrap();
    let third = session(
        &["--cache-dir", &cache_arg],
        &[],
        &[(
            "search_strings",
            json!({"file_path": path, "query": "different"}),
        )],
    );
    assert_eq!(third.tool_json(2)["cache"], "miss");
    assert_eq!(third.tool_json(2)["total"], 1);
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn an_unusable_cache_directory_is_one_stderr_line_not_a_crash() {
    let work = tempfile::tempdir().unwrap();
    let blocker = work.path().join("a-file");
    std::fs::write(&blocker, "x").unwrap();
    let bad = blocker.join("cache").to_string_lossy().into_owned();
    let path = sample(work.path());
    let run = session(
        &["--cache-dir", &bad],
        &[],
        &[
            (
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            ),
            ("cache_status", json!({})),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.tool_json(2)["total"], 1, "tools still work");
    assert_eq!(run.tool_json(3)["persistent"], false);
    let lines = run
        .stderr
        .lines()
        .filter(|l| l.contains("not usable"))
        .count();
    assert_eq!(lines, 1, "reported once: {}", run.stderr);
    assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
}

#[cfg(unix)]
#[test]
fn a_read_only_default_cache_location_does_not_stop_the_server() {
    use std::os::unix::fs::PermissionsExt;
    // CS25: a hardened host with nowhere to write used to abort at start-up.
    let work = tempfile::tempdir().unwrap();
    let locked = work.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
    let run = session(
        &[],
        &[("XDG_CACHE_HOME", &locked), ("TMPDIR", &locked)],
        &[("cache_status", json!({}))],
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.reply(1)["result"]["serverInfo"]["name"] == "file-scanner");
    assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
}

#[test]
fn no_cache_creates_nothing_and_serves_nothing_from_a_cache() {
    let work = tempfile::tempdir().unwrap();
    let cache = work.path().join("cache");
    let cache_arg = cache.to_string_lossy().into_owned();
    let path = sample(work.path());
    let run = session(
        &["--cache-dir", &cache_arg, "--no-cache"],
        &[],
        &[
            (
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            ),
            (
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            ),
            ("cache_status", json!({})),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_ne!(run.tool_json(3)["cache"], "hit");
    assert_eq!(run.tool_json(4)["enabled"], false);
    assert!(!cache.exists(), "nothing is written");
}

#[test]
fn the_cache_directory_can_come_from_the_environment() {
    let work = tempfile::tempdir().unwrap();
    let cache = work.path().join("from-env");
    let path = sample(work.path());
    let run = session(
        &[],
        &[("FILE_SCANNER_CACHE_DIR", &cache)],
        &[("analyze_file", json!({"file_path": path, "hashes": true}))],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(cache.join("metadata.json").exists());
}

/// A call that is still running when stdin closes (the `printf | file-scanner`
/// pattern) is answered, not dropped: the server drains for several seconds.
#[test]
fn a_slow_call_is_still_answered_after_stdin_closes() {
    let work = tempfile::tempdir().unwrap();
    let cache = work.path().join("cache");
    let big = work.path().join("big.txt");
    let mut text = String::with_capacity(24 << 20);
    let mut n = 0u64;
    while text.len() < (20 << 20) {
        text.push_str(&format!(
            "line {n} value-{} marker\n",
            n.wrapping_mul(2654435761)
        ));
        n += 1;
    }
    std::fs::write(&big, text).unwrap();
    let cache_arg = cache.to_string_lossy().into_owned();
    let run = session(
        &["--cache-dir", &cache_arg],
        &[],
        &[
            (
                "analyze_file",
                json!({"file_path": big.to_string_lossy(), "strings": true, "hashes": true}),
            ),
            (
                "search_strings",
                json!({"file_path": big.to_string_lossy(), "query": "marker"}),
            ),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.tool_json(2).is_object(), "{:?}", run.replies);
    assert!(
        run.reply(3)["result"].is_object(),
        "{:?}\n{}",
        run.replies,
        run.stderr
    );
}

/// SIGTERM, what a supervisor sends, ends the stdio server with exit 0 like SIGINT.
#[cfg(unix)]
#[test]
fn sigterm_ends_the_stdio_server_with_exit_zero() {
    use std::io::{BufRead, BufReader};
    let mut child = Command::new(BIN)
        .args(["mcp-stdio", "--no-cache"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "sigterm-test", "version": "1"}}})
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    .unwrap();
    // Wait for the reply, then stop the server and keep stdin open (the handlers are
    // installed before the handshake, so the timing does not matter).
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("\"id\":1"), "{line}");
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY: signals a child process this test started.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the server ignored SIGTERM for 30 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0), "{status:?}");
}
