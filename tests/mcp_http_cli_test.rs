//! The command line of `mcp-http` and `mcp-sse`: flags, banner, warnings and
//! shutdown on SIGTERM, with the real binary.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_file-scanner");

struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
    port: u16,
    stderr: Vec<String>,
    _cache_home: TempDir,
}

impl Server {
    /// Start `file-scanner <args>` (port 0) and wait for the banner.
    fn start(args: &[&str], envs: &[(&str, &str)]) -> Self {
        let cache_home = TempDir::new().unwrap();
        let mut command = Command::new(BIN);
        command
            .args(args)
            .args(["--port", "0"])
            .env("TMPDIR", cache_home.path())
            .env("FILE_SCANNER_CACHE_DIR", cache_home.path().join("cache"))
            .env_remove("FILE_SCANNER_AUTH_TOKEN")
            .env_remove("FILE_SCANNER_ALLOWED_ROOTS")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (name, value) in envs {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let port = loop {
            let line = lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no banner; stderr so far: {seen:?}"));
            seen.push(line.clone());
            if let Some(rest) = line.split("listening on http://").nth(1) {
                let address = rest.trim_end_matches("/mcp");
                break address.rsplit(':').next().unwrap().parse().unwrap();
            }
        };
        Self {
            child,
            lines,
            port,
            stderr: seen,
            _cache_home: cache_home,
        }
    }

    /// Everything printed so far, banner included.
    fn drain(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.stderr.push(line);
        }
        self.stderr.join("\n")
    }

    /// A minimal HTTP/1.1 GET; returns (status, body).
    fn get(&self, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = format!("GET {path} HTTP/1.1\r\nConnection: close\r\n");
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: 127.0.0.1:{}\r\n", self.port));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([&format!("-{name}"), &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Wait for the process to exit; returns its exit code (None: killed by a signal).
    fn wait(&mut self, limit: Duration) -> Option<i32> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            assert!(Instant::now() < deadline, "the server did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn version_flag_prints_the_package_version() {
    let output = Command::new(BIN).arg("--version").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        text.trim(),
        format!("file-scanner {}", env!("CARGO_PKG_VERSION"))
    );
    let short = Command::new(BIN).arg("-V").output().unwrap();
    assert!(short.status.success());
}

#[test]
fn help_lists_the_network_and_scope_flags_for_every_mcp_subcommand() {
    for sub in ["mcp-http", "mcp-sse"] {
        let output = Command::new(BIN).args([sub, "--help"]).output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        for flag in [
            "--port",
            "--host",
            "--allowed-host",
            "--allowed-origin",
            "--auth-token",
            "FILE_SCANNER_AUTH_TOKEN",
            "--allow-root",
        ] {
            assert!(text.contains(flag), "{sub}: {flag} missing from\n{text}");
        }
    }
    let output = Command::new(BIN)
        .args(["mcp-stdio", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("--allow-root"));
}

#[test]
fn the_default_bind_is_loopback_and_the_banner_says_what_is_active() {
    let mut server = Server::start(&["mcp-http"], &[]);
    let text = server.drain();
    assert!(text.contains("listening on http://127.0.0.1:"), "{text}");
    assert!(text.contains("Bearer token: not set"), "{text}");
    assert!(text.contains("File access: unrestricted"), "{text}");
    assert!(
        text.contains("Host allow-list: localhost, 127.0.0.1, ::1"),
        "{text}"
    );
    assert!(!text.contains("warning:"), "{text}");
    let (status, body) = server.get("/health", &[]);
    assert_eq!(status, 200, "{body}");
    server.signal("TERM");
    assert_eq!(server.wait(Duration::from_secs(10)), Some(0));
}

#[test]
fn sigterm_and_sigint_stop_the_server_with_exit_code_0() {
    for signal in ["TERM", "INT"] {
        let mut server = Server::start(&["mcp-http"], &[]);
        assert_eq!(server.get("/health", &[]).0, 200);
        server.signal(signal);
        assert_eq!(server.wait(Duration::from_secs(10)), Some(0), "SIG{signal}");
        assert!(server.drain().contains("shutting down"));
    }
}

/// A minimal HTTP/1.1 POST of a JSON body to `/tools/call`; returns (status, body).
fn post_call(port: u16, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let request = format!(
        "POST /tools/call HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (
        status,
        response.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

#[test]
fn a_signal_with_a_rest_call_in_flight_stops_the_server_promptly() {
    let mut server = Server::start(&["mcp-http"], &[]);
    // A file that takes long enough to analyse that the call is normally
    // still running when the signal lands: 64 MiB of distinct text lines.
    let scratch = TempDir::new().unwrap();
    let sample = scratch.path().join("slow_sample.bin");
    {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&sample).unwrap());
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..(2 * 1024 * 1024) {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            writeln!(file, "line_{state:016x}_padding_text_here").unwrap();
        }
    }
    let port = server.port;
    let body = format!(
        r#"{{"name":"analyze_file","arguments":{{"file_path":{},"all":true}}}}"#,
        serde_json::to_string(&sample.to_string_lossy()).unwrap()
    );
    let caller = std::thread::spawn(move || post_call(port, &body));
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    server.signal("INT");
    assert_eq!(server.wait(Duration::from_secs(8)), Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    // The call in flight gets a clean answer. Which one depends on timing: a
    // call cut by the shutdown is refused with 503 ("shutting down"); a call
    // that finished just before the signal is answered 200 with a complete
    // JSON body. Anything else (a reset, an empty or half answer) fails.
    let (status, answer) = caller.join().unwrap();
    match status {
        503 => assert!(answer.contains("shutting down"), "{answer}"),
        200 => {
            let parsed: serde_json::Value = serde_json::from_str(&answer)
                .unwrap_or_else(|error| panic!("200 with an incomplete body ({error}): {answer}"));
            assert!(parsed.is_object(), "{answer}");
        }
        other => panic!("status {other}: {answer}"),
    }
    assert!(
        !server.drain().contains("grace period"),
        "the grace period should not have been needed"
    );
}

#[test]
fn refused_requests_are_logged_on_stderr_without_the_token() {
    let mut server = Server::start(&["mcp-http", "--auth-token", "very-secret-token"], &[]);
    assert_eq!(server.get("/api/info", &[]).0, 401);
    assert_eq!(
        server
            .get(
                "/api/info",
                &[("Authorization", "Bearer wrong-token-value")]
            )
            .0,
        401
    );
    assert_eq!(server.get("/health", &[("Host", "evil.example")]).0, 403);
    assert_eq!(
        server
            .get(
                "/health",
                &[
                    ("Origin", "https://evil.example"),
                    ("Authorization", "Bearer very-secret-token")
                ]
            )
            .0,
        403
    );
    // The log lines are written before the answers; give the pipe a moment.
    std::thread::sleep(Duration::from_millis(200));
    let text = server.drain();
    for expected in [
        "refused GET \"/api/info\" (401): no bearer token sent",
        "refused GET \"/api/info\" (401): bearer token does not match",
        "refused GET \"/health\" (403): Host \"evil.example\" is not allowed",
        "refused GET \"/health\" (403): Origin \"https://evil.example\" is not allowed",
    ] {
        assert!(text.contains(expected), "{expected}\n{text}");
    }
    for secret in ["very-secret-token", "wrong-token-value"] {
        assert!(!text.contains(secret), "the token leaked: {text}");
    }
}

#[test]
fn a_non_loopback_host_without_a_token_warns_on_stderr() {
    let mut server = Server::start(&["mcp-http", "--host", "0.0.0.0"], &[]);
    let text = server.drain();
    assert!(
        text.contains("warning: listening on 0.0.0.0 without a bearer token"),
        "{text}"
    );
    assert!(text.contains("listening on http://0.0.0.0:"), "{text}");
    drop(server);

    // With a token (from the environment) the open-bind warning is gone.
    let mut protected = Server::start(
        &["mcp-http", "--host", "0.0.0.0"],
        &[("FILE_SCANNER_AUTH_TOKEN", "env-token-value")],
    );
    let text = protected.drain();
    assert!(!text.contains("without a bearer token"), "{text}");
    assert!(
        text.contains("required on every route except /health"),
        "{text}"
    );
    assert!(
        !text.contains("env-token-value"),
        "the token is never printed"
    );
    assert_eq!(protected.get("/health", &[]).0, 200);
    assert_eq!(protected.get("/cache/stats", &[]).0, 401);
    assert_eq!(
        protected
            .get(
                "/cache/stats",
                &[("Authorization", "Bearer env-token-value")]
            )
            .0,
        200
    );
}

#[test]
fn the_flags_reach_the_guard() {
    let root = TempDir::new().unwrap();
    let root_arg = root.path().to_string_lossy().into_owned();
    let mut server = Server::start(
        &[
            "mcp-http",
            "--allowed-host",
            "scanner.internal",
            "--allowed-origin",
            "https://app.example",
            "--auth-token",
            "flag-token",
            "--allow-root",
            &root_arg,
        ],
        &[],
    );
    let text = server.drain();
    assert!(text.contains("scanner.internal"), "{text}");
    assert!(text.contains("https://app.example"), "{text}");
    assert!(text.contains("File access: limited to"), "{text}");
    let auth = ("Authorization", "Bearer flag-token");
    assert_eq!(
        server.get("/health", &[("Host", "scanner.internal:80")]).0,
        200
    );
    assert_eq!(server.get("/health", &[("Host", "other.example")]).0, 403);
    assert_eq!(
        server
            .get("/api/info", &[auth, ("Origin", "https://app.example")])
            .0,
        200
    );
    assert_eq!(
        server
            .get("/api/info", &[auth, ("Origin", "https://evil.example")])
            .0,
        403
    );
    assert_eq!(server.get("/api/info", &[]).0, 401);
}

#[test]
fn allow_root_flag_beats_the_environment_variable() {
    let flag_root = TempDir::new().unwrap();
    let env_root = TempDir::new().unwrap();
    let flag_arg = flag_root.path().to_string_lossy().into_owned();
    let env_value = env_root.path().to_string_lossy().into_owned();
    let mut server = Server::start(
        &["mcp-http", "--allow-root", &flag_arg],
        &[("FILE_SCANNER_ALLOWED_ROOTS", &env_value)],
    );
    let text = server.drain();
    let limited = text
        .lines()
        .find(|l| l.contains("File access"))
        .unwrap()
        .to_string();
    assert!(
        limited.contains(&flag_arg) && !limited.contains(&env_value),
        "{limited}"
    );
    drop(server);

    let mut from_env = Server::start(&["mcp-http"], &[("FILE_SCANNER_ALLOWED_ROOTS", &env_value)]);
    let text = from_env.drain();
    assert!(
        text.contains("File access: limited to") && text.contains(&env_value),
        "{text}"
    );
}

#[test]
fn mcp_sse_is_a_deprecated_alias_for_the_same_server() {
    let mut server = Server::start(&["mcp-sse"], &[]);
    let text = server.drain();
    assert!(text.contains("mcp-sse is deprecated"), "{text}");
    assert_eq!(
        text.matches("deprecated").count(),
        1,
        "one deprecation line: {text}"
    );
    assert_eq!(server.get("/health", &[]).0, 200);
    assert_eq!(server.get("/sse", &[]).0, 404, "the old /sse route is gone");
}

#[test]
fn bad_settings_fail_at_start_up_with_the_fix() {
    let output = Command::new(BIN)
        .args(["mcp-http", "--port", "0", "--allowed-origin", "example.com"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("--allowed-origin"), "{text}");

    let output = Command::new(BIN)
        .args(["mcp-http", "--port", "0", "--auth-token", ""])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("auth token"));
}
