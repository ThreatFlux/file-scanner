use super::*;

fn launcher() -> Launcher {
    Launcher {
        bwrap: PathBuf::from("/usr/bin/bwrap"),
        worker_exe: PathBuf::from("/opt/fs/file-scanner"),
        runtime: vec![
            RuntimeMount::Bind(PathBuf::from("/usr")),
            RuntimeMount::Symlink {
                target: PathBuf::from("usr/lib"),
                at: PathBuf::from("/lib"),
            },
            RuntimeMount::BindIfPresent(PathBuf::from("/etc/ld.so.cache")),
        ],
        deadline: DEFAULT_DEADLINE,
        memory_bytes: DEFAULT_MEMORY_BYTES,
        startup_bytes: 0,
    }
}

#[tokio::test]
async fn a_limit_below_the_startup_footprint_is_refused_before_launch() {
    let mut tight = launcher().with_limits(Duration::from_secs(1), 16 * MIB);
    tight.startup_bytes = 200 * MIB;
    let error = tight.run(tempfile::tempfile().unwrap()).await.unwrap_err();
    assert!(
        matches!(error, WorkerError::MemoryBelowStartup { .. }),
        "{error}"
    );
    assert!(error.to_string().starts_with("startup memory refusal"));
}

#[test]
fn the_command_line_isolates_and_mounts_only_the_allowlist() {
    let args: Vec<String> = launcher()
        .arguments()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let joined = args.join(" ");
    assert!(joined
        .starts_with("--unshare-all --die-with-parent --new-session --clearenv --cap-drop ALL "));
    for flag in [
        "--share-net",
        "--bind ",
        "--dev-bind",
        "--proc",
        "--dev ",
        "--tmpfs",
    ] {
        assert!(!joined.contains(flag), "{flag} in {joined}");
    }
    let mounted: Vec<&str> = args
        .windows(3)
        .filter(|w| w[0] == "--ro-bind" || w[0] == "--ro-bind-try")
        .map(|w| w[1].as_str())
        .collect();
    assert_eq!(
        mounted,
        ["/usr", "/etc/ld.so.cache", "/opt/fs/file-scanner"],
        "{joined}"
    );
    assert!(joined.contains("--symlink usr/lib /lib"), "{joined}");
    assert!(joined.contains("--remount-ro /"), "{joined}");
    assert!(joined.ends_with(&format!("-- {WORKER_IN_SANDBOX} {WORKER_ARG}")));
}

#[test]
fn limits_have_a_floor() {
    let tight = launcher().with_limits(Duration::ZERO, 0);
    assert_eq!(tight.deadline(), Duration::from_millis(1));
    assert_eq!(tight.memory_bytes(), MIB);
}

#[test]
fn answers_are_checked_before_use() {
    let good = WorkerAnswer {
        mime_type: "application/x-elf".to_string(),
        hashes: Hashes {
            md5: "0".repeat(32),
            sha256: EMPTY_SHA256.to_string(),
            sha512: "a".repeat(128),
            blake3: "f".repeat(64),
        },
    };
    assert!(good.check().is_ok());
    let mut bad = good.clone();
    bad.mime_type = "text/html; <script>".to_string();
    assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
    let mut bad = good.clone();
    bad.hashes.sha256 = EMPTY_SHA256.to_uppercase();
    assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
    let mut bad = good;
    bad.hashes.md5.push('0');
    assert!(matches!(bad.check(), Err(WorkerError::BadAnswer(_))));
    let extra = r#"{"mime_type":"application/pdf","hashes":{"md5":"","sha256":"","sha512":"","blake3":""},"path":"/etc/passwd"}"#;
    assert!(serde_json::from_str::<WorkerAnswer>(extra).is_err());
    assert!(matches!(
        parse_answer(&vec![b' '; MAX_WORKER_STDOUT + 1]),
        Err(WorkerError::BadAnswer(_))
    ));
}

#[test]
fn failures_name_the_limit() {
    let deadline = WorkerError::Deadline {
        deadline: Duration::from_millis(1500),
    };
    assert!(
        deadline.to_string().contains("1.5 s deadline"),
        "{deadline}"
    );
    let memory = WorkerError::Memory {
        memory_bytes: 16 * MIB,
    };
    assert!(
        memory.to_string().contains("16 MiB memory limit"),
        "{memory}"
    );
    let failed = WorkerError::Failed {
        status: "exit status: 1".to_string(),
        memory_bytes: 16 * MIB,
        deadline: Duration::from_secs(2),
        detail: printable(b"bwrap: \x1b[31msetting up uid map\n"),
    };
    let text = failed.to_string();
    assert!(
        text.contains("16 MiB memory limit") && text.contains("2 s"),
        "{text}"
    );
    assert!(!text.chars().any(char::is_control), "{text:?}");
}
