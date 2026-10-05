//! Built-in threat detection rules

/// Get built-in YARA rules for threat detection
#[cfg(feature = "builtin-rules")]
pub fn get_builtin_rules() -> Vec<&'static str> {
    vec![
        MALWARE_GENERIC_RULE,
        TROJAN_DETECTION_RULE,
        RANSOMWARE_DETECTION_RULE,
        APT_DETECTION_RULE,
        CRYPTOMINER_DETECTION_RULE,
        INFOSTEALER_DETECTION_RULE,
        BACKDOOR_DETECTION_RULE,
        WEBSHELL_DETECTION_RULE,
        EXPLOIT_DETECTION_RULE,
        PACKER_DETECTION_RULE,
    ]
}

#[cfg(not(feature = "builtin-rules"))]
pub fn get_builtin_rules() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(feature = "builtin-rules")]
const MALWARE_GENERIC_RULE: &str = r#"
rule Generic_Malware_Indicators
{
    meta:
        author = "ThreatFlux"
        description = "Generic malware indicators"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        malware suspicious

    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "SetWindowsHookEx" ascii
        $api5 = "GetProcAddress" ascii
        $api6 = "LoadLibrary" ascii
        
        $crypto1 = { 6A 40 68 00 30 00 00 } // PAGE_EXECUTE_READWRITE
        $crypto2 = { 64 A1 30 00 00 00 } // PEB access
        
        $string1 = "cmd.exe /c" ascii
        $string2 = "powershell.exe" ascii
        $string3 = "rundll32.exe" ascii

    condition:
        3 of ($api*) or 
        any of ($crypto*) or
        2 of ($string*)
}
"#;

#[cfg(feature = "builtin-rules")]
const TROJAN_DETECTION_RULE: &str = r#"
rule Trojan_Behavior_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects common trojan behaviors"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        trojan malware

    strings:
        $keylog1 = "GetAsyncKeyState" ascii
        $keylog2 = "SetWindowsHookEx" ascii
        $keylog3 = "keylogger" ascii nocase
        
        $network1 = "InternetOpen" ascii
        $network2 = "HttpSendRequest" ascii
        $network3 = "FtpPutFile" ascii
        
        $persistence1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $persistence2 = "HKEY_LOCAL_MACHINE" ascii
        
        $anti_debug1 = "IsDebuggerPresent" ascii
        $anti_debug2 = "CheckRemoteDebuggerPresent" ascii

    condition:
        (any of ($keylog*) and any of ($network*)) or
        (any of ($persistence*) and any of ($anti_debug*)) or
        3 of them
}
"#;

#[cfg(feature = "builtin-rules")]
const RANSOMWARE_DETECTION_RULE: &str = r#"
rule Ransomware_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects ransomware characteristics"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        ransomware malware critical

    strings:
        $crypt1 = "CryptAcquireContext" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "CryptEncrypt" ascii
        $crypt4 = "CryptDestroyKey" ascii
        
        $ransom1 = "ransom" ascii nocase
        $ransom2 = "decrypt" ascii nocase
        $ransom3 = "bitcoin" ascii nocase
        $ransom4 = "payment" ascii nocase
        $ransom5 = "files encrypted" ascii nocase
        
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypto" ascii
        
        $note1 = "READ_ME.txt" ascii nocase
        $note2 = "DECRYPT_FILES.txt" ascii nocase
        $note3 = "HOW_TO_RESTORE" ascii nocase

    condition:
        (3 of ($crypt*) and any of ($ransom*)) or
        (any of ($ext*) and any of ($note*)) or
        4 of ($ransom*)
}
"#;

#[cfg(feature = "builtin-rules")]
const APT_DETECTION_RULE: &str = r#"
rule APT_Techniques_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects Advanced Persistent Threat techniques"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        apt advanced targeted

    strings:
        $lateral1 = "psexec" ascii nocase
        $lateral2 = "wmiexec" ascii nocase
        $lateral3 = "smbexec" ascii nocase
        
        $persistence1 = "schtasks" ascii
        $persistence2 = "at.exe" ascii
        $persistence3 = "wevtutil" ascii
        
        $recon1 = "whoami" ascii
        $recon2 = "net user" ascii
        $recon3 = "net group" ascii
        $recon4 = "systeminfo" ascii
        
        $stealth1 = "timestomp" ascii
        $stealth2 = "mimikatz" ascii nocase
        $stealth3 = "kerberoast" ascii nocase

    condition:
        any of ($lateral*) or
        (any of ($persistence*) and any of ($recon*)) or
        any of ($stealth*)
}
"#;

#[cfg(feature = "builtin-rules")]
const CRYPTOMINER_DETECTION_RULE: &str = r#"
rule Cryptominer_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects cryptocurrency mining malware"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        cryptominer malware

    strings:
        $miner1 = "stratum+tcp" ascii
        $miner2 = "xmrig" ascii nocase
        $miner3 = "ccminer" ascii nocase
        $miner4 = "cgminer" ascii nocase
        
        $wallet1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin address
        $wallet2 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ // Monero address
        
        $mining1 = "mining" ascii nocase
        $mining2 = "hashrate" ascii nocase
        $mining3 = "difficulty" ascii nocase
        $mining4 = "share accepted" ascii nocase

    condition:
        any of ($miner*) or
        any of ($wallet*) or
        2 of ($mining*)
}
"#;

#[cfg(feature = "builtin-rules")]
const INFOSTEALER_DETECTION_RULE: &str = r#"
rule InfoStealer_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects information stealing malware"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        infostealer stealer malware

    strings:
        $browser1 = "Login Data" ascii
        $browser2 = "Cookies" ascii
        $browser3 = "History" ascii
        $browser4 = "Bookmarks" ascii
        
        $crypto1 = "wallet.dat" ascii
        $crypto2 = "electrum" ascii nocase
        $crypto3 = "metamask" ascii nocase
        
        $cred1 = "password" ascii nocase
        $cred2 = "credential" ascii nocase
        $cred3 = "login" ascii nocase
        
        $file1 = "\\Google\\Chrome\\User Data" ascii
        $file2 = "\\Mozilla\\Firefox\\Profiles" ascii
        $file3 = "\\AppData\\Local\\Microsoft\\Edge" ascii

    condition:
        (2 of ($browser*) and any of ($file*)) or
        any of ($crypto*) or
        (2 of ($cred*) and any of ($file*))
}
"#;

#[cfg(feature = "builtin-rules")]
const BACKDOOR_DETECTION_RULE: &str = r#"
rule Backdoor_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects backdoor functionality"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        backdoor malware

    strings:
        $socket1 = "WSAStartup" ascii
        $socket2 = "socket" ascii
        $socket3 = "bind" ascii
        $socket4 = "listen" ascii
        $socket5 = "accept" ascii
        
        $shell1 = "cmd.exe" ascii
        $shell2 = "/bin/sh" ascii
        $shell3 = "CreateProcess" ascii
        
        $reverse1 = "connect" ascii
        $reverse2 = "recv" ascii
        $reverse3 = "send" ascii

    condition:
        (3 of ($socket*) and any of ($shell*)) or
        (all of ($reverse*) and any of ($shell*))
}
"#;

#[cfg(feature = "builtin-rules")]
const WEBSHELL_DETECTION_RULE: &str = r#"
rule WebShell_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects web shell scripts"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        webshell backdoor

    strings:
        $php1 = "<?php" ascii
        $php2 = "eval(" ascii
        $php3 = "system(" ascii
        $php4 = "exec(" ascii
        $php5 = "shell_exec(" ascii
        
        $asp1 = "<%eval" ascii nocase
        $asp2 = "Server.CreateObject" ascii nocase
        $asp3 = "WScript.Shell" ascii nocase
        
        $jsp1 = "Runtime.getRuntime()" ascii
        $jsp2 = "ProcessBuilder" ascii

    condition:
        ($php1 and 2 of ($php2,$php3,$php4,$php5)) or
        ($asp1 or ($asp2 and $asp3)) or
        any of ($jsp*)
}
"#;

#[cfg(feature = "builtin-rules")]
const EXPLOIT_DETECTION_RULE: &str = r#"
rule Exploit_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects exploit techniques"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        exploit malware

    strings:
        $shellcode1 = { 90 90 90 90 } // NOP sled
        $shellcode2 = { CC CC CC CC } // INT3 padding
        $shellcode3 = { EB FE } // JMP $
        
        $rop1 = "ROP" ascii nocase
        $rop2 = "gadget" ascii nocase
        
        $exploit1 = "exploit" ascii nocase
        $exploit2 = "payload" ascii nocase
        $exploit3 = "shellcode" ascii nocase
        
        $vuln1 = "CVE-" ascii
        $vuln2 = "MS" ascii
        
        $overflow1 = { 41 41 41 41 41 41 41 41 } // AAAAAAAA
        $overflow2 = { 42 42 42 42 42 42 42 42 } // BBBBBBBB

    condition:
        any of ($shellcode*) or
        any of ($rop*) or
        2 of ($exploit*) or
        any of ($overflow*)
}
"#;

#[cfg(feature = "builtin-rules")]
const PACKER_DETECTION_RULE: &str = r#"
rule Packer_Detection
{
    meta:
        author = "ThreatFlux"
        description = "Detects packed/compressed executables"
        version = "1.0"
        date = "2024-01-01"
        
    tags:
        packer compressed suspicious

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX" ascii
        
        $aspack1 = "aPLib" ascii
        $aspack2 = "ASPack" ascii
        
        $vmprotect1 = "VMProtect" ascii
        $themida1 = "Themida" ascii
        $mpress1 = "MPRESS" ascii
        
        $generic1 = "This program cannot be run in DOS mode" ascii
        $generic2 = { 60 E8 00 00 00 00 } // PUSHAD; CALL $+5

    condition:
        any of ($upx*) or
        any of ($aspack*) or
        any of ($vmprotect1, $themida1, $mpress1) or
        ($generic1 and $generic2)
}
"#;
