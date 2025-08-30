//! Detection engines for threat analysis

#[cfg(feature = "yara-engine")]
pub mod yara;

// ClamAV engine disabled due to shlex security vulnerability RUSTSEC-2024-0006
// #[cfg(feature = "clamav-engine")]
// pub mod clamav;

#[cfg(feature = "pattern-matching")]
pub mod patterns;
