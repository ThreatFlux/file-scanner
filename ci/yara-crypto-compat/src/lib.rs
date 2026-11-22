//! Compile the actual reviewed verification modules against stable crypto.

#[rustfmt::skip]
#[path = "../../../vendor/yara-x-1.24.0/src/modules/utils/asn1.rs"]
pub mod asn1;
#[rustfmt::skip]
#[path = "../../../vendor/yara-x-1.24.0/src/modules/utils/crypto.rs"]
pub mod crypto;
