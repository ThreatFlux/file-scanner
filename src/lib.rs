#![allow(
    dead_code,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::only_used_in_recursion,
    clippy::ref_option,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unnecessary_debug_formatting,
    clippy::useless_let_if_seq,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::wildcard_enum_match_arm
)]

pub mod archive_analysis;
pub mod behavioral_analysis;
pub mod binary_parser;
pub mod cache;
pub mod call_graph;
pub mod code_metrics;
pub mod control_flow;
pub mod dependency_analysis;
pub mod disassembly;
pub mod entropy_analysis;
pub mod function_analysis;
pub mod hash;
pub mod hexdump;
pub mod java_analysis;
pub mod mcp_server;
pub mod mcp_transport;
pub mod metadata;
pub mod npm_analysis;
pub mod npm_vuln_db;
pub mod ole_vba_analysis;
pub mod pdf_analysis;
pub mod python_analysis;
pub mod python_vuln_db;
pub mod rar_analysis;
pub mod repository_integrity;
pub mod script_analysis;
pub mod sevenz_analysis;
pub mod signature;
pub mod string_tracker_compat;
pub mod strings;
pub mod taint_tracking;
pub mod tar_analysis;
pub mod threat_detection;
pub mod typosquatting_detection;
pub mod vulnerability_detection;
