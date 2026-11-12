//! `disassemble` and `read_hex`: the two targeted looks at the code and the
//! bytes of one file. Neither ever returns a whole binary.
//!
//! `disassemble` is served from the section cache, which keeps a bounded part
//! of the disassembly (the function table, the first instructions); a range
//! outside that part is decoded again for the call.
//! `read_hex` reads the file directly: a few hundred bytes need no cache.

use std::{collections::HashMap, fmt::Write as _};

use rmcp::{model::JsonObject, schemars};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    identify,
    sections::{plan, Ctx, Engine, Failure, Options},
};
use crate::{
    hexdump::{generate_hex_dump, HexDumpOptions},
    mcp_server::{
        output::{fit_rows, page, parse_request, render, respond_text, tool_error, DEFAULT_LIMIT},
        paths::Expect,
        FileScannerMcp,
    },
};

/// Instructions a `disassemble` call lists when the caller names no count.
pub const DEFAULT_INSTRUCTIONS: usize = 200;
/// Most instructions one `disassemble` call lists.
pub const MAX_INSTRUCTIONS: usize = 1000;
/// Bytes a `read_hex` call reads when the caller names no length.
pub const DEFAULT_HEX_LENGTH: usize = 256;
/// Most bytes one `read_hex` call reads.
pub const MAX_HEX_LENGTH: usize = 4096;
/// Candidates named in an "ambiguous function" error.
const CANDIDATES: usize = 12;

pub(super) const DISASSEMBLE_DESCRIPTION: &str =
    "Read the machine code of ONE function or address \
range of an ELF or thin Mach-O binary as a text listing (address, bytes, mnemonic, operands, direct call and jump targets named when they match a function). Never the whole binary. Pass `function` (a name from query_analysis section \
`disassembly` list `functions`, or from analyze_file's symbols) or `address` (\"0x401136\" or a \
number); the listing is capped at `max_instructions` (default 200, at most 1000) and says where to \
continue (`next_address`). With neither, it lists the functions (name, address, size, complexity) \
paged with `offset`/`limit`/`filter`, so you can pick one. A bounded part of the \
disassembly is cached by the file's SHA-256 (`cache: hit`); a range outside that part is decoded \
again for the call, which takes a moment on a large file. Call analyze_file first to see whether \
the file is an executable; use query_analysis for suspicious patterns and read_hex for raw bytes.";

pub(super) const READ_HEX_DESCRIPTION: &str = "Read raw bytes of a file as a hex dump: `offset` \
(a negative offset counts from the end of the file, so -64 is the last 64 bytes, headers and \
trailers/overlays) and `length` (default 256, at most 4096). The answer says the file's total size, \
whether the dump reached the end of the file, and the offsets of the next and previous pages \
(`next_offset`, `previous_offset`). Use it after analyze_file or query_analysis name an offset \
(string offsets, section or high-entropy regions); for code use disassemble.";

/// An address as a number or a string: `4198710`, `"0x401136"`.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum AddressArg {
    Number(u64),
    Text(String),
}

impl<'de> Deserialize<'de> for AddressArg {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Number(n) => n.as_u64().map(Self::Number).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "address {n} is not allowed: use a non-negative whole number or a string \
                     like \"0x401136\""
                ))
            }),
            Value::String(text) => Ok(Self::Text(text)),
            other => Err(serde::de::Error::custom(format!(
                "address {other} is not allowed: use a non-negative whole number or a string \
                 like \"0x401136\""
            ))),
        }
    }
}

impl AddressArg {
    fn parse(&self) -> Result<u64, String> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::Text(text) => parse_address(text),
        }
    }
}

/// `0x...` is hexadecimal, anything else decimal.
fn parse_address(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    parsed.map_err(|_| {
        format!(
            "'{text}' is not an address. Use a hexadecimal address with a 0x prefix, for example \
             \"0x401136\", or a decimal number."
        )
    })
}

/// The arguments of `read_hex`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadHexRequest {
    #[schemars(description = "Absolute path of the file (a leading ~/ is expanded)")]
    pub file_path: String,
    #[schemars(
        description = "Byte offset to start at (default 0). Negative counts from the end of the file: -64 is the last 64 bytes"
    )]
    pub offset: Option<i64>,
    #[schemars(description = "Bytes to read (default 256, at most 4096)")]
    pub length: Option<usize>,
}

/// The arguments of `disassemble`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisassembleRequest {
    #[schemars(description = "Absolute path of the binary (a leading ~/ is expanded)")]
    pub file_path: String,
    #[schemars(
        description = "Function to list: its name (exact, else a unique case-insensitive match) or its address"
    )]
    pub function: Option<String>,
    #[schemars(
        description = "Address to start at, \"0x401136\" or a number: the function that contains it is listed from that instruction"
    )]
    pub address: Option<AddressArg>,
    #[schemars(description = "Most instructions to list (default 200, at most 1000)")]
    pub max_instructions: Option<usize>,
    #[schemars(
        description = "With no function or address: keep only functions whose name contains this text"
    )]
    pub filter: Option<String>,
    #[schemars(description = "With no function or address: functions to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(
        description = "With no function or address: functions to return (default 50, at most 500)"
    )]
    pub limit: Option<usize>,
    #[schemars(
        description = "Universal (fat) Mach-O only: names a slice (binary_info.universal_slices), but disassembly does not read one of its slices yet, so a fat binary is refused whatever this says"
    )]
    pub arch: Option<String>,
}

// ---------------------------------------------------------------------------
// read_hex
// ---------------------------------------------------------------------------

/// Where a `read_hex` dump starts, and a note when the request was adjusted.
fn hex_start(offset: i64, size: u64) -> Result<(u64, Option<String>), String> {
    if offset >= 0 {
        let start = offset as u64;
        if size > 0 && start >= size {
            return Err(format!(
                "offset {offset} is at or past the end of the file, which is {size} bytes long. \
                 Use an offset below {size}, or a negative offset such as -64 for the last 64 bytes."
            ));
        }
        return Ok((start, None));
    }
    let back = offset.unsigned_abs();
    if back > size {
        Ok((
            0,
            Some(format!(
                "offset {offset} reaches before the start of the {size}-byte file; the dump starts at 0"
            )),
        ))
    } else {
        Ok((size - back, None))
    }
}

impl FileScannerMcp {
    /// The `read_hex` tool body.
    pub(crate) async fn run_read_hex(&self, args: JsonObject) -> rmcp::model::CallToolResult {
        let (request, budget, _raw) = match parse_request::<ReadHexRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let length = request.length.unwrap_or(DEFAULT_HEX_LENGTH);
        if length == 0 || length > MAX_HEX_LENGTH {
            return tool_error(format!(
                "length {length} is not allowed: ask for 1 to {MAX_HEX_LENGTH} bytes per call and \
                 page with next_offset."
            ));
        }
        let path = match self
            .state
            .resolve_path(&request.file_path, "File", Expect::File)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        let size = match std::fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(error) => {
                return tool_error(format!("Cannot read {}: {error}", request.file_path));
            }
        };
        let (start, note) = match hex_start(request.offset.unwrap_or(0), size) {
            Ok(start) => start,
            Err(message) => return tool_error(message),
        };
        let file_path = path.to_string_lossy().into_owned();
        let outcome = self
            .state
            .run_blocking("read_hex", move || {
                let dump = generate_hex_dump(
                    &path,
                    HexDumpOptions {
                        offset: start,
                        length: Some(length),
                        bytes_per_line: 16,
                        max_lines: None,
                    },
                )
                .map_err(|e| format!("Cannot read {file_path}: {e:#}"))?;
                let end = dump.offset + dump.length as u64;
                let lines: Vec<String> = dump
                    .lines
                    .iter()
                    .map(|l| format!("{:08x}  {}  |{}|", l.offset, l.hex_bytes, l.ascii_repr))
                    .collect();
                let mut value = json!({
                    "file_path": file_path,
                    "offset": dump.offset,
                    "length": dump.length,
                    "total_bytes": dump.total_bytes,
                    "end_of_file": end >= dump.total_bytes,
                    "lines": lines,
                });
                if end < dump.total_bytes {
                    value["next_offset"] = end.into();
                }
                if dump.offset > 0 {
                    value["previous_offset"] = dump.offset.saturating_sub(length as u64).into();
                }
                if let Some(note) = note {
                    value["note"] = note.into();
                }
                if dump.total_bytes == 0 {
                    value["note"] = "the file is empty".into();
                }
                let all_lines = dump.lines.len();
                fit_rows(&mut value, "lines", budget, 0, all_lines);
                let kept = value["lines"].as_array().map_or(0, Vec::len);
                if kept < all_lines {
                    // The budget cut the dump: say which bytes were sent.
                    let sent = (kept as u64 * 16).min(dump.length as u64);
                    let next = dump.offset + sent;
                    value["length"] = sent.into();
                    value["end_of_file"] = false.into();
                    value["next_offset"] = next.into();
                    value["hint"] = format!(
                        "The dump was cut to {sent} bytes to fit max_output_bytes; repeat the \
                         call with offset {next} for the rest."
                    )
                    .into();
                    if let Some(map) = value.as_object_mut() {
                        map.remove("returned");
                    }
                }
                Ok::<String, String>(render(value, budget))
            })
            .await;
        match outcome {
            Err(crash) => tool_error(crash),
            Ok(Err(message)) => tool_error(message),
            Ok(Ok(text)) => respond_text(text),
        }
    }
}

// ---------------------------------------------------------------------------
// disassemble
// ---------------------------------------------------------------------------

/// Instructions decoded again around an address that the stored section does
/// not hold.
const WINDOW_INSTRUCTIONS: usize = 2_000;

/// The stored section with what the request needs filled in when the bounded
/// section does not hold it: the instructions of the one function asked for,
/// or a window of the flat list from the address. The typed disassembly is
/// decoded again for that (`window_note` says so); nothing else changes.
fn with_window(
    section: &std::sync::Arc<Value>,
    request: &DisassembleRequest,
    typed: &mut dyn FnMut()
        -> Result<std::sync::Arc<crate::disassembly::DisassemblyResult>, String>,
) -> Result<(std::sync::Arc<Value>, Option<String>), String> {
    let functions = section
        .get("functions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let address = request
        .address
        .as_ref()
        .map(AddressArg::parse)
        .transpose()?
        .or_else(|| {
            request
                .function
                .as_deref()
                .filter(|f| f.trim_start().starts_with("0x"))
                .and_then(|f| parse_address(f).ok())
        });
    let function = match (&request.function, address) {
        (Some(name), None) => Some(find_function(functions, name, section)?),
        (_, Some(a)) => function_containing(functions, a),
        (None, None) => return Ok((std::sync::Arc::clone(section), None)),
    };
    let stored_count = |f: &Value| {
        f.get("instructions")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    let flat = section
        .get("instructions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let flat_total = section
        .get("instructions_total")
        .and_then(Value::as_u64)
        .map_or(flat.len(), |n| n as usize);
    let truncated = flat_total > flat.len();
    let last_stored = flat.last().and_then(address_of);
    let page = request
        .max_instructions
        .unwrap_or(DEFAULT_INSTRUCTIONS)
        .clamp(1, MAX_INSTRUCTIONS);
    // The stored list answers a page only when the whole page lies inside it:
    // a page that would run past its last instruction continues in a decoded
    // window, so the walk never stops at the stored part.
    let flat_covers_page = |a: u64| {
        !truncated
            || flat
                .iter()
                .position(|i| {
                    address_of(i).is_some_and(|start| {
                        let size = i.get("size").and_then(Value::as_u64).unwrap_or(1).max(1);
                        start <= a && a < start.saturating_add(size)
                    })
                })
                .is_some_and(|at| at + page <= flat.len())
    };
    // A function whose instructions are not stored is read from the flat list
    // only when its whole range lies inside the stored part.
    let function_in_flat = |f: &Value| {
        !truncated
            || (f.get("size").and_then(Value::as_u64).unwrap_or(0) > 0
                && address_of(f).is_some_and(|start| {
                    let end =
                        start.saturating_add(f.get("size").and_then(Value::as_u64).unwrap_or(0));
                    last_stored.is_some_and(|last| last >= end)
                }))
    };
    let need_function = function
        .filter(|f| instruction_count(f).unwrap_or(0) > stored_count(f) && !function_in_flat(f));
    let need_flat = function.is_none() && address.is_some_and(|a| !flat_covers_page(a));
    if need_function.is_none() && !need_flat {
        return Ok((std::sync::Arc::clone(section), None));
    }
    let result = typed()?;
    let mut patched = (**section).clone();
    if let Some(wanted) = need_function {
        let (at, name) = (
            address_of(wanted),
            wanted.get("name").and_then(Value::as_str),
        );
        if let Some(full) = result
            .functions
            .iter()
            .find(|f| Some(f.address) == at && Some(f.name.as_str()) == name)
        {
            // A window of the function from the requested address (or its
            // start), not all of it: a function can hold a million instructions.
            let from = address
                .and_then(|a| {
                    full.instructions.iter().position(|i| {
                        i.address <= a && a < i.address.saturating_add(i.size.max(1) as u64)
                    })
                })
                .unwrap_or(0);
            let instructions: Vec<Value> = full.instructions[from..]
                .iter()
                .take(WINDOW_INSTRUCTIONS)
                .map(super::sections::instruction_value)
                .collect();
            let window_from = from;
            if let Some(entry) = patched
                .get_mut("functions")
                .and_then(Value::as_array_mut)
                .and_then(|list| {
                    list.iter_mut().find(|f| {
                        address_of(f) == at && f.get("name").and_then(Value::as_str) == name
                    })
                })
            {
                entry["instructions"] = instructions.into();
                entry["window_from"] = window_from.into();
            }
        }
    } else if let Some(a) = address {
        let from = result
            .instructions
            .iter()
            .position(|i| i.address <= a && a < i.address.saturating_add(i.size.max(1) as u64))
            .or_else(|| result.instructions.iter().position(|i| i.address >= a));
        if let Some(from) = from {
            let window: Vec<Value> = result.instructions[from..]
                .iter()
                .take(WINDOW_INSTRUCTIONS)
                .map(super::sections::instruction_value)
                .collect();
            let beyond = result
                .instructions
                .len()
                .saturating_sub(from + window.len());
            patched["instructions"] = window.into();
            patched["instructions_beyond"] = beyond.into();
        }
    }
    Ok((
        std::sync::Arc::new(patched),
        Some(
            "These instructions are not in the stored section (it keeps a bounded part of a \
             large disassembly), so the file was decoded again for them."
                .to_string(),
        ),
    ))
}

/// Instructions a function has: its stored count, else the stored list's length.
fn instruction_count(function: &Value) -> Option<usize> {
    function
        .get("instruction_count")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .or_else(|| {
            function
                .get("instructions")
                .and_then(Value::as_array)
                .map(Vec::len)
        })
}

fn address_of(value: &Value) -> Option<u64> {
    value.get("address").and_then(Value::as_u64)
}

/// `a:b` style "0x401136 (main)" naming for error texts.
fn describe(function: &Value) -> String {
    format!(
        "{} at 0x{:x}",
        function.get("name").and_then(Value::as_str).unwrap_or("?"),
        address_of(function).unwrap_or(0)
    )
}

/// The function a `function` argument names.
fn find_function<'a>(
    functions: &'a [Value],
    query: &str,
    section: &Value,
) -> Result<&'a Value, String> {
    let query = query.trim();
    let by_name = |matches: &dyn Fn(&str) -> bool| -> Vec<&'a Value> {
        functions
            .iter()
            .filter(|f| f.get("name").and_then(Value::as_str).is_some_and(matches))
            .collect()
    };
    let exact = by_name(&|n| n == query);
    let candidates = if exact.is_empty() {
        let lower = query.to_lowercase();
        let ci = by_name(&|n| n.to_lowercase() == lower);
        if ci.is_empty() {
            by_name(&|n| n.to_lowercase().contains(&lower))
        } else {
            ci
        }
    } else {
        exact
    };
    match candidates.as_slice() {
        [one] => Ok(one),
        [] => {
            // What the analyzer said about functions it left out.
            let truncated = section
                .pointer("/coverage/truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let limits: Vec<&str> = section
                .pointer("/coverage/notes")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(Value::as_str)
                .filter(|n| truncated || n.starts_with("Limit"))
                .collect();
            Err(format!(
                "No function named '{query}' in this file's disassembly ({} functions). Call \
                 disassemble with only file_path (and `filter`: part of a name) to list them, or \
                 pass an `address`.{}",
                functions.len(),
                if limits.is_empty() {
                    String::new()
                } else {
                    format!(" The analyzer said: {}", limits.join(" "))
                }
            ))
        }
        many => {
            let list = many
                .iter()
                .take(CANDIDATES)
                .map(|f| describe(f))
                .collect::<Vec<_>>()
                .join("; ");
            let more = many.len().saturating_sub(CANDIDATES);
            Err(format!(
                "'{query}' matches {} functions: {list}{}. Pass the exact name or an `address`.",
                many.len(),
                if more > 0 {
                    format!(" (and {more} more)")
                } else {
                    String::new()
                }
            ))
        }
    }
}

/// The function whose range holds `address`.
fn function_containing(functions: &[Value], address: u64) -> Option<&Value> {
    functions.iter().find(|f| {
        let start = address_of(f).unwrap_or(u64::MAX);
        let size = f.get("size").and_then(Value::as_u64).unwrap_or(0);
        start <= address && address < start.saturating_add(size.max(1))
    })
}

/// The address a direct `call` or jump names in its operand (`call 0x1549`),
/// for when the analyzer did not resolve it.
fn direct_target(mnemonic: &str, operands: &str) -> Option<u64> {
    let mnemonic = mnemonic.to_ascii_lowercase();
    let branch = mnemonic.starts_with("call")
        || mnemonic.starts_with('j')
        || matches!(mnemonic.as_str(), "b" | "bl" | "loop")
        || mnemonic.starts_with("b.");
    if !branch {
        return None;
    }
    let digits = operands.trim().strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// One listing line: `0x401136  55 48 89 e5  push rbp  ; call -> main`.
fn line(instruction: &Value, names: &HashMap<u64, &str>) -> String {
    let address = address_of(instruction).unwrap_or(0);
    let bytes = match instruction.get("bytes") {
        Some(Value::String(hex)) => hex.clone(),
        Some(Value::Array(items)) => {
            let mut text = String::new();
            for (i, b) in items.iter().enumerate() {
                if i > 0 {
                    text.push(' ');
                }
                let _ = write!(text, "{:02x}", b.as_u64().unwrap_or(0));
            }
            text
        }
        _ => String::new(),
    };
    let mnemonic = instruction
        .get("mnemonic")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let operands = instruction
        .get("operands")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut out = format!("0x{address:x}  {bytes:<23}  {mnemonic} {operands}")
        .trim_end()
        .to_string();
    let target = instruction
        .get("flow_control")
        .and_then(|f| {
            f.get("Call")
                .or_else(|| f.get("Jump"))
                .and_then(|c| c.get("target"))
                .and_then(Value::as_u64)
        })
        .or_else(|| direct_target(mnemonic, operands));
    if let Some(target) = target {
        if let Some(name) = names.get(&target) {
            let _ = write!(out, "  ; -> {name}");
        }
    }
    out
}

/// Instructions the whole disassembly holds (the stored list can be shorter).
fn total_instructions(section: &Value) -> usize {
    let stored = section
        .get("instructions")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    section
        .get("instructions_total")
        .and_then(Value::as_u64)
        .map_or(stored, |n| n as usize)
        .max(stored)
}

/// First and last address of the whole instruction list, not of the stored part.
fn decoded_bounds(section: &Value) -> Option<(u64, u64)> {
    let stored = section.get("instructions").and_then(Value::as_array);
    let first = section
        .get("instructions_first_address")
        .and_then(Value::as_u64)
        .or_else(|| stored.and_then(|l| l.first()).and_then(address_of))?;
    let last = section
        .get("instructions_last_address")
        .and_then(Value::as_u64)
        .or_else(|| stored.and_then(|l| l.last()).and_then(address_of))?;
    Some((first, last))
}

/// The function table of a `disassemble` call with no target.
fn function_table(
    section: &Value,
    request: &DisassembleRequest,
    file_path: &str,
    budget: usize,
    extras: &Value,
) -> Value {
    let functions = section
        .get("functions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let filter = request.filter.as_deref().map(str::to_lowercase);
    let rows: Vec<Value> = functions
        .iter()
        .filter(|f| {
            filter.as_ref().is_none_or(|needle| {
                f.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.to_lowercase().contains(needle))
            })
        })
        .map(|f| {
            json!({
                "name": f.get("name"),
                "address": format!("0x{:x}", address_of(f).unwrap_or(0)),
                "size": f.get("size"),
                "instructions": instruction_count(f),
                "complexity": f.get("complexity"),
            })
        })
        .collect();
    let mut value = page(
        &rows,
        request.offset.unwrap_or(0),
        request.limit.unwrap_or(DEFAULT_LIMIT),
    );
    value["view"] = "functions".into();
    value["file_path"] = file_path.into();
    value["architecture"] = section.get("architecture").cloned().unwrap_or(Value::Null);
    value["total_instructions"] = section
        .pointer("/analysis/total_instructions")
        .cloned()
        .unwrap_or(Value::Null);
    let (first, last) = match decoded_bounds(section) {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    if rows.is_empty() {
        // No function names to pass: start from an address instead.
        let step = json!({
            "tool": "disassemble",
            "arguments": {"file_path": file_path, "address": first.map(|a| format!("0x{a:x}"))},
            "gives": "the first decoded instructions; follow next_address for the rest",
        });
        value["note"] = if filter.is_some() {
            "No function name matches the filter."
        } else {
            "This file's analysis found no function symbols (stripped or no symbol table); \
             list instructions by address instead."
        }
        .into();
        value["next_steps"] = json!([step]);
    } else {
        value["next_steps"] = json!([{
            "tool": "disassemble",
            "arguments": {"file_path": file_path, "function": "<name from items>"},
            "gives": "the instruction listing of that function (or pass `address`)",
        }]);
    }
    if let (Some(first), Some(last)) = (first, last) {
        value["decoded_range"] = format!("0x{first:x}..0x{last:x}").into();
    }
    merge(&mut value, extras);
    fit_rows(
        &mut value,
        "items",
        budget,
        request.offset.unwrap_or(0),
        rows.len(),
    );
    value
}

/// The fields of the object `extras` copied into `value`.
fn merge(value: &mut Value, extras: &Value) {
    if let (Some(into), Some(from)) = (value.as_object_mut(), extras.as_object()) {
        for (k, v) in from {
            into.insert(k.clone(), v.clone());
        }
    }
}

/// The listing of one function or address range.
fn listing(
    section: &Value,
    request: &DisassembleRequest,
    file_path: &str,
    budget: usize,
    extras: &Value,
) -> Result<Value, String> {
    let empty = Vec::new();
    let functions = section
        .get("functions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let flat = section
        .get("instructions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let requested = request.max_instructions.unwrap_or(DEFAULT_INSTRUCTIONS);
    if requested == 0 {
        return Err(format!(
            "max_instructions must be at least 1 (default {DEFAULT_INSTRUCTIONS}, at most \
             {MAX_INSTRUCTIONS})."
        ));
    }
    let max = requested.min(MAX_INSTRUCTIONS);

    let address = request
        .address
        .as_ref()
        .map(AddressArg::parse)
        .transpose()?
        .or_else(|| {
            // A `function` that is an address is one.
            request
                .function
                .as_deref()
                .filter(|f| f.trim_start().starts_with("0x"))
                .and_then(|f| parse_address(f).ok())
        });
    let function = match (&request.function, address) {
        (Some(name), None) => Some(find_function(functions, name, section)?),
        (_, Some(a)) => function_containing(functions, a),
        (None, None) => None,
    };

    // The instructions to walk and where to start in them.
    let function_instructions = function
        .and_then(|f| f.get("instructions"))
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty());
    let (pool, start_at): (Vec<&Value>, u64) = if let Some(items) = function_instructions {
        (
            items.iter().collect(),
            address.unwrap_or_else(|| function.and_then(address_of).unwrap_or(0)),
        )
    } else if let Some(f) = function {
        // A function with no instructions of its own: its range of the flat list.
        let from = address_of(f).unwrap_or(0);
        let to = from.saturating_add(f.get("size").and_then(Value::as_u64).unwrap_or(0));
        (
            flat.iter()
                .filter(|i| address_of(i).is_some_and(|a| a >= from && a < to))
                .collect(),
            address.unwrap_or(from),
        )
    } else {
        let a = address.unwrap_or(0);
        (flat.iter().collect(), a)
    };
    let first = pool
        .iter()
        .position(|i| {
            let a = address_of(i).unwrap_or(0);
            let size = i.get("size").and_then(Value::as_u64).unwrap_or(1).max(1);
            a <= start_at && start_at < a.saturating_add(size)
        })
        .or_else(|| {
            if function.is_some() {
                pool.iter()
                    .position(|i| address_of(i).unwrap_or(0) >= start_at)
            } else {
                None
            }
        });
    let Some(first) = first else {
        let near = flat
            .iter()
            .filter_map(address_of)
            .filter(|a| *a >= start_at)
            .min();
        let range = match decoded_bounds(section) {
            Some((a, b)) => format!(
                " The analyzer decoded {} instructions in 0x{a:x}..0x{b:x} and stops at the \
                 first byte it cannot decode, so addresses outside that range are not listed; \
                 read_hex shows the raw bytes there.",
                total_instructions(section)
            ),
            _ => String::new(),
        };
        return Err(format!(
            "No instruction at 0x{start_at:x} in this file's disassembly{}. Pass the address of an \
             instruction, or a `function` name; call disassemble with only file_path to list the \
             functions.{range}",
            near.map_or_else(String::new, |a| format!(
                " (the next one is at 0x{a:x})"
            ))
        ));
    };

    let names: HashMap<u64, &str> = functions
        .iter()
        .filter_map(|f| Some((address_of(f)?, f.get("name")?.as_str()?)))
        .collect();
    let slice = &pool[first..];
    // Instructions of a decoded-again window (or of the part that is not
    // stored) that lie past the end of the pool.
    let flat_beyond = section
        .get("instructions_beyond")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or_else(|| total_instructions(section).saturating_sub(flat.len()));
    let beyond = if function_instructions.is_none() && function.is_none() {
        flat_beyond
    } else {
        0
    } + function_instructions.map_or(0, |items| {
        let from = function
            .and_then(|f| f.get("window_from"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        function
            .and_then(instruction_count)
            .unwrap_or(0)
            .saturating_sub(from + items.len())
    });
    let wanted = &slice[..slice.len().min(max)];
    let texts: Vec<String> = wanted.iter().map(|i| line(i, &names)).collect();
    // The answer with `count` lines; whole lines only, and the count is
    // lowered until the whole answer (path, cache fields, next step) fits.
    let build = |count: usize| -> Value {
        let shown = &wanted[..count];
        let mut text = String::new();
        for t in &texts[..count] {
            text.push_str(t);
            text.push('\n');
        }
        let mut value = json!({
            "view": "listing",
            "file_path": file_path,
            "architecture": section.get("architecture"),
            "start_address": format!("0x{:x}", address_of(shown[0]).unwrap_or(0)),
            "returned": shown.len(),
            "max_instructions": max,
            "listing": text,
        });
        if let Some(f) = function {
            value["function"] = json!({
                "name": f.get("name"),
                "address": format!("0x{:x}", address_of(f).unwrap_or(0)),
                "size": f.get("size"),
                "complexity": f.get("complexity"),
                "instructions": instruction_count(f).unwrap_or(pool.len()),
            });
        }
        if requested > max {
            value["note"] = format!(
                "max_instructions {requested} was lowered to the limit of {MAX_INSTRUCTIONS}"
            )
            .into();
        }
        if count < wanted.len() {
            let cut = format!(
                "The listing was shortened to {count} of the {} instructions asked for to fit \
                 max_output_bytes; next_address continues where it stops.",
                wanted.len()
            );
            value["note"] = match value.get("note").and_then(Value::as_str) {
                Some(earlier) => format!("{earlier}. {cut}"),
                None => cut,
            }
            .into();
        }
        if slice.len() + beyond > shown.len() {
            let next = match slice.get(shown.len()) {
                Some(i) => address_of(i).unwrap_or(0),
                None => shown.last().map_or(0, |i| {
                    address_of(i)
                        .unwrap_or(0)
                        .saturating_add(i.get("size").and_then(Value::as_u64).unwrap_or(1).max(1))
                }),
            };
            value["more"] = true.into();
            value["remaining"] = (slice.len() - shown.len() + beyond).into();
            value["next_address"] = format!("0x{next:x}").into();
            value["next_steps"] = json!([{
                "tool": "disassemble",
                "arguments": {"file_path": file_path, "address": format!("0x{next:x}")},
                "gives": "the next instructions",
            }]);
        }
        merge(&mut value, extras);
        value
    };
    let mut count = texts.len();
    loop {
        let value = build(count);
        let size = serde_json::to_vec(&value).map_or(0, |v| v.len());
        if size <= budget || count <= 1 {
            return Ok(value);
        }
        let average = (size / count).max(1);
        count = count
            .saturating_sub(((size - budget) / average).max(1))
            .max(1);
    }
}

impl FileScannerMcp {
    /// The `disassemble` tool body.
    pub(crate) async fn run_disassemble(&self, args: JsonObject) -> rmcp::model::CallToolResult {
        let (request, budget, _raw) = match parse_request::<DisassembleRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        if request.function.is_some() && request.address.is_some() {
            return tool_error(
                "Pass either `function` or `address`, not both: `function` lists one function \
                 from its start, `address` lists from that instruction on."
                    .to_string(),
            );
        }
        // Reject a bad address before the (cached, but possibly long) analysis.
        if let Some(address) = &request.address {
            if let Err(message) = address.parse() {
                return tool_error(message);
            }
        }
        let (path, sha256, _size, mtime_ns) =
            match identify(self, &request.file_path, Expect::File).await {
                Ok(identity) => identity,
                Err(error) => return *error,
            };
        let state = std::sync::Arc::clone(&self.state);
        let runtime = tokio::runtime::Handle::current();
        let file_path = path.to_string_lossy().into_owned();
        let arch = super::sections::arch_option(request.arch.as_deref());
        let outcome = self
            .state
            .run_blocking("disassemble", move || {
                let options = Options {
                    arch: arch.clone(),
                    ..Options::default()
                };
                let ctx = Ctx::new(&path, &runtime, options.clone());
                let mut engine =
                    Engine::new(state.section_cache(), &sha256, ctx, state.cache_enabled());
                let planned = plan("disassembly", &options, &file_path, mtime_ns);
                let section = engine.load(&planned).map_err(|failure| match failure {
                    Failure::Error(m) => format!("The disassembly failed: {m}"),
                    Failure::NotApplicable(m) => format!(
                        "Disassembly does not apply to this file: {m}. Call analyze_file with \
                         only file_path to see what kind of file it is."
                    ),
                })?;
                let (section, window_note) =
                    with_window(&section, &request, &mut || engine.typed_disassembly())
                        .map_err(|m| format!("The disassembly failed: {m}"))?;
                let mut extras = json!({"cache": engine.cache_state()});
                if let Some(note) = engine.cache_note() {
                    extras["cache_note"] = note.into();
                }
                if let Some(note) = window_note {
                    extras["window_note"] = note.into();
                }
                let value = if request.function.is_none() && request.address.is_none() {
                    function_table(&section, &request, &file_path, budget, &extras)
                } else {
                    listing(&section, &request, &file_path, budget, &extras)?
                };
                Ok::<String, String>(render(value, budget))
            })
            .await;
        match outcome {
            Err(crash) => tool_error(crash),
            Ok(Err(message)) => tool_error(message),
            Ok(Ok(text)) => respond_text(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that is not found carries the analyzer's coverage notes when it
    /// left functions out, whatever the notes start with.
    #[test]
    fn a_missing_function_name_carries_the_coverage_note() {
        let section = json!({
            "coverage": {
                "truncated": true,
                "notes": ["functions are grouped for the first 5000 function symbols only"],
            },
        });
        let err = find_function(&[], "main.main", &section).unwrap_err();
        assert!(err.contains("first 5000 function symbols"), "{err}");
        let whole = json!({"coverage": {"truncated": false, "notes": ["other remark"]}});
        let err = find_function(&[], "main.main", &whole).unwrap_err();
        assert!(!err.contains("other remark"), "{err}");
    }

    fn request() -> DisassembleRequest {
        serde_json::from_value(json!({"file_path": "/x"})).unwrap()
    }

    /// A stripped binary has no function names: the table says so, its next
    /// step is an address, and the decoded range is named.
    #[test]
    fn a_table_without_functions_points_at_an_address_and_the_decoded_range() {
        let section = json!({
            "architecture": "x86_64",
            "functions": [],
            "instructions": [
                {"address": 0x1000, "size": 1, "bytes": [0x90], "mnemonic": "nop", "operands": ""},
                {"address": 0x1001, "size": 1, "bytes": [0xc3], "mnemonic": "ret", "operands": ""},
            ],
        });
        let table = function_table(&section, &request(), "/x", 80_000, &json!({}));
        assert!(table["note"]
            .as_str()
            .unwrap()
            .contains("no function symbols"));
        assert_eq!(table["next_steps"][0]["arguments"]["address"], "0x1000");
        assert_eq!(table["decoded_range"], "0x1000..0x1001");
    }

    #[test]
    fn direct_branch_operands_are_resolved_to_names() {
        let names: HashMap<u64, &str> = HashMap::from([(0x1549, "detect_debugger")]);
        let call = json!({"address": 0x1d93, "bytes": [0xe8], "mnemonic": "call",
                          "operands": "0x1549"});
        assert!(line(&call, &names).ends_with("; -> detect_debugger"));
        let indirect = json!({"address": 0x1d93, "bytes": [0xff], "mnemonic": "call",
                              "operands": "rax"});
        assert!(!line(&indirect, &names).contains("; ->"));
        let mov = json!({"address": 0x1d93, "bytes": [0x48], "mnemonic": "mov",
                         "operands": "0x1549"});
        assert!(!line(&mov, &names).contains("; ->"));
    }

    fn nops(count: u64) -> std::sync::Arc<crate::disassembly::DisassemblyResult> {
        use crate::disassembly::{
            ControlFlowSummary, DisassembledFunction, DisassemblyResult, GraphVisualizationData,
            Instruction, InstructionAnalysis, InstructionType, OutputFormats,
        };
        let instructions: Vec<Instruction> = (0..count)
            .map(|address| Instruction {
                address: 0x1000 + address,
                bytes: vec![0x90],
                mnemonic: "nop".into(),
                operands: String::new(),
                instruction_type: InstructionType::Other,
                flow_control: None,
                size: 1,
            })
            .collect();
        let functions = vec![DisassembledFunction {
            address: 0x1000,
            name: "big".into(),
            size: count as usize,
            instructions: instructions.clone(),
            basic_blocks: Vec::new(),
            complexity: 1,
        }];
        std::sync::Arc::new(DisassemblyResult {
            architecture: "x86_64".into(),
            analysis: InstructionAnalysis {
                total_instructions: instructions.len(),
                instruction_types: Default::default(),
                register_usage: Default::default(),
                memory_accesses: Vec::new(),
                system_calls: Vec::new(),
                crypto_operations: Vec::new(),
                suspicious_patterns: Vec::new(),
                control_flow_summary: ControlFlowSummary {
                    total_jumps: 0,
                    conditional_jumps: 0,
                    unconditional_jumps: 0,
                    function_calls: 0,
                    indirect_calls: 0,
                    returns: 0,
                    interrupts: 0,
                },
            },
            instructions,
            functions,
            output_formats: OutputFormats {
                assembly: String::new(),
                json_structured: Value::Null,
                graph_data: GraphVisualizationData {
                    nodes: Vec::new(),
                    edges: Vec::new(),
                },
            },
        })
    }

    /// Follows next_address from `first` (or the function) until the answer
    /// has no `more`; returns the lines listed.
    fn walk(
        section: &std::sync::Arc<Value>,
        typed: &std::sync::Arc<crate::disassembly::DisassemblyResult>,
        function: Option<&str>,
    ) -> usize {
        let mut lines = 0;
        let mut next: Option<String> = None;
        for _ in 0..200 {
            let mut args = json!({"file_path": "/x", "max_instructions": 1000});
            match (&next, function) {
                (Some(a), _) => args["address"] = a.clone().into(),
                (None, Some(name)) => args["function"] = name.into(),
                (None, None) => args["address"] = "0x1000".into(),
            }
            let request: DisassembleRequest = serde_json::from_value(args).unwrap();
            let (patched, _) = with_window(section, &request, &mut || Ok(typed.clone())).unwrap();
            let answer = listing(&patched, &request, "/x", 10_000_000, &json!({})).unwrap();
            lines += answer["returned"].as_u64().unwrap() as usize;
            match answer.get("next_address").and_then(Value::as_str) {
                Some(a) if answer["more"] == true => next = Some(a.to_string()),
                _ => return lines,
            }
        }
        panic!("the walk did not end");
    }

    /// The stored part keeps 20,000 instructions; a walk by next_address
    /// continues past it and ends at the true total, by address and by
    /// function.
    #[test]
    fn a_walk_continues_past_the_stored_instructions() {
        let typed = nops(45_000);
        let mut stored =
            crate::mcp_server::tools_analyze::sections::bounded_disassembly(&typed, None).unwrap();
        stored["functions"][0]["instructions"] = json!([]);
        let section = std::sync::Arc::new(stored);
        assert_eq!(section["instructions"].as_array().unwrap().len(), 20_000);
        assert_eq!(walk(&section, &typed, None), 45_000);
        assert_eq!(walk(&section, &typed, Some("big")), 45_000);
        let table = function_table(&section, &request(), "/x", 80_000, &json!({}));
        assert_eq!(table["decoded_range"], "0x1000..0xbfc7");
        let err = listing(
            &section,
            &serde_json::from_value(json!({"file_path": "/x", "address": "0x100000"})).unwrap(),
            "/x",
            80_000,
            &json!({}),
        )
        .unwrap_err();
        assert!(
            err.contains("45000 instructions in 0x1000..0xbfc7"),
            "{err}"
        );
    }
}
