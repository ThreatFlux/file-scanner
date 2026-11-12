//! `disassemble` and `read_hex`: the two targeted looks at the code and the
//! bytes of one file. Neither ever returns a whole binary.
//!
//! `disassemble` is served from the section cache (the full disassembly is
//! computed once per file and kept), so asking for a second function is fast.
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
range of an ELF or thin Mach-O binary as a text listing (address, bytes, mnemonic, operands, call \
targets named). Never the whole binary. Pass `function` (a name from query_analysis section \
`disassembly` list `functions`, or from analyze_file's symbols) or `address` (\"0x401136\" or a \
number); the listing is capped at `max_instructions` (default 200, at most 1000) and says where to \
continue (`next_address`). With neither, it lists the functions (name, address, size, complexity) \
paged with `offset`/`limit`/`filter`, so you can pick one. The full disassembly is computed once \
and cached by the file's SHA-256 (`cache: hit` afterwards). Call analyze_file first to see whether \
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
fn find_function<'a>(functions: &'a [Value], query: &str) -> Result<&'a Value, String> {
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
        [] => Err(format!(
            "No function named '{query}' in this file's disassembly ({} functions). Call \
             disassemble with only file_path (and `filter`: part of a name) to list them, or pass \
             an `address`.",
            functions.len()
        )),
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

/// One listing line: `0x401136  55 48 89 e5  push rbp  ; call -> main`.
fn line(instruction: &Value, names: &HashMap<u64, &str>) -> String {
    let address = address_of(instruction).unwrap_or(0);
    let mut bytes = String::new();
    for (i, b) in instruction
        .get("bytes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if i > 0 {
            bytes.push(' ');
        }
        let _ = write!(bytes, "{:02x}", b.as_u64().unwrap_or(0));
    }
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
    let target = instruction.get("flow_control").and_then(|f| {
        f.get("Call")
            .or_else(|| f.get("Jump"))
            .and_then(|c| c.get("target"))
            .and_then(Value::as_u64)
    });
    if let Some(target) = target {
        match names.get(&target) {
            Some(name) => {
                let _ = write!(out, "  ; -> {name}");
            }
            None => {
                let _ = write!(out, "  ; -> 0x{target:x}");
            }
        }
    }
    out
}

/// The function table of a `disassemble` call with no target.
fn function_table(
    section: &Value,
    request: &DisassembleRequest,
    file_path: &str,
    budget: usize,
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
                "instructions": f.get("instructions").and_then(Value::as_array).map(Vec::len),
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
    fit_rows(
        &mut value,
        "items",
        budget.saturating_sub(800),
        request.offset.unwrap_or(0),
        rows.len(),
    );
    let flat = section
        .get("instructions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let first = flat.first().and_then(address_of);
    let last = flat.last().and_then(address_of);
    if rows.is_empty() {
        // No function names to pass: start from an address instead.
        let mut step = json!({
            "tool": "disassemble",
            "arguments": {"file_path": file_path, "address": first.map(|a| format!("0x{a:x}"))},
            "gives": "the first decoded instructions; follow next_address for the rest",
        });
        if let Some(entry) = section.get("entry_point").and_then(Value::as_u64) {
            step["note"] = format!("the entry point is 0x{entry:x}").into();
        }
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
    value
}

/// The listing of one function or address range.
fn listing(
    section: &Value,
    request: &DisassembleRequest,
    file_path: &str,
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
        (Some(name), None) => Some(find_function(functions, name)?),
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
        let range = match (
            flat.first().and_then(address_of),
            flat.last().and_then(address_of),
        ) {
            (Some(a), Some(b)) => format!(
                " The analyzer decoded {} instructions in 0x{a:x}..0x{b:x} and stops at the \
                 first byte it cannot decode, so addresses outside that range are not listed; \
                 read_hex shows the raw bytes there.",
                flat.len()
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
    let shown = &slice[..slice.len().min(max)];
    let mut text = String::new();
    for instruction in shown {
        text.push_str(&line(instruction, &names));
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
            "instructions": pool.len(),
        });
    }
    if requested > max {
        value["note"] =
            format!("max_instructions {requested} was lowered to the limit of {MAX_INSTRUCTIONS}")
                .into();
    }
    if slice.len() > shown.len() {
        let next = address_of(slice[shown.len()]).unwrap_or(0);
        value["truncated"] = true.into();
        value["remaining"] = (slice.len() - shown.len()).into();
        value["next_address"] = format!("0x{next:x}").into();
        value["next_steps"] = json!([{
            "tool": "disassemble",
            "arguments": {"file_path": file_path, "address": format!("0x{next:x}")},
            "gives": "the next instructions",
        }]);
    }
    Ok(value)
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
        let outcome = self
            .state
            .run_blocking("disassemble", move || {
                let options = Options::default();
                let ctx = Ctx::new(&path, &runtime, options);
                let mut engine = Engine::new(state.section_cache(), &sha256, ctx);
                let planned = plan("disassembly", &options, &file_path, mtime_ns);
                let section = engine.load(&planned).map_err(|failure| match failure {
                    Failure::Error(m) => format!("The disassembly failed: {m}"),
                    Failure::NotApplicable(m) => format!(
                        "Disassembly does not apply to this file: {m}. Call analyze_file with \
                         only file_path to see what kind of file it is."
                    ),
                })?;
                let mut value = if request.function.is_none() && request.address.is_none() {
                    function_table(&section, &request, &file_path, budget)
                } else {
                    listing(&section, &request, &file_path)?
                };
                value["cache"] = engine.cache_state().into();
                if let Some(note) = engine.cache_note() {
                    value["cache_note"] = note.into();
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
