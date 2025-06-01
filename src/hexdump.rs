use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct HexDump {
    pub offset: u64,
    pub length: usize,
    pub bytes_per_line: usize,
    pub total_bytes: u64,
    pub lines: Vec<HexLine>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HexLine {
    pub offset: u64,
    pub hex_bytes: String,
    pub ascii_repr: String,
    pub raw_bytes: Vec<u8>,
}

pub struct HexDumpOptions {
    pub offset: u64,
    pub length: Option<usize>,
    pub bytes_per_line: usize,
    pub max_lines: Option<usize>,
}

impl Default for HexDumpOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            length: None,
            bytes_per_line: 16,
            max_lines: Some(32), // Default to first 512 bytes
        }
    }
}

pub fn generate_hex_dump(path: &Path, options: HexDumpOptions) -> Result<HexDump> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    file.seek(SeekFrom::Start(options.offset))?;

    let max_bytes = match (options.length, options.max_lines) {
        (Some(len), _) => len,
        (None, Some(max_lines)) => max_lines * options.bytes_per_line,
        (None, None) => file_size as usize,
    };

    let bytes_to_read = if options.offset >= file_size {
        0
    } else {
        std::cmp::min(max_bytes, (file_size - options.offset) as usize)
    };

    let mut buffer = vec![0u8; bytes_to_read];
    let mut reader = BufReader::new(file);
    let actual_read = reader.read(&mut buffer)?;
    buffer.truncate(actual_read);

    let mut lines = Vec::new();
    let mut current_offset = options.offset;

    for chunk in buffer.chunks(options.bytes_per_line) {
        let hex_bytes = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Pad hex representation to align ASCII
        let padded_hex = if chunk.len() < options.bytes_per_line {
            let padding_needed = (options.bytes_per_line - chunk.len()) * 3;
            format!("{}{}", hex_bytes, " ".repeat(padding_needed))
        } else {
            hex_bytes
        };

        let ascii_repr = chunk
            .iter()
            .map(|&b| {
                if (32..=126).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        lines.push(HexLine {
            offset: current_offset,
            hex_bytes: padded_hex,
            ascii_repr,
            raw_bytes: chunk.to_vec(),
        });

        current_offset += chunk.len() as u64;
    }

    Ok(HexDump {
        offset: options.offset,
        length: actual_read,
        bytes_per_line: options.bytes_per_line,
        total_bytes: file_size,
        lines,
    })
}

pub fn format_hex_dump_text(hex_dump: &HexDump) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "Hex dump (offset: 0x{:08x}, length: {} bytes, total file size: {} bytes)\n",
        hex_dump.offset, hex_dump.length, hex_dump.total_bytes
    ));
    output.push_str(&format!("{:-<80}\n", ""));

    for line in &hex_dump.lines {
        output.push_str(&format!(
            "{:08x}  {}  |{}|\n",
            line.offset, line.hex_bytes, line.ascii_repr
        ));
    }

    if hex_dump.lines.len() * hex_dump.bytes_per_line < hex_dump.total_bytes as usize {
        output.push_str("... (truncated)\n");
    }

    output
}

pub fn extract_header_hex(path: &Path, header_size: usize) -> Result<HexDump> {
    let options = HexDumpOptions {
        offset: 0,
        length: Some(header_size),
        bytes_per_line: 16,
        max_lines: None,
    };
    generate_hex_dump(path, options)
}

pub fn extract_footer_hex(path: &Path, footer_size: usize) -> Result<HexDump> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();

    let offset = file_size.saturating_sub(footer_size as u64);

    let options = HexDumpOptions {
        offset,
        length: Some(footer_size),
        bytes_per_line: 16,
        max_lines: None,
    };
    generate_hex_dump(path, options)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_hex_dump_default_options() {
        let content = b"Hello, World!";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

        assert_eq!(hex_dump.offset, 0);
        assert_eq!(hex_dump.length, 13);
        assert_eq!(hex_dump.bytes_per_line, 16);
        assert_eq!(hex_dump.total_bytes, 13);
        assert_eq!(hex_dump.lines.len(), 1);

        let line = &hex_dump.lines[0];
        assert_eq!(line.offset, 0);
        assert_eq!(
            line.hex_bytes,
            "48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21         "
        );
        assert_eq!(line.ascii_repr, "Hello, World!");
        assert_eq!(line.raw_bytes, content);
    }

    #[test]
    fn test_hex_dump_with_offset() {
        let content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let options = HexDumpOptions {
            offset: 5,
            length: Some(10),
            bytes_per_line: 16,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.offset, 5);
        assert_eq!(hex_dump.length, 10);
        assert_eq!(hex_dump.lines[0].ascii_repr, "FGHIJKLMNO");
    }

    #[test]
    fn test_hex_dump_custom_bytes_per_line() {
        let content = b"0123456789ABCDEF0123456789ABCDEF";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let options = HexDumpOptions {
            offset: 0,
            length: None,
            bytes_per_line: 8,
            max_lines: Some(4),
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.bytes_per_line, 8);
        assert_eq!(hex_dump.lines.len(), 4);

        // Each line should have 8 bytes
        for line in &hex_dump.lines {
            assert_eq!(line.raw_bytes.len(), 8);
        }
    }

    #[test]
    fn test_hex_dump_max_lines() {
        let content = vec![0x41; 256]; // 256 'A' bytes
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let options = HexDumpOptions {
            offset: 0,
            length: None,
            bytes_per_line: 16,
            max_lines: Some(2),
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.lines.len(), 2);
        assert_eq!(hex_dump.length, 32); // 2 lines * 16 bytes
    }

    #[test]
    fn test_hex_dump_beyond_file_size() {
        let content = b"Short";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let options = HexDumpOptions {
            offset: 0,
            length: Some(100), // Request more than file size
            bytes_per_line: 16,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.length, 5); // Only actual file content
    }

    #[test]
    fn test_hex_dump_offset_beyond_file() {
        let content = b"Test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let options = HexDumpOptions {
            offset: 100, // Beyond file size
            length: Some(10),
            bytes_per_line: 16,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.length, 0);
        assert_eq!(hex_dump.lines.len(), 0);
    }

    #[test]
    fn test_hex_dump_ascii_representation() {
        // Test all printable ASCII and some non-printable
        let mut content = Vec::new();
        for i in 0..=255u8 {
            content.push(i);
        }

        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let options = HexDumpOptions {
            offset: 30, // Start just before space (32)
            length: Some(100),
            bytes_per_line: 16,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        // Check ASCII representation
        let line = &hex_dump.lines[0];
        assert_eq!(&line.ascii_repr[0..2], ".."); // 30, 31 are non-printable
        assert_eq!(&line.ascii_repr[2..3], " "); // 32 is space
        assert_eq!(&line.ascii_repr[3..4], "!"); // 33 is !
    }

    #[test]
    fn test_format_hex_dump_text() {
        let content = b"Test formatting output";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();
        let formatted = format_hex_dump_text(&hex_dump);

        assert!(formatted.contains("Hex dump"));
        assert!(formatted.contains("offset: 0x00000000"));
        assert!(formatted.contains("length: 22 bytes"));
        assert!(formatted.contains("total file size: 22 bytes"));
        assert!(formatted.contains("00000000"));
        assert!(formatted.contains("|Test formatting |"));
    }

    #[test]
    fn test_format_hex_dump_truncated() {
        let content = vec![0x41; 1000]; // Large file
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let options = HexDumpOptions {
            offset: 0,
            length: Some(32),
            bytes_per_line: 16,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();
        let formatted = format_hex_dump_text(&hex_dump);

        assert!(formatted.contains("... (truncated)"));
    }

    #[test]
    fn test_extract_header_hex() {
        let content = b"HEADER_DATArest of file content that is longer";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = extract_header_hex(&file_path, 11).unwrap();

        assert_eq!(hex_dump.offset, 0);
        assert_eq!(hex_dump.length, 11);
        assert_eq!(hex_dump.lines[0].ascii_repr, "HEADER_DATA");
    }

    #[test]
    fn test_extract_footer_hex() {
        let content = b"Beginning of file contentFOOTER_DATA";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = extract_footer_hex(&file_path, 11).unwrap();

        assert_eq!(hex_dump.offset, 25); // File is 36 bytes, footer is 11
        assert_eq!(hex_dump.length, 11);
        assert_eq!(hex_dump.lines[0].ascii_repr, "FOOTER_DATA");
    }

    #[test]
    fn test_extract_footer_hex_larger_than_file() {
        let content = b"Small";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = extract_footer_hex(&file_path, 100).unwrap();

        assert_eq!(hex_dump.offset, 0); // saturating_sub returns 0
        assert_eq!(hex_dump.length, 5); // Entire file
    }

    #[test]
    fn test_hex_line_raw_bytes() {
        let content = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

        assert_eq!(hex_dump.lines[0].raw_bytes, content);
        assert_eq!(
            hex_dump.lines[0].hex_bytes,
            "00 01 02 ff fe fd                              "
        );
    }

    #[test]
    fn test_empty_file() {
        let (_temp_dir, file_path) = create_test_file(b"").unwrap();

        let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

        assert_eq!(hex_dump.length, 0);
        assert_eq!(hex_dump.lines.len(), 0);
        assert_eq!(hex_dump.total_bytes, 0);
    }

    #[test]
    fn test_hex_dump_partial_last_line() {
        let content = b"123456789ABCDEF012"; // 18 bytes (one full line + 2 bytes)
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let hex_dump = generate_hex_dump(&file_path, HexDumpOptions::default()).unwrap();

        assert_eq!(hex_dump.lines.len(), 2);
        assert_eq!(hex_dump.lines[0].raw_bytes.len(), 16);
        assert_eq!(hex_dump.lines[1].raw_bytes.len(), 2);

        // Check padding in second line
        assert!(hex_dump.lines[1]
            .hex_bytes
            .ends_with("                                          "));
    }

    #[test]
    fn test_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/file");
        let result = generate_hex_dump(path, HexDumpOptions::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_dump_serialization() {
        let hex_line = HexLine {
            offset: 0x100,
            hex_bytes: "41 42 43".to_string(),
            ascii_repr: "ABC".to_string(),
            raw_bytes: vec![0x41, 0x42, 0x43],
        };

        let hex_dump = HexDump {
            offset: 0,
            length: 3,
            bytes_per_line: 16,
            total_bytes: 100,
            lines: vec![hex_line],
        };

        // Test JSON serialization
        let json = serde_json::to_string(&hex_dump).unwrap();
        let deserialized: HexDump = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.offset, hex_dump.offset);
        assert_eq!(deserialized.length, hex_dump.length);
        assert_eq!(deserialized.lines.len(), 1);
        assert_eq!(deserialized.lines[0].offset, 0x100);
    }

    #[test]
    fn test_large_offset_calculation() {
        let content = vec![0x42; 10000]; // Large file with 'B' bytes
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let options = HexDumpOptions {
            offset: 9990,
            length: Some(20),
            bytes_per_line: 5,
            max_lines: None,
        };

        let hex_dump = generate_hex_dump(&file_path, options).unwrap();

        assert_eq!(hex_dump.offset, 9990);
        assert_eq!(hex_dump.length, 10); // Only 10 bytes left
        assert_eq!(hex_dump.lines.len(), 2); // 10 bytes / 5 per line
    }
}
