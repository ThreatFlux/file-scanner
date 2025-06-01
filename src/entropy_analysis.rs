use anyhow::{Context, Result};
use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub packed_indicators: PackedIndicators,
    pub encryption_indicators: EncryptionIndicators,
    pub obfuscation_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_suspicious: bool,
    pub characteristics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedIndicators {
    pub likely_packed: bool,
    pub packer_signatures: Vec<String>,
    pub compression_ratio_estimate: f64,
    pub import_table_anomalies: Vec<String>,
    pub section_anomalies: Vec<String>,
    pub entry_point_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionIndicators {
    pub likely_encrypted: bool,
    pub high_entropy_regions: Vec<HighEntropyRegion>,
    pub crypto_constants_found: Vec<String>,
    pub random_data_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighEntropyRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub description: String,
}

const ENTROPY_THRESHOLD_PACKED: f64 = 7.0;
const ENTROPY_THRESHOLD_ENCRYPTED: f64 = 7.5;
const ENTROPY_THRESHOLD_COMPRESSED: f64 = 6.5;

pub fn analyze_entropy(path: &Path) -> Result<EntropyAnalysis> {
    let mut file = File::open(path).context("Failed to open file for entropy analysis")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Failed to read file")?;

    let overall_entropy = calculate_entropy(&buffer);
    let sections = analyze_sections(&buffer, path)?;
    let packed_indicators = detect_packing(&buffer, &sections, path)?;
    let encryption_indicators = detect_encryption(&buffer, &sections);
    let obfuscation_score =
        calculate_obfuscation_score(&sections, &packed_indicators, &encryption_indicators);
    let recommendations =
        generate_recommendations(&sections, &packed_indicators, &encryption_indicators);

    Ok(EntropyAnalysis {
        overall_entropy,
        sections,
        packed_indicators,
        encryption_indicators,
        obfuscation_score,
        recommendations,
    })
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

fn analyze_sections(buffer: &[u8], _path: &Path) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    // Try to parse as different binary formats
    if let Ok(elf) = goblin::elf::Elf::parse(buffer) {
        sections.extend(analyze_elf_sections(&elf, buffer)?);
    } else if let Ok(pe) = goblin::pe::PE::parse(buffer) {
        sections.extend(analyze_pe_sections(&pe, buffer)?);
    } else if let Ok(mach) = goblin::mach::Mach::parse(buffer) {
        sections.extend(analyze_mach_sections(&mach, buffer)?);
    } else {
        // Fallback: analyze the whole file as one section
        let entropy = calculate_entropy(buffer);
        sections.push(SectionEntropy {
            name: "entire_file".to_string(),
            offset: 0,
            size: buffer.len() as u64,
            entropy,
            is_suspicious: entropy > ENTROPY_THRESHOLD_PACKED,
            characteristics: vec![format!("Raw entropy: {:.2}", entropy)],
        });
    }

    Ok(sections)
}

fn analyze_elf_sections(elf: &Elf, buffer: &[u8]) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    for section in &elf.section_headers {
        if section.sh_size == 0 {
            continue;
        }

        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown");
        let offset = section.sh_offset as usize;
        let size = section.sh_size as usize;

        if offset + size <= buffer.len() {
            let section_data = &buffer[offset..offset + size];
            let entropy = calculate_entropy(section_data);

            let mut characteristics = Vec::new();
            if section.is_executable() {
                characteristics.push("executable".to_string());
            }
            if section.is_writable() {
                characteristics.push("writable".to_string());
            }

            let is_suspicious = determine_suspicious_entropy(name, entropy, &characteristics);

            sections.push(SectionEntropy {
                name: name.to_string(),
                offset: section.sh_offset,
                size: section.sh_size,
                entropy,
                is_suspicious,
                characteristics,
            });
        }
    }

    Ok(sections)
}

fn analyze_pe_sections(pe: &PE, buffer: &[u8]) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        if offset + size <= buffer.len() {
            let section_data = &buffer[offset..offset + size];
            let entropy = calculate_entropy(section_data);

            let mut characteristics = Vec::new();
            if section.characteristics & 0x20000000 != 0 {
                characteristics.push("executable".to_string());
            }
            if section.characteristics & 0x80000000 != 0 {
                characteristics.push("writable".to_string());
            }

            let is_suspicious = determine_suspicious_entropy(&name, entropy, &characteristics);

            sections.push(SectionEntropy {
                name,
                offset: section.pointer_to_raw_data as u64,
                size: section.size_of_raw_data as u64,
                entropy,
                is_suspicious,
                characteristics,
            });
        }
    }

    Ok(sections)
}

fn analyze_mach_sections(mach: &Mach, buffer: &[u8]) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    match mach {
        Mach::Binary(macho) => {
            for segment in &macho.segments {
                for (section, _) in segment.sections()? {
                    let name = section.name()?;
                    let offset = section.offset as usize;
                    let size = section.size as usize;

                    if offset + size <= buffer.len() {
                        let section_data = &buffer[offset..offset + size];
                        let entropy = calculate_entropy(section_data);

                        let characteristics = vec![format!("segment: {}", segment.name()?)];

                        let is_suspicious =
                            determine_suspicious_entropy(name, entropy, &characteristics);

                        sections.push(SectionEntropy {
                            name: name.to_string(),
                            offset: section.offset as u64,
                            size: section.size,
                            entropy,
                            is_suspicious,
                            characteristics,
                        });
                    }
                }
            }
        }
        Mach::Fat(_) => {
            // For fat binaries, we'd need to handle multiple architectures
            // For now, we'll skip this case
        }
    }

    Ok(sections)
}

fn determine_suspicious_entropy(name: &str, entropy: f64, characteristics: &[String]) -> bool {
    // Text sections should have moderate entropy (4-6)
    if name == ".text" || name == "__text" {
        return !(4.0..=6.5).contains(&entropy);
    }

    // Data sections usually have lower entropy
    if name == ".data" || name == "__data" || name == ".rdata" {
        return entropy > 6.0;
    }

    // Executable sections with very high entropy are suspicious
    if characteristics.contains(&"executable".to_string()) && entropy > ENTROPY_THRESHOLD_PACKED {
        return true;
    }

    // Any section with entropy > 7.5 is suspicious
    entropy > ENTROPY_THRESHOLD_ENCRYPTED
}

fn detect_packing(
    buffer: &[u8],
    sections: &[SectionEntropy],
    _path: &Path,
) -> Result<PackedIndicators> {
    let mut packer_signatures = Vec::new();
    let mut import_table_anomalies = Vec::new();
    let mut section_anomalies = Vec::new();
    let mut entry_point_suspicious = false;

    // Check for known packer signatures
    if let Some(sig) = detect_packer_signature(buffer) {
        packer_signatures.push(sig);
    }

    // Check section characteristics
    for section in sections {
        if section.name.is_empty() || section.name.chars().all(|c| !c.is_alphanumeric()) {
            section_anomalies.push(format!("Suspicious section name: '{}'", section.name));
        }

        if section.characteristics.contains(&"executable".to_string())
            && section.characteristics.contains(&"writable".to_string())
        {
            section_anomalies.push(format!(
                "Section {} is both writable and executable",
                section.name
            ));
        }

        if section.entropy > ENTROPY_THRESHOLD_PACKED
            && section.characteristics.contains(&"executable".to_string())
        {
            section_anomalies.push(format!(
                "Section {} has high entropy ({:.2}) for executable code",
                section.name, section.entropy
            ));
        }
    }

    // Check import table (simplified check)
    if let Ok(pe) = goblin::pe::PE::parse(buffer) {
        if pe.imports.is_empty() || pe.imports.len() < 3 {
            import_table_anomalies.push("Unusually small import table".to_string());
        }

        // Check if entry point is in an unusual section
        let entry = pe.entry;
        let mut found_in_normal_section = false;
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name);
            let name = name.trim_end_matches('\0');
            if name == ".text" || name == "CODE" {
                let start = section.virtual_address as usize;
                let end = start + section.virtual_size as usize;
                if entry >= start && entry < end {
                    found_in_normal_section = true;
                    break;
                }
            }
        }
        if !found_in_normal_section {
            entry_point_suspicious = true;
        }
    }

    let compression_ratio_estimate = estimate_compression_ratio(sections);
    let likely_packed = !packer_signatures.is_empty()
        || compression_ratio_estimate > 0.7
        || sections
            .iter()
            .any(|s| s.is_suspicious && s.characteristics.contains(&"executable".to_string()));

    Ok(PackedIndicators {
        likely_packed,
        packer_signatures,
        compression_ratio_estimate,
        import_table_anomalies,
        section_anomalies,
        entry_point_suspicious,
    })
}

fn detect_packer_signature(buffer: &[u8]) -> Option<String> {
    // Common packer signatures (simplified)
    let signatures = vec![
        (&b"UPX0"[..], "UPX"),
        (&b"UPX1"[..], "UPX"),
        (&b"UPX!"[..], "UPX"),
        (&b"MPRESS1"[..], "MPRESS"),
        (&b"MPRESS2"[..], "MPRESS"),
        (&b".petite"[..], "Petite"),
        (&b"PECompact"[..], "PECompact"),
        (&b"ASPack"[..], "ASPack"),
        (&b"FSG!"[..], "FSG"),
        (&b"PEC2"[..], "PECrypt"),
    ];

    for (sig, name) in signatures {
        if buffer.windows(sig.len()).any(|window| window == sig) {
            return Some(name.to_string());
        }
    }

    None
}

fn estimate_compression_ratio(sections: &[SectionEntropy]) -> f64 {
    let high_entropy_sections = sections
        .iter()
        .filter(|s| s.entropy > ENTROPY_THRESHOLD_COMPRESSED)
        .count() as f64;

    if sections.is_empty() {
        return 0.0;
    }

    high_entropy_sections / sections.len() as f64
}

fn detect_encryption(buffer: &[u8], sections: &[SectionEntropy]) -> EncryptionIndicators {
    let mut high_entropy_regions = Vec::new();
    let mut crypto_constants = Vec::new();

    // Look for regions with very high entropy
    for section in sections {
        if section.entropy > ENTROPY_THRESHOLD_ENCRYPTED {
            high_entropy_regions.push(HighEntropyRegion {
                offset: section.offset,
                size: section.size,
                entropy: section.entropy,
                description: format!("Section {} has encryption-level entropy", section.name),
            });
        }
    }

    // Look for known crypto constants
    crypto_constants.extend(find_crypto_constants(buffer));

    // Calculate percentage of random-looking data
    let random_bytes = buffer
        .iter()
        .filter(|&&b| (32..=126).contains(&b)) // Printable ASCII
        .count();
    let random_data_percentage = 1.0 - (random_bytes as f64 / buffer.len() as f64);

    let likely_encrypted = !high_entropy_regions.is_empty()
        || !crypto_constants.is_empty()
        || random_data_percentage > 0.8;

    EncryptionIndicators {
        likely_encrypted,
        high_entropy_regions,
        crypto_constants_found: crypto_constants,
        random_data_percentage,
    }
}

fn find_crypto_constants(buffer: &[u8]) -> Vec<String> {
    let mut found = Vec::new();

    // Common crypto constants (simplified)
    let constants: Vec<(&[u8], &str)> = vec![
        // AES S-box beginning
        (&[0x63, 0x7c, 0x77, 0x7b, 0xf2], "AES S-box"),
        // SHA-256 initial hash values
        (&[0x67, 0xe6, 0x09, 0x6a], "SHA-256 constant"),
        // RC4 initialization
        (
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            "Possible RC4 init",
        ),
        // MD5 constants
        (
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            "MD5 constant",
        ),
    ];

    for (constant, name) in constants {
        if buffer
            .windows(constant.len())
            .any(|window| window == constant)
        {
            found.push(name.to_string());
        }
    }

    found
}

fn calculate_obfuscation_score(
    sections: &[SectionEntropy],
    packed: &PackedIndicators,
    encrypted: &EncryptionIndicators,
) -> f64 {
    let mut score = 0.0;

    // Base score from entropy
    let avg_entropy = sections.iter().map(|s| s.entropy).sum::<f64>() / sections.len() as f64;
    score += (avg_entropy / 8.0) * 30.0; // Max 30 points for entropy

    // Packing indicators
    if packed.likely_packed {
        score += 20.0;
    }
    if !packed.packer_signatures.is_empty() {
        score += 10.0;
    }
    if packed.entry_point_suspicious {
        score += 10.0;
    }

    // Encryption indicators
    if encrypted.likely_encrypted {
        score += 15.0;
    }
    if !encrypted.crypto_constants_found.is_empty() {
        score += 10.0;
    }

    // Section anomalies
    score += (packed.section_anomalies.len() as f64).min(3.0) * 5.0;

    score.min(100.0) // Cap at 100
}

fn generate_recommendations(
    sections: &[SectionEntropy],
    packed: &PackedIndicators,
    encrypted: &EncryptionIndicators,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    if packed.likely_packed {
        recommendations
            .push("Binary appears to be packed. Consider unpacking before analysis.".to_string());
        if !packed.packer_signatures.is_empty() {
            recommendations.push(format!(
                "Detected packer: {}. Use appropriate unpacking tool.",
                packed.packer_signatures.join(", ")
            ));
        }
    }

    if encrypted.likely_encrypted {
        recommendations.push("Binary contains encrypted/obfuscated regions.".to_string());
        if encrypted.random_data_percentage > 0.9 {
            recommendations.push(
                "Very high percentage of non-printable data suggests strong encryption."
                    .to_string(),
            );
        }
    }

    for section in sections {
        if section.is_suspicious {
            recommendations.push(format!(
                "Section '{}' has suspicious entropy ({:.2}). Investigate further.",
                section.name, section.entropy
            ));
        }
    }

    if packed.entry_point_suspicious {
        recommendations.push(
            "Entry point is in an unusual section. May indicate runtime unpacking.".to_string(),
        );
    }

    if recommendations.is_empty() {
        recommendations.push(
            "No significant obfuscation detected. Standard analysis should be effective."
                .to_string(),
        );
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // All zeros - minimum entropy
        let data1 = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&data1), 0.0);

        // Random data - high entropy
        let data2: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy2 = calculate_entropy(&data2);
        assert!(entropy2 > 7.9 && entropy2 <= 8.0);

        // Text-like data - medium entropy
        let data3 = b"Hello, world! This is a test string with normal text entropy.";
        let entropy3 = calculate_entropy(data3);
        assert!(entropy3 > 3.0 && entropy3 < 6.0);
    }
}
