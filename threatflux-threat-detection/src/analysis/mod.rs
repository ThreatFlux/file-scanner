//! Analysis and scoring logic for threat detection

use crate::types::{Severity, ThreatClassification, ThreatIndicator, ThreatLevel, YaraMatch};

/// Calculate overall threat level based on matches and indicators
pub fn calculate_threat_level(
    matches: &[YaraMatch],
    indicators: &[ThreatIndicator],
) -> ThreatLevel {
    if matches.is_empty() && indicators.is_empty() {
        return ThreatLevel::Clean;
    }

    let mut score = 0.0;

    // Score based on YARA matches
    for yara_match in matches {
        // High-value tags increase score significantly
        for tag in &yara_match.tags {
            match tag.as_str() {
                "malware" | "trojan" | "virus" | "ransomware" => score += 100.0,
                "apt" | "advanced" | "targeted" => score += 80.0,
                "suspicious" | "potential" => score += 40.0,
                "pua" | "adware" => score += 20.0,
                _ => score += 10.0,
            }
        }

        // Metadata can also influence scoring
        if let Some(family) = yara_match.metadata.get("family") {
            if family.contains("APT") || family.contains("Lazarus") || family.contains("Carbanak") {
                score += 120.0;
            }
        }
    }

    // Score based on indicators
    for indicator in indicators {
        let indicator_score = match indicator.severity {
            Severity::Critical => 80.0,
            Severity::High => 60.0,
            Severity::Medium => 30.0,
            Severity::Low => 10.0,
        };

        score += indicator_score * indicator.confidence;
    }

    // Determine threat level based on score
    if score >= 200.0 {
        ThreatLevel::Critical
    } else if score >= 100.0 {
        ThreatLevel::Malicious
    } else if score >= 50.0 {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Clean
    }
}

/// Generate security recommendations based on findings
pub fn generate_recommendations(
    threat_level: &ThreatLevel,
    matches: &[YaraMatch],
    classifications: &[ThreatClassification],
) -> Vec<String> {
    let mut recommendations = Vec::new();

    match threat_level {
        ThreatLevel::Critical => {
            recommendations.push(
                "IMMEDIATE ACTION REQUIRED: Isolate the affected system immediately".to_string(),
            );
            recommendations.push("Disconnect from network to prevent lateral movement".to_string());
            recommendations.push("Initiate incident response procedures".to_string());
            recommendations.push("Preserve forensic evidence before remediation".to_string());
        }
        ThreatLevel::Malicious => {
            recommendations.push("HIGH PRIORITY: Quarantine the file immediately".to_string());
            recommendations.push("Scan the entire system for additional threats".to_string());
            recommendations.push("Review system logs for signs of compromise".to_string());
            recommendations.push("Consider restoring from clean backup if available".to_string());
        }
        ThreatLevel::Suspicious => {
            recommendations.push("CAUTION: Further analysis recommended".to_string());
            recommendations.push("Submit to additional analysis tools or sandbox".to_string());
            recommendations.push("Monitor system for unusual activity".to_string());
            recommendations
                .push("Consider temporary isolation pending further analysis".to_string());
        }
        ThreatLevel::Clean => {
            recommendations.push("No immediate threats detected".to_string());
            recommendations.push("Continue regular security monitoring".to_string());
        }
        ThreatLevel::None => {
            recommendations.push("No analysis performed or insufficient data".to_string());
            recommendations.push("Consider running additional scans or analysis".to_string());
        }
    }

    // Add classification-specific recommendations
    for classification in classifications {
        match classification {
            ThreatClassification::Ransomware => {
                recommendations
                    .push("RANSOMWARE DETECTED: Immediately disconnect from network".to_string());
                recommendations.push("Check backup integrity and availability".to_string());
                recommendations.push("Do NOT pay ransom - contact law enforcement".to_string());
            }
            ThreatClassification::Apt => {
                recommendations.push("APT ACTIVITY: Assume persistent compromise".to_string());
                recommendations
                    .push("Engage threat hunting team for comprehensive analysis".to_string());
                recommendations.push("Review all privileged accounts and access logs".to_string());
            }
            ThreatClassification::InfoStealer => {
                recommendations
                    .push("DATA THEFT RISK: Change all passwords immediately".to_string());
                recommendations
                    .push("Review data access logs for unauthorized activity".to_string());
                recommendations.push("Enable additional authentication factors".to_string());
            }
            ThreatClassification::Banker => {
                recommendations.push("BANKING TROJAN: Secure all financial accounts".to_string());
                recommendations.push("Use separate, clean device for banking".to_string());
                recommendations
                    .push("Monitor financial accounts for unauthorized transactions".to_string());
            }
            ThreatClassification::Rootkit => {
                recommendations.push("ROOTKIT DETECTED: Deep system analysis required".to_string());
                recommendations.push("Boot from external media for offline scanning".to_string());
                recommendations.push("Consider complete OS reinstallation".to_string());
            }
            ThreatClassification::Cryptominer => {
                recommendations
                    .push("CRYPTOMINER: Monitor system performance and network usage".to_string());
                recommendations
                    .push("Check for unauthorized cryptocurrency wallet addresses".to_string());
                recommendations.push("Review scheduled tasks and startup programs".to_string());
            }
            _ => {}
        }
    }

    // Add YARA rule specific recommendations
    for yara_match in matches {
        if let Some(recommendation) = yara_match.metadata.get("recommendation") {
            recommendations.push(format!("Rule recommendation: {}", recommendation));
        }
    }

    // Remove duplicates and sort
    recommendations.sort();
    recommendations.dedup();

    recommendations
}

/// Analyze YARA rule tags to extract threat classifications
pub fn extract_classifications_from_tags(tags: &[String]) -> Vec<ThreatClassification> {
    let mut classifications = Vec::new();

    for tag in tags {
        let classification = match tag.to_lowercase().as_str() {
            "trojan" => Some(ThreatClassification::Trojan),
            "virus" => Some(ThreatClassification::Virus),
            "worm" => Some(ThreatClassification::Worm),
            "rootkit" => Some(ThreatClassification::Rootkit),
            "adware" => Some(ThreatClassification::Adware),
            "spyware" => Some(ThreatClassification::Spyware),
            "ransomware" => Some(ThreatClassification::Ransomware),
            "apt" => Some(ThreatClassification::Apt),
            "pua" => Some(ThreatClassification::Pua),
            "banker" | "banking" => Some(ThreatClassification::Banker),
            "downloader" => Some(ThreatClassification::Downloader),
            "backdoor" => Some(ThreatClassification::Backdoor),
            "exploit" => Some(ThreatClassification::Exploit),
            "cryptominer" | "miner" => Some(ThreatClassification::Cryptominer),
            "infostealer" | "stealer" => Some(ThreatClassification::InfoStealer),
            "botnet" => Some(ThreatClassification::Botnet),
            "webshell" => Some(ThreatClassification::WebShell),
            "keylogger" => Some(ThreatClassification::Keylogger),
            "rat" | "remote_access" => Some(ThreatClassification::RemoteAccess),
            _ => None,
        };

        if let Some(cls) = classification {
            if !classifications.contains(&cls) {
                classifications.push(cls);
            }
        }
    }

    classifications
}

/// Generate confidence score based on various factors
pub fn calculate_confidence_score(
    matches: &[YaraMatch],
    indicators: &[ThreatIndicator],
    file_size: u64,
) -> f32 {
    let mut confidence = 0.0;
    let mut factors = 0;

    // Factor 1: Number of rule matches
    if !matches.is_empty() {
        confidence += (matches.len() as f32 * 0.2).min(1.0);
        factors += 1;
    }

    // Factor 2: Quality of indicators
    if !indicators.is_empty() {
        let avg_indicator_confidence: f32 =
            indicators.iter().map(|i| i.confidence).sum::<f32>() / indicators.len() as f32;
        confidence += avg_indicator_confidence;
        factors += 1;
    }

    // Factor 3: File size (very small or very large files might be less reliable)
    let size_factor = if file_size < 1024 || file_size > 50 * 1024 * 1024 {
        0.8
    } else {
        1.0
    };
    confidence *= size_factor;

    // Factor 4: Rule metadata quality
    let has_quality_metadata = matches.iter().any(|m| {
        m.metadata.contains_key("author")
            || m.metadata.contains_key("description")
            || m.metadata.contains_key("family")
    });

    if has_quality_metadata {
        confidence += 0.1;
    }

    if factors > 0 {
        (confidence / factors as f32).min(1.0).max(0.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndicatorType, StringMatch};

    #[test]
    fn test_threat_level_calculation() {
        // Test clean result
        let result = calculate_threat_level(&[], &[]);
        assert_eq!(result, ThreatLevel::Clean);

        // Test malicious result
        let matches = vec![YaraMatch {
            rule_identifier: "test_rule".to_string(),
            tags: vec!["malware".to_string(), "trojan".to_string()],
            metadata: HashMap::new(),
            strings: vec![],
        }];
        let result = calculate_threat_level(&matches, &[]);
        assert_eq!(result, ThreatLevel::Critical);
    }

    #[test]
    fn test_classification_extraction() {
        let tags = vec![
            "trojan".to_string(),
            "banker".to_string(),
            "unknown_tag".to_string(),
        ];

        let classifications = extract_classifications_from_tags(&tags);
        assert_eq!(classifications.len(), 2);
        assert!(classifications.contains(&ThreatClassification::Trojan));
        assert!(classifications.contains(&ThreatClassification::Banker));
    }

    #[test]
    fn test_confidence_calculation() {
        let matches = vec![YaraMatch {
            rule_identifier: "test".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
            strings: vec![],
        }];

        let indicators = vec![ThreatIndicator {
            indicator_type: IndicatorType::KnownMalwareFamily,
            description: "Test".to_string(),
            severity: Severity::High,
            confidence: 0.8,
            mitre_technique: None,
            context: HashMap::new(),
        }];

        let confidence = calculate_confidence_score(&matches, &indicators, 1024);
        assert!(confidence > 0.0 && confidence <= 1.0);
    }
}
