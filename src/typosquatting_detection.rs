use anyhow::Result;
use edit_distance::edit_distance;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strsim::{jaro_winkler, levenshtein, normalized_damerau_levenshtein};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TyposquattingAnalysis {
    pub is_potential_typosquatting: bool,
    pub similar_packages: Vec<SimilarPackage>,
    pub typosquatting_score: f32,
    pub attack_techniques: Vec<TyposquattingTechnique>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimilarPackage {
    pub name: String,
    pub distance_metrics: DistanceMetrics,
    pub popularity_score: Option<u64>,
    pub similarity_type: SimilarityType,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DistanceMetrics {
    pub levenshtein_distance: usize,
    pub jaro_winkler_similarity: f64,
    pub damerau_levenshtein_similarity: f64,
    pub edit_distance: usize,
    pub normalized_similarity: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SimilarityType {
    CharacterSubstitution,
    CharacterAddition,
    CharacterDeletion,
    CharacterTransposition,
    KeyboardProximity,
    VisualSimilarity,
    PhoneticSimilarity,
    Hyphenation,
    Abbreviation,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RiskLevel {
    Critical, // Very high similarity to popular package
    High,     // High similarity with suspicious patterns
    Medium,   // Moderate similarity
    Low,      // Low similarity but worth noting
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TyposquattingTechnique {
    pub technique_name: String,
    pub description: String,
    pub examples: Vec<String>,
    pub detected: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspiciousPattern {
    pub pattern_type: String,
    pub description: String,
    pub evidence: String,
    pub severity: String,
}

pub struct TyposquattingDetector {
    popular_packages: HashMap<String, PopularPackage>,
    keyboard_layout: KeyboardLayout,
    visual_similarities: HashMap<char, Vec<char>>,
    phonetic_similarities: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct PopularPackage {
    name: String,
    download_count: u64,
    ecosystem: PackageEcosystem,
    aliases: Vec<String>,
}

#[derive(Debug, Clone)]
enum PackageEcosystem {
    Npm,
    PyPI,
    Cargo,
    Maven,
    NuGet,
}

struct KeyboardLayout {
    adjacent_keys: HashMap<char, Vec<char>>,
}

impl TyposquattingDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            popular_packages: HashMap::new(),
            keyboard_layout: KeyboardLayout::qwerty(),
            visual_similarities: Self::create_visual_similarities(),
            phonetic_similarities: Self::create_phonetic_similarities(),
        };

        detector.load_popular_packages();
        detector
    }

    /// Analyze a package name for typosquatting indicators
    pub fn analyze_package_name(
        &self,
        package_name: &str,
        ecosystem: &str,
    ) -> Result<TyposquattingAnalysis> {
        let mut similar_packages = Vec::new();
        let mut attack_techniques = Vec::new();
        let mut suspicious_patterns = Vec::new();

        // Find similar packages using multiple distance metrics
        for (popular_name, popular_pkg) in &self.popular_packages {
            if self.should_compare_packages(package_name, popular_name, ecosystem) {
                if let Some(similar_pkg) = self.calculate_similarity(package_name, popular_pkg) {
                    similar_packages.push(similar_pkg);
                }
            }
        }

        // Sort by risk level and similarity
        similar_packages.sort_by(|a, b| match (&a.risk_level, &b.risk_level) {
            (RiskLevel::Critical, RiskLevel::Critical) => b
                .distance_metrics
                .normalized_similarity
                .partial_cmp(&a.distance_metrics.normalized_similarity)
                .unwrap(),
            (RiskLevel::Critical, _) => std::cmp::Ordering::Less,
            (_, RiskLevel::Critical) => std::cmp::Ordering::Greater,
            (RiskLevel::High, RiskLevel::High) => b
                .distance_metrics
                .normalized_similarity
                .partial_cmp(&a.distance_metrics.normalized_similarity)
                .unwrap(),
            (RiskLevel::High, _) => std::cmp::Ordering::Less,
            (_, RiskLevel::High) => std::cmp::Ordering::Greater,
            _ => b
                .distance_metrics
                .normalized_similarity
                .partial_cmp(&a.distance_metrics.normalized_similarity)
                .unwrap(),
        });

        // Limit to top 10 most similar packages
        similar_packages.truncate(10);

        // Detect attack techniques
        attack_techniques.extend(self.detect_attack_techniques(package_name, &similar_packages));

        // Detect suspicious patterns
        suspicious_patterns.extend(self.detect_suspicious_patterns(package_name));

        // Calculate overall typosquatting score
        let typosquatting_score =
            self.calculate_typosquatting_score(&similar_packages, &suspicious_patterns);

        // Determine if this is potential typosquatting
        let is_potential_typosquatting = typosquatting_score > 0.7
            || similar_packages
                .iter()
                .any(|p| matches!(p.risk_level, RiskLevel::Critical | RiskLevel::High));

        // Generate recommendations
        let recommendations =
            self.generate_recommendations(&similar_packages, &suspicious_patterns);

        Ok(TyposquattingAnalysis {
            is_potential_typosquatting,
            similar_packages,
            typosquatting_score,
            attack_techniques,
            suspicious_patterns,
            recommendations,
        })
    }

    fn should_compare_packages(
        &self,
        package_name: &str,
        popular_name: &str,
        _ecosystem: &str,
    ) -> bool {
        // Skip exact matches
        if package_name == popular_name {
            return false;
        }

        // Skip if names are too different in length
        let len_diff = (package_name.len() as i32 - popular_name.len() as i32).abs();
        if len_diff > 5 {
            return false;
        }

        // Skip very short names unless very similar
        if package_name.len() < 3 || popular_name.len() < 3 {
            return levenshtein(package_name, popular_name) <= 1;
        }

        true
    }

    fn calculate_similarity(
        &self,
        package_name: &str,
        popular_pkg: &PopularPackage,
    ) -> Option<SimilarPackage> {
        let popular_name = &popular_pkg.name;

        // Calculate multiple distance metrics
        let levenshtein_dist = levenshtein(package_name, popular_name);
        let jaro_winkler_sim = jaro_winkler(package_name, popular_name);
        let damerau_levenshtein_sim = normalized_damerau_levenshtein(package_name, popular_name);
        let edit_dist = edit_distance(package_name, popular_name);

        // Calculate normalized similarity (0.0 to 1.0)
        let max_len = package_name.len().max(popular_name.len()) as f32;
        let normalized_similarity = 1.0 - (levenshtein_dist as f32 / max_len);

        // Only consider packages with reasonable similarity
        if normalized_similarity < 0.5 {
            return None;
        }

        let distance_metrics = DistanceMetrics {
            levenshtein_distance: levenshtein_dist,
            jaro_winkler_similarity: jaro_winkler_sim,
            damerau_levenshtein_similarity: damerau_levenshtein_sim,
            edit_distance: edit_dist,
            normalized_similarity,
        };

        // Determine similarity type
        let similarity_type = self.classify_similarity_type(package_name, popular_name);

        // Calculate risk level
        let risk_level = self.calculate_risk_level(
            &distance_metrics,
            popular_pkg.download_count,
            &similarity_type,
        );

        Some(SimilarPackage {
            name: popular_name.clone(),
            distance_metrics,
            popularity_score: Some(popular_pkg.download_count),
            similarity_type,
            risk_level,
        })
    }

    fn classify_similarity_type(&self, package_name: &str, popular_name: &str) -> SimilarityType {
        let pkg_chars: Vec<char> = package_name.chars().collect();
        let pop_chars: Vec<char> = popular_name.chars().collect();

        // Check for character substitution
        if pkg_chars.len() == pop_chars.len() {
            let mut substitutions = 0;
            for (p, q) in pkg_chars.iter().zip(pop_chars.iter()) {
                if p != q {
                    substitutions += 1;
                    // Check for visual similarity
                    if self.are_visually_similar(*p, *q) {
                        return SimilarityType::VisualSimilarity;
                    }
                    // Check for keyboard proximity
                    if self.keyboard_layout.are_adjacent(*p, *q) {
                        return SimilarityType::KeyboardProximity;
                    }
                }
            }
            if substitutions == 1 {
                return SimilarityType::CharacterSubstitution;
            }
        }

        // Check for character addition
        if pkg_chars.len() == pop_chars.len() + 1 {
            return SimilarityType::CharacterAddition;
        }

        // Check for character deletion
        if pkg_chars.len() + 1 == pop_chars.len() {
            return SimilarityType::CharacterDeletion;
        }

        // Check for transposition
        if self.is_transposition(package_name, popular_name) {
            return SimilarityType::CharacterTransposition;
        }

        // Check for hyphenation variations
        if package_name.replace('-', "") == popular_name.replace('-', "")
            || package_name.replace('_', "") == popular_name.replace('_', "")
        {
            return SimilarityType::Hyphenation;
        }

        // Default to character substitution
        SimilarityType::CharacterSubstitution
    }

    fn calculate_risk_level(
        &self,
        metrics: &DistanceMetrics,
        popularity: u64,
        similarity_type: &SimilarityType,
    ) -> RiskLevel {
        let mut risk_score = 0.0;

        // High similarity score increases risk
        if metrics.normalized_similarity > 0.9 {
            risk_score += 3.0;
        } else if metrics.normalized_similarity > 0.8 {
            risk_score += 2.0;
        } else if metrics.normalized_similarity > 0.7 {
            risk_score += 1.0;
        }

        // Popular packages are higher risk targets
        if popularity > 10_000_000 {
            risk_score += 3.0;
        } else if popularity > 1_000_000 {
            risk_score += 2.0;
        } else if popularity > 100_000 {
            risk_score += 1.0;
        }

        // Certain similarity types are more suspicious
        match similarity_type {
            SimilarityType::VisualSimilarity | SimilarityType::KeyboardProximity => {
                risk_score += 2.0;
            }
            SimilarityType::CharacterSubstitution => risk_score += 1.5,
            SimilarityType::CharacterAddition | SimilarityType::CharacterDeletion => {
                risk_score += 1.0;
            }
            _ => risk_score += 0.5,
        }

        match risk_score {
            x if x >= 6.0 => RiskLevel::Critical,
            x if x >= 4.0 => RiskLevel::High,
            x if x >= 2.0 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }

    fn detect_attack_techniques(
        &self,
        _package_name: &str,
        similar_packages: &[SimilarPackage],
    ) -> Vec<TyposquattingTechnique> {
        let mut techniques = Vec::new();

        // Character substitution technique
        let char_substitution = TyposquattingTechnique {
            technique_name: "Character Substitution".to_string(),
            description: "Replace characters with visually similar ones".to_string(),
            examples: vec!["react -> reakt".to_string(), "lodash -> lod4sh".to_string()],
            detected: similar_packages
                .iter()
                .any(|p| matches!(p.similarity_type, SimilarityType::CharacterSubstitution)),
        };
        techniques.push(char_substitution);

        // Keyboard proximity technique
        let keyboard_proximity = TyposquattingTechnique {
            technique_name: "Keyboard Proximity".to_string(),
            description: "Use adjacent keys on keyboard".to_string(),
            examples: vec![
                "express -> rxpress".to_string(),
                "jquery -> jqueey".to_string(),
            ],
            detected: similar_packages
                .iter()
                .any(|p| matches!(p.similarity_type, SimilarityType::KeyboardProximity)),
        };
        techniques.push(keyboard_proximity);

        // Visual similarity technique
        let visual_similarity = TyposquattingTechnique {
            technique_name: "Visual Similarity".to_string(),
            description: "Use visually similar characters".to_string(),
            examples: vec!["babel -> babe1".to_string(), "async -> async".to_string()],
            detected: similar_packages
                .iter()
                .any(|p| matches!(p.similarity_type, SimilarityType::VisualSimilarity)),
        };
        techniques.push(visual_similarity);

        // Hyphenation technique
        let hyphenation = TyposquattingTechnique {
            technique_name: "Hyphenation/Underscore".to_string(),
            description: "Add or remove hyphens and underscores".to_string(),
            examples: vec![
                "vue-router -> vuerouter".to_string(),
                "eslint -> es-lint".to_string(),
            ],
            detected: similar_packages
                .iter()
                .any(|p| matches!(p.similarity_type, SimilarityType::Hyphenation)),
        };
        techniques.push(hyphenation);

        techniques
    }

    fn detect_suspicious_patterns(&self, package_name: &str) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();

        // Check for common suspicious patterns
        if package_name.ends_with("-dev") || package_name.ends_with("-test") {
            patterns.push(SuspiciousPattern {
                pattern_type: "Development Suffix".to_string(),
                description: "Package name ends with development-related suffix".to_string(),
                evidence: package_name.to_string(),
                severity: "Medium".to_string(),
            });
        }

        if package_name.starts_with("test-") || package_name.starts_with("demo-") {
            patterns.push(SuspiciousPattern {
                pattern_type: "Test Prefix".to_string(),
                description: "Package name starts with test/demo prefix".to_string(),
                evidence: package_name.to_string(),
                severity: "Medium".to_string(),
            });
        }

        // Check for numbers at the end
        if package_name
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_digit())
        {
            patterns.push(SuspiciousPattern {
                pattern_type: "Numeric Suffix".to_string(),
                description: "Package name ends with a number".to_string(),
                evidence: package_name.to_string(),
                severity: "Low".to_string(),
            });
        }

        // Check for repeated characters
        if self.has_repeated_characters(package_name) {
            patterns.push(SuspiciousPattern {
                pattern_type: "Repeated Characters".to_string(),
                description: "Package name contains repeated characters".to_string(),
                evidence: package_name.to_string(),
                severity: "Low".to_string(),
            });
        }

        // Check for common typosquatting indicators
        if package_name.contains('1') || package_name.contains('0') {
            patterns.push(SuspiciousPattern {
                pattern_type: "Number Substitution".to_string(),
                description: "Package name uses numbers that might substitute letters".to_string(),
                evidence: package_name.to_string(),
                severity: "Medium".to_string(),
            });
        }

        patterns
    }

    fn calculate_typosquatting_score(
        &self,
        similar_packages: &[SimilarPackage],
        suspicious_patterns: &[SuspiciousPattern],
    ) -> f32 {
        let mut score = 0.0;

        // Score based on similar packages
        for package in similar_packages {
            let package_score = match package.risk_level {
                RiskLevel::Critical => 0.4,
                RiskLevel::High => 0.3,
                RiskLevel::Medium => 0.2,
                RiskLevel::Low => 0.1,
            };
            score += package_score * package.distance_metrics.normalized_similarity;
        }

        // Score based on suspicious patterns
        for pattern in suspicious_patterns {
            let pattern_score = match pattern.severity.as_str() {
                "High" => 0.3,
                "Medium" => 0.2,
                "Low" => 0.1,
                _ => 0.05,
            };
            score += pattern_score;
        }

        score.min(1.0)
    }

    fn generate_recommendations(
        &self,
        similar_packages: &[SimilarPackage],
        suspicious_patterns: &[SuspiciousPattern],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !similar_packages.is_empty() {
            recommendations.push("Verify the package author and repository legitimacy".to_string());
            recommendations
                .push("Check the package's publication date and version history".to_string());
            recommendations
                .push("Compare functionality with the similar legitimate package".to_string());
        }

        if similar_packages
            .iter()
            .any(|p| matches!(p.risk_level, RiskLevel::Critical))
        {
            recommendations.push("HIGH RISK: This package name is very similar to a popular package - exercise extreme caution".to_string());
        }

        if !suspicious_patterns.is_empty() {
            recommendations.push("Review the package name for suspicious patterns".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push(
                "Package name appears legitimate, but continue with normal security practices"
                    .to_string(),
            );
        }

        recommendations
    }

    fn are_visually_similar(&self, c1: char, c2: char) -> bool {
        self.visual_similarities
            .get(&c1)
            .is_some_and(|similar| similar.contains(&c2))
    }

    fn is_transposition(&self, s1: &str, s2: &str) -> bool {
        if s1.len() != s2.len() {
            return false;
        }

        let chars1: Vec<char> = s1.chars().collect();
        let chars2: Vec<char> = s2.chars().collect();
        let mut differences = 0;

        for i in 0..chars1.len() {
            if chars1[i] != chars2[i] {
                differences += 1;
                if differences > 2 {
                    return false;
                }
            }
        }

        differences == 2
    }

    fn has_repeated_characters(&self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] && chars[i].is_alphabetic() {
                return true;
            }
        }
        false
    }

    fn create_visual_similarities() -> HashMap<char, Vec<char>> {
        let mut similarities = HashMap::new();

        // Numbers and letters
        similarities.insert('0', vec!['o', 'O']);
        similarities.insert('1', vec!['l', 'I', '|']);
        similarities.insert('5', vec!['s', 'S']);
        similarities.insert('6', vec!['g', 'G']);
        similarities.insert('8', vec!['b', 'B']);

        // Visually similar letters
        similarities.insert('o', vec!['0', 'O']);
        similarities.insert('l', vec!['1', 'I', '|']);
        similarities.insert('s', vec!['5', 'S']);
        similarities.insert('g', vec!['6', 'q']);
        similarities.insert('b', vec!['8', 'd']);
        similarities.insert('d', vec!['b', 'p']);
        similarities.insert('p', vec!['d', 'q']);
        similarities.insert('q', vec!['p', 'g']);
        similarities.insert('m', vec!['n', 'r']);
        similarities.insert('n', vec!['m', 'u']);
        similarities.insert('u', vec!['n', 'v']);
        similarities.insert('v', vec!['u', 'w']);
        similarities.insert('w', vec!['v']);

        similarities
    }

    fn create_phonetic_similarities() -> HashMap<String, Vec<String>> {
        let mut similarities = HashMap::new();

        // Common phonetic substitutions
        similarities.insert("ph".to_string(), vec!["f".to_string()]);
        similarities.insert("ck".to_string(), vec!["k".to_string()]);
        similarities.insert("qu".to_string(), vec!["kw".to_string()]);

        similarities
    }

    fn load_popular_packages(&mut self) {
        // Load popular npm packages
        let npm_packages = [
            ("react", 50_000_000),
            ("lodash", 45_000_000),
            ("express", 40_000_000),
            ("axios", 35_000_000),
            ("moment", 30_000_000),
            ("webpack", 25_000_000),
            ("babel-core", 20_000_000),
            ("eslint", 18_000_000),
            ("typescript", 15_000_000),
            ("vue", 12_000_000),
        ];

        for (name, downloads) in npm_packages {
            self.popular_packages.insert(
                name.to_string(),
                PopularPackage {
                    name: name.to_string(),
                    download_count: downloads,
                    ecosystem: PackageEcosystem::Npm,
                    aliases: vec![],
                },
            );
        }

        // Load popular PyPI packages
        let pypi_packages = [
            ("requests", 100_000_000),
            ("numpy", 80_000_000),
            ("pandas", 70_000_000),
            ("setuptools", 65_000_000),
            ("django", 60_000_000),
            ("flask", 55_000_000),
            ("pillow", 50_000_000),
            ("pytest", 45_000_000),
            ("matplotlib", 40_000_000),
            ("scipy", 35_000_000),
        ];

        for (name, downloads) in pypi_packages {
            self.popular_packages.insert(
                name.to_string(),
                PopularPackage {
                    name: name.to_string(),
                    download_count: downloads,
                    ecosystem: PackageEcosystem::PyPI,
                    aliases: vec![],
                },
            );
        }
    }
}

impl KeyboardLayout {
    fn qwerty() -> Self {
        let mut adjacent_keys = HashMap::new();

        // Define QWERTY keyboard adjacencies
        let adjacencies = [
            ('q', vec!['w', 'a', 's']),
            ('w', vec!['q', 'e', 'a', 's', 'd']),
            ('e', vec!['w', 'r', 's', 'd', 'f']),
            ('r', vec!['e', 't', 'd', 'f', 'g']),
            ('t', vec!['r', 'y', 'f', 'g', 'h']),
            ('y', vec!['t', 'u', 'g', 'h', 'j']),
            ('u', vec!['y', 'i', 'h', 'j', 'k']),
            ('i', vec!['u', 'o', 'j', 'k', 'l']),
            ('o', vec!['i', 'p', 'k', 'l']),
            ('p', vec!['o', 'l']),
            ('a', vec!['q', 'w', 's', 'z', 'x']),
            ('s', vec!['q', 'w', 'e', 'a', 'd', 'z', 'x', 'c']),
            ('d', vec!['w', 'e', 'r', 's', 'f', 'x', 'c', 'v']),
            ('f', vec!['e', 'r', 't', 'd', 'g', 'c', 'v', 'b']),
            ('g', vec!['r', 't', 'y', 'f', 'h', 'v', 'b', 'n']),
            ('h', vec!['t', 'y', 'u', 'g', 'j', 'b', 'n', 'm']),
            ('j', vec!['y', 'u', 'i', 'h', 'k', 'n', 'm']),
            ('k', vec!['u', 'i', 'o', 'j', 'l', 'm']),
            ('l', vec!['i', 'o', 'p', 'k']),
            ('z', vec!['a', 's', 'x']),
            ('x', vec!['a', 's', 'd', 'z', 'c']),
            ('c', vec!['s', 'd', 'f', 'x', 'v']),
            ('v', vec!['d', 'f', 'g', 'c', 'b']),
            ('b', vec!['f', 'g', 'h', 'v', 'n']),
            ('n', vec!['g', 'h', 'j', 'b', 'm']),
            ('m', vec!['h', 'j', 'k', 'n']),
        ];

        for (key, adjacent) in adjacencies {
            adjacent_keys.insert(key, adjacent);
        }

        Self { adjacent_keys }
    }

    fn are_adjacent(&self, c1: char, c2: char) -> bool {
        self.adjacent_keys
            .get(&c1.to_ascii_lowercase())
            .is_some_and(|adjacent| adjacent.contains(&c2.to_ascii_lowercase()))
    }
}

impl Default for TyposquattingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze package name for typosquatting using advanced algorithms
pub fn analyze_typosquatting(package_name: &str, ecosystem: &str) -> Result<TyposquattingAnalysis> {
    let detector = TyposquattingDetector::new();
    detector.analyze_package_name(package_name, ecosystem)
}

/// Quick check if a package name is potentially typosquatting
pub fn is_potential_typosquatting(package_name: &str, ecosystem: &str) -> bool {
    analyze_typosquatting(package_name, ecosystem)
        .is_ok_and(|analysis| analysis.is_potential_typosquatting)
}

/// Get similarity score between two package names
pub fn calculate_package_similarity(name1: &str, name2: &str) -> f32 {
    let levenshtein_dist = levenshtein(name1, name2);
    let max_len = name1.len().max(name2.len()) as f32;

    // Handle edge case where both strings are empty
    if max_len == 0.0 {
        return 1.0; // Two empty strings are identical
    }

    1.0 - (levenshtein_dist as f32 / max_len)
}
