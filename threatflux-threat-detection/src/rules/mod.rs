//! Rule management and compilation

use crate::types::{CompiledRules, RuleMetadata};
use crate::{Result, ThreatError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub mod builtin;

#[cfg(feature = "rule-management")]
pub mod updater;

#[cfg(feature = "rule-management")]
use updater::{RuleSource, RuleSourceType};

// Simple rule source for when rule-management feature is disabled
#[cfg(not(feature = "rule-management"))]
#[derive(Debug, Clone)]
pub struct RuleSource {
    pub name: String,
    pub url: String,
    pub source_type: RuleSourceType,
}

#[cfg(not(feature = "rule-management"))]
#[derive(Debug, Clone)]
pub enum RuleSourceType {
    Local,
    Builtin,
}

/// Rule manager for loading, compiling, and updating threat detection rules
pub struct RuleManager {
    rule_sources: Vec<RuleSource>,
    #[allow(dead_code)]
    cache_dir: PathBuf,
    compiled_rules: Option<CompiledRules>,
}

impl RuleManager {
    /// Create a new rule manager
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Self {
            rule_sources: Vec::new(),
            cache_dir: cache_dir.as_ref().to_path_buf(),
            compiled_rules: None,
        }
    }

    /// Add a rule source
    pub fn add_source(&mut self, source: RuleSource) {
        self.rule_sources.push(source);
    }

    /// Load and compile all rules
    pub async fn compile_rules(&mut self) -> Result<&CompiledRules> {
        let mut all_rules = String::new();
        let mut metadata = HashMap::new();
        let mut errors = Vec::new();
        let warnings = Vec::new();

        // Load built-in rules
        #[cfg(feature = "builtin-rules")]
        {
            let builtin_rules = builtin::get_builtin_rules();
            for rule in &builtin_rules {
                all_rules.push_str(rule);
                all_rules.push('\n');
            }
        }

        // Load rules from sources
        for source in &self.rule_sources {
            match self.load_rules_from_source(source).await {
                Ok(rules) => {
                    all_rules.push_str(&rules);
                    all_rules.push('\n');
                }
                Err(e) => {
                    errors.push(format!("Failed to load from {}: {}", source.name, e));
                }
            }
        }

        // Parse metadata from rules
        metadata.extend(self.extract_metadata(&all_rules));

        // Compile rules (this would use the actual YARA compiler in real implementation)
        let rule_count = self.count_rules(&all_rules);

        self.compiled_rules = Some(CompiledRules {
            rule_count,
            errors,
            warnings,
            metadata,
        });

        Ok(self.compiled_rules.as_ref().unwrap())
    }

    /// Get compiled rules
    pub fn get_compiled_rules(&self) -> Option<&CompiledRules> {
        self.compiled_rules.as_ref()
    }

    /// Update rules from all sources
    #[cfg(feature = "rule-management")]
    pub async fn update_rules(&mut self) -> Result<()> {
        for source in &self.rule_sources {
            if let Err(e) = updater::update_source(source, &self.cache_dir).await {
                log::warn!("Failed to update source {}: {}", source.name, e);
            }
        }

        // Recompile after updates
        self.compile_rules().await?;
        Ok(())
    }

    /// Load rules from a specific source
    async fn load_rules_from_source(&self, source: &RuleSource) -> Result<String> {
        match source.source_type {
            RuleSourceType::Local => std::fs::read_to_string(&source.url)
                .map_err(|e| ThreatError::rule_load(format!("Local file {}: {}", source.url, e))),
            RuleSourceType::Builtin => {
                #[cfg(feature = "builtin-rules")]
                {
                    Ok(builtin::get_builtin_rules().join("\n"))
                }
                #[cfg(not(feature = "builtin-rules"))]
                {
                    Err(ThreatError::rule_load("Built-in rules not enabled"))
                }
            }
            #[cfg(feature = "rule-management")]
            RuleSourceType::Http => updater::fetch_http_rules(source).await,
            #[cfg(feature = "rule-management")]
            RuleSourceType::Git => updater::fetch_git_rules(source, &self.cache_dir).await,
        }
    }

    /// Extract metadata from rule text
    fn extract_metadata(&self, rules: &str) -> HashMap<String, RuleMetadata> {
        let mut metadata = HashMap::new();

        for rule_text in rules.split("rule ").skip(1) {
            if let Some(rule_name) = self.extract_rule_name(rule_text) {
                let rule_metadata = RuleMetadata {
                    name: rule_name.clone(),
                    author: self.extract_metadata_field(rule_text, "author"),
                    description: self.extract_metadata_field(rule_text, "description"),
                    version: self.extract_metadata_field(rule_text, "version"),
                    date: self.extract_metadata_field(rule_text, "date"),
                    tags: self.extract_tags(rule_text),
                };
                metadata.insert(rule_name, rule_metadata);
            }
        }

        metadata
    }

    /// Extract rule name from rule text
    fn extract_rule_name(&self, rule_text: &str) -> Option<String> {
        rule_text
            .lines()
            .next()?
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    }

    /// Extract metadata field from rule text
    fn extract_metadata_field(&self, rule_text: &str, field: &str) -> Option<String> {
        for line in rule_text.lines() {
            let line = line.trim();
            if line.starts_with(field) && line.contains('=') {
                let value = line.split('=').nth(1)?;
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
        None
    }

    /// Extract tags from rule text
    fn extract_tags(&self, rule_text: &str) -> Vec<String> {
        // Simple tag extraction - look for tags: line
        for line in rule_text.lines() {
            let line = line.trim();
            if line.starts_with("tags:") {
                let tags_str = line.strip_prefix("tags:").unwrap_or("").trim();
                return tags_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        Vec::new()
    }

    /// Count number of rules in rule text
    fn count_rules(&self, rules: &str) -> usize {
        rules.matches("rule ").count()
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new(std::env::temp_dir().join("threatflux-rules"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_manager_creation() {
        let manager = RuleManager::new("/tmp/test");
        assert_eq!(manager.rule_sources.len(), 0);
        assert!(manager.compiled_rules.is_none());
    }

    #[test]
    fn test_rule_counting() {
        let manager = RuleManager::default();
        let rules = r#"
rule test_rule_1 {
    condition: true
}

rule test_rule_2 {
    condition: false
}
"#;
        assert_eq!(manager.count_rules(rules), 2);
    }

    #[test]
    fn test_rule_name_extraction() {
        let manager = RuleManager::default();
        let rule_text = "test_rule { condition: true }";
        assert_eq!(
            manager.extract_rule_name(rule_text),
            Some("test_rule".to_string())
        );
    }
}
