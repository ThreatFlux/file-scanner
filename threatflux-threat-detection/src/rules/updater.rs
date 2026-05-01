//! Rule update management for threat detection

use crate::error::{Result, ThreatError};
use chrono::{DateTime, Utc};
use std::path::Path;

/// Rule source configuration
#[derive(Debug, Clone)]
pub struct RuleSource {
    /// Name of the rule source
    pub name: String,
    /// URL or path to rule source
    pub url: String,
    /// Type of source (git, http, file)
    pub source_type: RuleSourceType,
    /// Update frequency in hours
    pub update_frequency_hours: u64,
    /// Last update timestamp
    pub last_updated: Option<DateTime<Utc>>,
}

/// Types of rule sources
#[derive(Debug, Clone)]
pub enum RuleSourceType {
    /// Git repository
    Git,
    /// HTTP endpoint
    Http,
    /// Local file system
    File,
}

/// Rule updater for managing threat detection rules
pub struct RuleUpdater {
    sources: Vec<RuleSource>,
    rules_directory: std::path::PathBuf,
}

impl RuleUpdater {
    /// Create a new rule updater
    pub fn new<P: AsRef<Path>>(rules_directory: P) -> Self {
        Self {
            sources: Vec::new(),
            rules_directory: rules_directory.as_ref().to_path_buf(),
        }
    }

    /// Add a rule source
    pub fn add_source(&mut self, source: RuleSource) {
        self.sources.push(source);
    }

    /// Update rules from all sources
    pub async fn update_all(&mut self) -> Result<()> {
        for source in &mut self.sources {
            if let Err(e) = Self::update_source(source).await {
                log::warn!("Failed to update source {}: {}", source.name, e);
            }
        }
        Ok(())
    }

    /// Update rules from a specific source
    async fn update_source(source: &mut RuleSource) -> Result<()> {
        match source.source_type {
            RuleSourceType::Git => Self::update_from_git(source).await,
            RuleSourceType::Http => Self::update_from_http(source).await,
            RuleSourceType::File => Self::update_from_file(source).await,
        }
    }

    /// Update rules from Git repository
    async fn update_from_git(source: &mut RuleSource) -> Result<()> {
        // Placeholder implementation - would use git2 crate when feature is enabled
        log::info!("Updating rules from Git source: {}", source.name);
        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Update rules from HTTP endpoint
    async fn update_from_http(source: &mut RuleSource) -> Result<()> {
        // Placeholder implementation - would use reqwest when feature is enabled
        log::info!("Updating rules from HTTP source: {}", source.name);
        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Update rules from local file
    async fn update_from_file(source: &mut RuleSource) -> Result<()> {
        // Placeholder implementation
        log::info!("Updating rules from file source: {}", source.name);

        if !Path::new(&source.url).exists() {
            return Err(ThreatError::rule_not_found(&source.url));
        }

        source.last_updated = Some(Utc::now());
        Ok(())
    }

    /// Check if sources need updating
    pub fn needs_update(&self) -> Vec<&RuleSource> {
        let now = Utc::now();
        self.sources
            .iter()
            .filter(|source| {
                match source.last_updated {
                    Some(last_update) => {
                        let hours_since_update = (now - last_update).num_hours() as u64;
                        hours_since_update >= source.update_frequency_hours
                    }
                    None => true, // Never updated
                }
            })
            .collect()
    }

    /// Get rule sources
    pub fn get_sources(&self) -> &[RuleSource] {
        &self.sources
    }

    /// Get rules directory
    pub fn rules_directory(&self) -> &Path {
        &self.rules_directory
    }
}
