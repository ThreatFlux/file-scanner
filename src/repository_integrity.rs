use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use url::Url;
// use git2::{Repository, ObjectType, Oid};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RepositoryIntegrityAnalysis {
    pub package_info: PackageRepositoryInfo,
    pub integrity_checks: Vec<IntegrityCheck>,
    pub source_comparison: SourceComparison,
    pub maintainer_verification: MaintainerVerification,
    pub timeline_analysis: TimelineAnalysis,
    pub trust_score: f32,
    pub risk_indicators: Vec<RiskIndicator>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageRepositoryInfo {
    pub package_name: String,
    pub package_version: String,
    pub repository_url: Option<String>,
    pub homepage_url: Option<String>,
    pub registry_info: RegistryInfo,
    pub repository_status: RepositoryStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistryInfo {
    pub registry_type: RegistryType,
    pub publish_date: Option<String>,
    pub last_modified: Option<String>,
    pub download_count: Option<u64>,
    pub version_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RegistryType {
    Npm,
    PyPI,
    Cargo,
    Maven,
    NuGet,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RepositoryStatus {
    Accessible,
    NotFound,
    Private,
    Archived,
    Deleted,
    InvalidUrl,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrityCheck {
    pub check_type: IntegrityCheckType,
    pub status: CheckStatus,
    pub description: String,
    pub evidence: Vec<String>,
    pub severity: CheckSeverity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IntegrityCheckType {
    RepositoryExists,
    UrlConsistency,
    VersionTagExists,
    CommitExists,
    FileChecksums,
    ContentComparison,
    MaintainerVerification,
    SignatureVerification,
    TimelineConsistency,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CheckStatus {
    Pass,
    Fail,
    Warning,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CheckSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceComparison {
    pub comparison_possible: bool,
    pub files_compared: u32,
    pub files_matched: u32,
    pub files_different: u32,
    pub missing_in_package: Vec<String>,
    pub extra_in_package: Vec<String>,
    pub content_differences: Vec<ContentDifference>,
    pub similarity_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContentDifference {
    pub file_path: String,
    pub difference_type: DifferenceType,
    pub description: String,
    pub severity: CheckSeverity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DifferenceType {
    ContentMismatch,
    FileMissing,
    ExtraFile,
    SizeSignificantDifference,
    TimestampMismatch,
    PermissionMismatch,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerVerification {
    pub package_maintainers: Vec<MaintainerInfo>,
    pub repository_contributors: Vec<ContributorInfo>,
    pub maintainer_overlap: Vec<String>,
    pub verification_status: VerificationStatus,
    pub suspicious_activity: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerInfo {
    pub name: String,
    pub email: Option<String>,
    pub registry_username: Option<String>,
    pub publish_permissions: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContributorInfo {
    pub name: String,
    pub email: Option<String>,
    pub commit_count: u32,
    pub first_commit: Option<String>,
    pub last_commit: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VerificationStatus {
    Verified,
    PartiallyVerified,
    Unverified,
    Suspicious,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineAnalysis {
    pub package_creation: Option<String>,
    pub repository_creation: Option<String>,
    pub first_commit: Option<String>,
    pub version_releases: Vec<ReleaseInfo>,
    pub timeline_inconsistencies: Vec<TimelineInconsistency>,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReleaseInfo {
    pub version: String,
    pub release_date: Option<String>,
    pub commit_hash: Option<String>,
    pub tag_exists: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineInconsistency {
    pub inconsistency_type: String,
    pub description: String,
    pub severity: CheckSeverity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RiskIndicator {
    pub indicator_type: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

pub struct RepositoryIntegrityChecker {
    client: Client,
}

impl RepositoryIntegrityChecker {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("file-scanner-integrity-checker/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Perform comprehensive repository integrity analysis
    pub async fn analyze_package_integrity(
        &self,
        package_path: &Path,
        package_name: &str,
        package_version: &str,
        registry_type: RegistryType,
    ) -> Result<RepositoryIntegrityAnalysis> {
        // Step 1: Extract package repository information
        let package_info = self
            .extract_package_repository_info(
                package_path,
                package_name,
                package_version,
                registry_type,
            )
            .await?;

        // Step 2: Perform integrity checks
        let integrity_checks = self.perform_integrity_checks(&package_info).await?;

        // Step 3: Compare package contents with repository
        let source_comparison = if package_info.repository_status == RepositoryStatus::Accessible {
            self.compare_package_with_repository(&package_info, package_path)
                .await?
        } else {
            SourceComparison {
                comparison_possible: false,
                files_compared: 0,
                files_matched: 0,
                files_different: 0,
                missing_in_package: vec![],
                extra_in_package: vec![],
                content_differences: vec![],
                similarity_score: 0.0,
            }
        };

        // Step 4: Verify maintainer information
        let maintainer_verification = self.verify_maintainers(&package_info).await?;

        // Step 5: Analyze timeline consistency
        let timeline_analysis = self.analyze_timeline(&package_info).await?;

        // Step 6: Calculate trust score
        let trust_score = self.calculate_trust_score(
            &integrity_checks,
            &source_comparison,
            &maintainer_verification,
            &timeline_analysis,
        );

        // Step 7: Identify risk indicators
        let risk_indicators = self.identify_risk_indicators(
            &integrity_checks,
            &source_comparison,
            &maintainer_verification,
            &timeline_analysis,
        );

        // Step 8: Generate recommendations
        let recommendations = self.generate_recommendations(&risk_indicators, trust_score);

        Ok(RepositoryIntegrityAnalysis {
            package_info,
            integrity_checks,
            source_comparison,
            maintainer_verification,
            timeline_analysis,
            trust_score,
            risk_indicators,
            recommendations,
        })
    }

    async fn extract_package_repository_info(
        &self,
        package_path: &Path,
        package_name: &str,
        package_version: &str,
        registry_type: RegistryType,
    ) -> Result<PackageRepositoryInfo> {
        // Extract repository URL from package metadata
        let repository_url = self.extract_repository_url(package_path, &registry_type)?;
        let homepage_url = self.extract_homepage_url(package_path, &registry_type)?;

        // Fetch registry information
        let registry_info = self
            .fetch_registry_info(package_name, &registry_type)
            .await?;

        // Check repository status
        let repository_status = if let Some(ref url) = repository_url {
            self.check_repository_status(url).await
        } else {
            RepositoryStatus::NotFound
        };

        Ok(PackageRepositoryInfo {
            package_name: package_name.to_string(),
            package_version: package_version.to_string(),
            repository_url,
            homepage_url,
            registry_info,
            repository_status,
        })
    }

    fn extract_repository_url(
        &self,
        package_path: &Path,
        registry_type: &RegistryType,
    ) -> Result<Option<String>> {
        match registry_type {
            RegistryType::Npm => self.extract_npm_repository_url(package_path),
            RegistryType::PyPI => self.extract_python_repository_url(package_path),
            _ => Ok(None),
        }
    }

    fn extract_npm_repository_url(&self, package_path: &Path) -> Result<Option<String>> {
        let package_json_path = if package_path.is_file() {
            // Extract from tarball
            return Ok(None); // TODO: Implement tarball extraction
        } else {
            package_path.join("package.json")
        };

        if package_json_path.exists() {
            let content = std::fs::read_to_string(&package_json_path)?;
            let json: serde_json::Value = serde_json::from_str(&content)?;

            if let Some(repository) = json.get("repository") {
                if let Some(url) = repository.get("url").and_then(|u| u.as_str()) {
                    return Ok(Some(self.normalize_repository_url(url)));
                }
            }
        }

        Ok(None)
    }

    fn extract_python_repository_url(&self, package_path: &Path) -> Result<Option<String>> {
        // Check setup.py for repository URL
        let setup_py_path = package_path.join("setup.py");
        if setup_py_path.exists() {
            let content = std::fs::read_to_string(&setup_py_path)?;
            if let Some(url) = self.extract_url_from_setup_py(&content) {
                return Ok(Some(self.normalize_repository_url(&url)));
            }
        }

        // Check pyproject.toml
        let pyproject_path = package_path.join("pyproject.toml");
        if pyproject_path.exists() {
            let content = std::fs::read_to_string(&pyproject_path)?;
            if let Some(url) = self.extract_url_from_pyproject_toml(&content) {
                return Ok(Some(self.normalize_repository_url(&url)));
            }
        }

        Ok(None)
    }

    fn extract_url_from_setup_py(&self, content: &str) -> Option<String> {
        // Simple regex to find repository URL in setup.py
        let patterns = [
            r#"url\s*=\s*['"](https://github\.com/[^'"]+)['"#,
            r#"project_urls\s*=\s*\{[^}]*['"](Source|Repository)['"]\s*:\s*['"](https://[^'"]+)['"#,
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(content) {
                    if let Some(url) = captures.get(captures.len() - 1) {
                        return Some(url.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    fn extract_url_from_pyproject_toml(&self, content: &str) -> Option<String> {
        // Simple parsing for pyproject.toml
        for line in content.lines() {
            if line.contains("repository") && line.contains("http") {
                if let Some(start) = line.find("http") {
                    if let Some(end) = line[start..].find('"') {
                        return Some(line[start..start + end].to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_homepage_url(
        &self,
        package_path: &Path,
        registry_type: &RegistryType,
    ) -> Result<Option<String>> {
        if matches!(registry_type, RegistryType::Npm) {
            let package_json_path = package_path.join("package.json");
            if package_json_path.exists() {
                let content = std::fs::read_to_string(&package_json_path)?;
                let json: serde_json::Value = serde_json::from_str(&content)?;
                if let Some(homepage) = json.get("homepage").and_then(|h| h.as_str()) {
                    return Ok(Some(homepage.to_string()));
                }
            }
        }
        Ok(None)
    }

    fn normalize_repository_url(&self, url: &str) -> String {
        let mut normalized = url.to_string();

        // Remove git+ prefix
        if normalized.starts_with("git+") {
            normalized = normalized[4..].to_string();
        }

        // Remove .git suffix
        if normalized.ends_with(".git") {
            normalized = normalized[..normalized.len() - 4].to_string();
        }

        // Convert SSH to HTTPS
        if normalized.starts_with("git@github.com:") {
            normalized = normalized.replace("git@github.com:", "https://github.com/");
        }

        normalized
    }

    async fn fetch_registry_info(
        &self,
        package_name: &str,
        registry_type: &RegistryType,
    ) -> Result<RegistryInfo> {
        match registry_type {
            RegistryType::Npm => self.fetch_npm_registry_info(package_name).await,
            RegistryType::PyPI => self.fetch_pypi_registry_info(package_name).await,
            _ => Ok(RegistryInfo {
                registry_type: registry_type.clone(),
                publish_date: None,
                last_modified: None,
                download_count: None,
                version_count: None,
            }),
        }
    }

    async fn fetch_npm_registry_info(&self, package_name: &str) -> Result<RegistryInfo> {
        let url = format!("https://registry.npmjs.org/{package_name}");

        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let json: serde_json::Value = response.json().await?;

                let version_count = json
                    .get("versions")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.len() as u32);

                let time_info = json.get("time").and_then(|t| t.as_object());
                let publish_date = time_info
                    .and_then(|t| t.get("created"))
                    .and_then(|d| d.as_str())
                    .map(String::from);
                let last_modified = time_info
                    .and_then(|t| t.get("modified"))
                    .and_then(|d| d.as_str())
                    .map(String::from);

                Ok(RegistryInfo {
                    registry_type: RegistryType::Npm,
                    publish_date,
                    last_modified,
                    download_count: None, // Would need separate API call
                    version_count,
                })
            }
            _ => Ok(RegistryInfo {
                registry_type: RegistryType::Npm,
                publish_date: None,
                last_modified: None,
                download_count: None,
                version_count: None,
            }),
        }
    }

    async fn fetch_pypi_registry_info(&self, package_name: &str) -> Result<RegistryInfo> {
        let url = format!("https://pypi.org/pypi/{package_name}/json");

        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let json: serde_json::Value = response.json().await?;

                let version_count = json
                    .get("releases")
                    .and_then(|r| r.as_object())
                    .map(|obj| obj.len() as u32);

                Ok(RegistryInfo {
                    registry_type: RegistryType::PyPI,
                    publish_date: None, // Would need to parse release info
                    last_modified: None,
                    download_count: None,
                    version_count,
                })
            }
            _ => Ok(RegistryInfo {
                registry_type: RegistryType::PyPI,
                publish_date: None,
                last_modified: None,
                download_count: None,
                version_count: None,
            }),
        }
    }

    async fn check_repository_status(&self, url: &str) -> RepositoryStatus {
        if let Ok(_parsed_url) = Url::parse(url) {
            match self.client.head(url).send().await {
                Ok(response) => match response.status().as_u16() {
                    200 => RepositoryStatus::Accessible,
                    404 => RepositoryStatus::NotFound,
                    403 => RepositoryStatus::Private,
                    _ => RepositoryStatus::Unknown,
                },
                Err(_) => RepositoryStatus::Unknown,
            }
        } else {
            RepositoryStatus::InvalidUrl
        }
    }

    async fn perform_integrity_checks(
        &self,
        package_info: &PackageRepositoryInfo,
    ) -> Result<Vec<IntegrityCheck>> {
        let mut checks = Vec::new();

        // Check 1: Repository exists
        checks.push(IntegrityCheck {
            check_type: IntegrityCheckType::RepositoryExists,
            status: match package_info.repository_status {
                RepositoryStatus::Accessible => CheckStatus::Pass,
                RepositoryStatus::NotFound | RepositoryStatus::InvalidUrl => CheckStatus::Fail,
                RepositoryStatus::Private => CheckStatus::Warning,
                _ => CheckStatus::Unknown,
            },
            description: "Verify that the repository URL is accessible".to_string(),
            evidence: vec![package_info
                .repository_url
                .clone()
                .unwrap_or_else(|| "No repository URL".to_string())],
            severity: CheckSeverity::High,
        });

        // Check 2: URL consistency
        if let (Some(repo_url), Some(homepage_url)) =
            (&package_info.repository_url, &package_info.homepage_url)
        {
            let consistent = self.are_urls_consistent(repo_url, homepage_url);
            checks.push(IntegrityCheck {
                check_type: IntegrityCheckType::UrlConsistency,
                status: if consistent {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warning
                },
                description: "Verify consistency between repository and homepage URLs".to_string(),
                evidence: vec![repo_url.clone(), homepage_url.clone()],
                severity: CheckSeverity::Medium,
            });
        }

        // Check 3: Version tag exists (for accessible repositories)
        if package_info.repository_status == RepositoryStatus::Accessible {
            if let Some(repo_url) = &package_info.repository_url {
                let tag_exists = self
                    .check_version_tag_exists(repo_url, &package_info.package_version)
                    .await;
                checks.push(IntegrityCheck {
                    check_type: IntegrityCheckType::VersionTagExists,
                    status: if tag_exists {
                        CheckStatus::Pass
                    } else {
                        CheckStatus::Warning
                    },
                    description: "Verify that a Git tag exists for the package version".to_string(),
                    evidence: vec![format!("Version: {}", package_info.package_version)],
                    severity: CheckSeverity::Medium,
                });
            }
        }

        Ok(checks)
    }

    fn are_urls_consistent(&self, repo_url: &str, homepage_url: &str) -> bool {
        if let (Ok(repo_parsed), Ok(homepage_parsed)) =
            (Url::parse(repo_url), Url::parse(homepage_url))
        {
            repo_parsed.host() == homepage_parsed.host()
                || homepage_url.contains(repo_url)
                || repo_url.contains(homepage_url)
        } else {
            false
        }
    }

    async fn check_version_tag_exists(&self, repo_url: &str, version: &str) -> bool {
        // For GitHub repositories, check if tag exists via API
        if repo_url.contains("github.com") {
            if let Some((owner, repo)) = self.extract_github_owner_repo(repo_url) {
                let tag_url =
                    format!("https://api.github.com/repos/{owner}/{repo}/git/refs/tags/v{version}");
                if let Ok(response) = self.client.get(&tag_url).send().await {
                    return response.status().is_success();
                }

                // Try without 'v' prefix
                let tag_url =
                    format!("https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{version}");
                if let Ok(response) = self.client.get(&tag_url).send().await {
                    return response.status().is_success();
                }
            }
        }
        false
    }

    fn extract_github_owner_repo(&self, url: &str) -> Option<(String, String)> {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                if host == "github.com" {
                    let segments: Vec<&str> = parsed.path_segments()?.collect();
                    if segments.len() >= 2 {
                        return Some((segments[0].to_string(), segments[1].to_string()));
                    }
                }
            }
        }
        None
    }

    async fn compare_package_with_repository(
        &self,
        _package_info: &PackageRepositoryInfo,
        _package_path: &Path,
    ) -> Result<SourceComparison> {
        // This is a simplified implementation
        // In practice, you would clone the repository and compare files

        Ok(SourceComparison {
            comparison_possible: false,
            files_compared: 0,
            files_matched: 0,
            files_different: 0,
            missing_in_package: vec![],
            extra_in_package: vec![],
            content_differences: vec![],
            similarity_score: 0.0,
        })
    }

    async fn verify_maintainers(
        &self,
        _package_info: &PackageRepositoryInfo,
    ) -> Result<MaintainerVerification> {
        // Simplified implementation
        Ok(MaintainerVerification {
            package_maintainers: vec![],
            repository_contributors: vec![],
            maintainer_overlap: vec![],
            verification_status: VerificationStatus::Unverified,
            suspicious_activity: vec![],
        })
    }

    async fn analyze_timeline(
        &self,
        package_info: &PackageRepositoryInfo,
    ) -> Result<TimelineAnalysis> {
        // Simplified implementation
        Ok(TimelineAnalysis {
            package_creation: package_info.registry_info.publish_date.clone(),
            repository_creation: None,
            first_commit: None,
            version_releases: vec![],
            timeline_inconsistencies: vec![],
            suspicious_patterns: vec![],
        })
    }

    fn calculate_trust_score(
        &self,
        integrity_checks: &[IntegrityCheck],
        source_comparison: &SourceComparison,
        maintainer_verification: &MaintainerVerification,
        _timeline_analysis: &TimelineAnalysis,
    ) -> f32 {
        let mut score = 100.0;

        // Deduct points for failed integrity checks
        for check in integrity_checks {
            match (&check.status, &check.severity) {
                (CheckStatus::Fail, CheckSeverity::Critical) => score -= 30.0,
                (CheckStatus::Fail, CheckSeverity::High) => score -= 20.0,
                (CheckStatus::Fail, CheckSeverity::Medium) => score -= 10.0,
                (CheckStatus::Warning, CheckSeverity::High) => score -= 10.0,
                (CheckStatus::Warning, CheckSeverity::Medium) => score -= 5.0,
                _ => {}
            }
        }

        // Adjust for source comparison
        if source_comparison.comparison_possible {
            score = source_comparison.similarity_score.mul_add(20.0, score);
        }

        // Adjust for maintainer verification
        match maintainer_verification.verification_status {
            VerificationStatus::Verified => score += 10.0,
            VerificationStatus::Suspicious => score -= 40.0,
            _ => {}
        }

        score.clamp(0.0, 100.0)
    }

    fn identify_risk_indicators(
        &self,
        integrity_checks: &[IntegrityCheck],
        _source_comparison: &SourceComparison,
        maintainer_verification: &MaintainerVerification,
        timeline_analysis: &TimelineAnalysis,
    ) -> Vec<RiskIndicator> {
        let mut indicators = Vec::new();

        // Repository not accessible
        for check in integrity_checks {
            if matches!(check.check_type, IntegrityCheckType::RepositoryExists)
                && matches!(check.status, CheckStatus::Fail)
            {
                indicators.push(RiskIndicator {
                    indicator_type: "Repository Not Accessible".to_string(),
                    description: "Package repository is not accessible or does not exist"
                        .to_string(),
                    risk_level: RiskLevel::High,
                    evidence: "Repository URL returns 404 or is invalid".to_string(),
                });
            }
        }

        // Suspicious maintainer activity
        if matches!(
            maintainer_verification.verification_status,
            VerificationStatus::Suspicious
        ) {
            indicators.push(RiskIndicator {
                indicator_type: "Suspicious Maintainer Activity".to_string(),
                description: "Maintainer verification shows suspicious patterns".to_string(),
                risk_level: RiskLevel::High,
                evidence: maintainer_verification.suspicious_activity.join("; "),
            });
        }

        // Timeline inconsistencies
        if !timeline_analysis.timeline_inconsistencies.is_empty() {
            indicators.push(RiskIndicator {
                indicator_type: "Timeline Inconsistencies".to_string(),
                description: "Package and repository timelines don't align".to_string(),
                risk_level: RiskLevel::Medium,
                evidence: format!(
                    "{} inconsistencies found",
                    timeline_analysis.timeline_inconsistencies.len()
                ),
            });
        }

        indicators
    }

    fn generate_recommendations(
        &self,
        risk_indicators: &[RiskIndicator],
        trust_score: f32,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if trust_score < 30.0 {
            recommendations.push(
                "HIGH RISK: Do not use this package without thorough manual review".to_string(),
            );
        } else if trust_score < 50.0 {
            recommendations.push("Exercise caution when using this package".to_string());
        }

        for indicator in risk_indicators {
            match indicator.indicator_type.as_str() {
                "Repository Not Accessible" => {
                    recommendations
                        .push("Verify package authenticity through alternative means".to_string());
                }
                "Suspicious Maintainer Activity" => {
                    recommendations
                        .push("Investigate maintainer reputation and history".to_string());
                }
                "Timeline Inconsistencies" => {
                    recommendations
                        .push("Review package publication timeline for anomalies".to_string());
                }
                _ => {}
            }
        }

        if recommendations.is_empty() {
            recommendations.push(
                "Package appears legitimate, continue with normal security practices".to_string(),
            );
        }

        recommendations
    }
}

impl Default for RepositoryIntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze package repository integrity
pub async fn analyze_repository_integrity(
    package_path: &Path,
    package_name: &str,
    package_version: &str,
    registry_type: RegistryType,
) -> Result<RepositoryIntegrityAnalysis> {
    let checker = RepositoryIntegrityChecker::new();
    checker
        .analyze_package_integrity(package_path, package_name, package_version, registry_type)
        .await
}

/// Quick check for repository integrity issues
pub async fn has_integrity_issues(
    package_path: &Path,
    package_name: &str,
    package_version: &str,
    registry_type: RegistryType,
) -> bool {
    analyze_repository_integrity(package_path, package_name, package_version, registry_type)
        .await
        .map_or(true, |analysis| {
            analysis.trust_score < 70.0 || !analysis.risk_indicators.is_empty()
        })
}
