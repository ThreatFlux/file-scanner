//! Typosquatting detection utilities

use std::collections::HashSet;
use strsim::levenshtein;

/// Typosquatting detector
pub struct TyposquattingDetector {
    popular_packages: HashSet<String>,
}

impl TyposquattingDetector {
    /// Create a new typosquatting detector
    pub fn new() -> Self {
        let mut popular_packages = HashSet::new();

        // Add popular npm packages
        for pkg in NPM_POPULAR_PACKAGES {
            popular_packages.insert(pkg.to_string());
        }

        // Add popular Python packages
        for pkg in PYTHON_POPULAR_PACKAGES {
            popular_packages.insert(pkg.to_string());
        }

        // Add popular Java packages
        for pkg in JAVA_POPULAR_PACKAGES {
            popular_packages.insert(pkg.to_string());
        }

        Self { popular_packages }
    }

    /// Check if a package name is likely typosquatting
    pub fn is_typosquatting(&self, package_name: &str) -> bool {
        // Check for common typosquatting patterns
        if self.has_suspicious_suffix(package_name) || self.has_suspicious_prefix(package_name) {
            return true;
        }

        // Check similarity to popular packages
        for popular in &self.popular_packages {
            let distance = levenshtein(package_name, popular);
            if distance > 0 && distance <= 2 {
                return true;
            }

            // Check for character substitution
            if self.is_character_substitution(package_name, popular) {
                return true;
            }
        }

        false
    }

    /// Find similar popular packages
    pub fn find_similar(&self, package_name: &str) -> Vec<String> {
        let mut similar = Vec::new();

        for popular in &self.popular_packages {
            let distance = levenshtein(package_name, popular);
            if distance > 0 && distance <= 3 {
                similar.push(popular.clone());
            }
        }

        similar
    }

    /// Check for suspicious suffixes
    fn has_suspicious_suffix(&self, name: &str) -> bool {
        const SUSPICIOUS_SUFFIXES: &[&str] = &[
            "-dev",
            "-test",
            "-beta",
            "-alpha",
            "-rc",
            "-snapshot",
            "js",
            "-js",
            "2",
            "-official",
            "-real",
            "-new",
        ];

        for suffix in SUSPICIOUS_SUFFIXES {
            if let Some(base) = name.strip_suffix(suffix) {
                // Check if removing suffix matches a popular package
                if self.popular_packages.contains(base) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for suspicious prefixes
    fn has_suspicious_prefix(&self, name: &str) -> bool {
        const SUSPICIOUS_PREFIXES: &[&str] =
            &["fake-", "test-", "my-", "new-", "real-", "official-"];

        for prefix in SUSPICIOUS_PREFIXES {
            if let Some(base) = name.strip_prefix(prefix) {
                if self.popular_packages.contains(base) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for single character substitution
    fn is_character_substitution(&self, name1: &str, name2: &str) -> bool {
        if name1.len() != name2.len() {
            return false;
        }

        let chars1: Vec<char> = name1.chars().collect();
        let chars2: Vec<char> = name2.chars().collect();
        let mut differences = 0;

        for (c1, c2) in chars1.iter().zip(chars2.iter()) {
            if c1 != c2 {
                differences += 1;
                if differences > 1 {
                    return false;
                }

                // Check for common visual confusions
                if !self.is_visual_confusion(*c1, *c2) {
                    return true;
                }
            }
        }

        differences == 1
    }

    /// Check for visually similar characters
    fn is_visual_confusion(&self, c1: char, c2: char) -> bool {
        matches!(
            (c1, c2),
            ('0', 'o')
                | ('o', '0')
                | ('0', 'O')
                | ('O', '0')
                | ('1', 'l')
                | ('l', '1')
                | ('1', 'I')
                | ('I', '1')
                | ('5', 's')
                | ('s', '5')
                | ('5', 'S')
                | ('S', '5')
        )
    }
}

impl Default for TyposquattingDetector {
    fn default() -> Self {
        Self::new()
    }
}

// Popular NPM packages
const NPM_POPULAR_PACKAGES: &[&str] = &[
    "react",
    "express",
    "axios",
    "lodash",
    "moment",
    "webpack",
    "typescript",
    "vue",
    "angular",
    "jquery",
    "bootstrap",
    "eslint",
    "babel-core",
    "jest",
    "mocha",
    "chai",
    "gulp",
    "grunt",
    "nodemon",
    "prettier",
    "commander",
];

// Popular Python packages
const PYTHON_POPULAR_PACKAGES: &[&str] = &[
    "numpy",
    "pandas",
    "requests",
    "flask",
    "django",
    "tensorflow",
    "matplotlib",
    "scipy",
    "scikit-learn",
    "pytest",
    "pillow",
    "beautifulsoup4",
    "selenium",
    "pytorch",
    "keras",
    "sqlalchemy",
    "celery",
    "scrapy",
    "opencv-python",
];

// Popular Java packages
const JAVA_POPULAR_PACKAGES: &[&str] = &[
    "spring-core",
    "spring-boot",
    "junit",
    "log4j",
    "commons-lang",
    "guava",
    "jackson-core",
    "gson",
    "okhttp",
    "retrofit",
    "hibernate-core",
    "mockito",
    "slf4j-api",
    "logback-classic",
    "apache-commons",
    "jetty",
    "tomcat",
];
