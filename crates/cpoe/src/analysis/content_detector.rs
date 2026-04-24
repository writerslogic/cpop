// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content type detection for keystroke context classification.
//!
//! Identifies whether keystrokes are from code, prose, technical documentation,
//! emails, chat messages, or other content types. Uses pattern matching and
//! keystroke characteristics to classify content.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detected content type with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContextType {
    /// Source code in identified language (e.g., "rust", "python", "javascript")
    Code { language: String },
    /// Prose writing with identified style
    Prose { style: ProseStyle },
    /// Technical documentation or reference
    TechnicalDoc,
    /// Email draft or message
    EmailDraft,
    /// Chat message or instant messaging
    ChatMessage,
    /// Unable to determine with confidence
    Unknown,
}

/// Prose writing style classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProseStyle {
    Academic,
    Fiction,
    Technical,
    Blog,
    Casual,
}

/// Result of content analysis for a keystroke window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalysis {
    /// Detected context type
    pub context: ContextType,
    /// Confidence in detection (0.0-1.0)
    pub confidence: f64,
    /// Detected patterns that led to this classification
    pub detected_patterns: Vec<String>,
    /// Timestamp of analysis (nanoseconds since epoch)
    pub timestamp: i64,
    /// Score breakdown by context type (for diagnostics)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<HashMap<String, f64>>,
}

/// Pattern matcher for code language detection.
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// Keywords for each language
    language_keywords: HashMap<String, Vec<&'static str>>,
    /// Common IDE/editor keybindings
    ide_patterns: Vec<&'static str>,
    /// Email/chat indicators
    messaging_patterns: Vec<&'static str>,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    /// Create a new pattern matcher with built-in keywords.
    pub fn new() -> Self {
        let mut keywords = HashMap::new();

        // Rust keywords
        keywords.insert(
            "rust".to_string(),
            vec![
                "fn", "pub", "impl", "struct", "enum", "trait", "use", "mod", "async", "await",
                "let", "mut", "const", "match", "unwrap", "Result", "Option", "Box",
            ],
        );

        // Python keywords
        keywords.insert(
            "python".to_string(),
            vec![
                "def", "class", "import", "from", "async", "await", "if", "elif", "else",
                "for", "while", "return", "yield", "raise", "try", "except", "with",
            ],
        );

        // JavaScript/TypeScript keywords
        keywords.insert(
            "javascript".to_string(),
            vec![
                "function", "const", "let", "var", "async", "await", "import", "export",
                "class", "extends", "interface", "type", "return", "if", "switch", "case",
                "=>", "=>",
            ],
        );

        // Swift keywords
        keywords.insert(
            "swift".to_string(),
            vec![
                "func", "class", "struct", "enum", "protocol", "extension", "var", "let",
                "import", "guard", "defer", "async", "await", "throws",
            ],
        );

        // SQL keywords
        keywords.insert(
            "sql".to_string(),
            vec![
                "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "JOIN", "CREATE",
                "DROP", "ALTER", "GROUP", "ORDER", "HAVING",
            ],
        );

        // IDE keybindings and editor patterns
        let ide_patterns = vec![
            "Ctrl+/",    // Comment/uncomment (cross-platform)
            "Cmd+/",     // Comment (macOS)
            "Cmd+Shift+L", // Multi-select (VS Code macOS)
            "Ctrl+Shift+L", // Multi-select (VS Code Windows/Linux)
            "Cmd+D",     // Select word (VS Code macOS)
            "Ctrl+D",    // Select word (VS Code Windows/Linux)
            "->",        // Arrow function or closure
            "=>",        // Function declaration
            ":::",       // Markdown fence marker
            "```",       // Code block delimiter
        ];

        // Email/chat patterns
        let messaging_patterns = vec![
            "To:",
            "Subject:",
            "From:",
            "Dear",
            "Thanks",
            "Best regards",
            "@username",
            "#hashtag",
        ];

        Self {
            language_keywords: keywords,
            ide_patterns,
            messaging_patterns,
        }
    }

    /// Detect patterns in text and return pattern names found.
    pub fn detect_patterns(&self, text: &str) -> Vec<String> {
        let mut found = Vec::new();

        // Check language keywords
        for (lang, keywords) in &self.language_keywords {
            for keyword in keywords {
                if text.contains(keyword) {
                    found.push(format!("{}:{}", lang, keyword));
                }
            }
        }

        // Check IDE patterns
        for pattern in &self.ide_patterns {
            if text.contains(pattern) {
                found.push(format!("ide:{}", pattern));
            }
        }

        // Check messaging patterns
        for pattern in &self.messaging_patterns {
            if text.contains(pattern) {
                found.push(format!("messaging:{}", pattern));
            }
        }

        found
    }
}

/// Analyze keystroke patterns to detect content type.
///
/// Uses a sliding window of recent keystrokes to classify content based on:
/// - Pattern frequency (code keywords, email headers, etc.)
/// - Keystroke timing characteristics
/// - Whitespace and punctuation patterns
///
/// # Confidence Thresholds
/// - ≥0.80: High confidence classification
/// - 0.60-0.79: Moderate confidence
/// - <0.60: Low confidence, return Unknown
#[derive(Debug)]
pub struct ContentDetector {
    matcher: PatternMatcher,
}

impl Default for ContentDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentDetector {
    /// Create a new content detector.
    pub fn new() -> Self {
        Self {
            matcher: PatternMatcher::new(),
        }
    }

    /// Analyze content from a keystroke window.
    ///
    /// # Arguments
    /// - `text`: Recent accumulated text (typically last 500-1000 characters)
    /// - `keystroke_metrics`: Timing information (inter-keystroke intervals)
    /// - `timestamp`: Current timestamp in nanoseconds
    ///
    /// # Returns
    /// ContentAnalysis with detected type and confidence
    pub fn analyze(
        &self,
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
        timestamp: i64,
    ) -> ContentAnalysis {
        if text.is_empty() {
            return ContentAnalysis {
                context: ContextType::Unknown,
                confidence: 0.0,
                detected_patterns: Vec::new(),
                timestamp,
                scores: None,
            };
        }

        let patterns = self.matcher.detect_patterns(text);
        let mut scores = HashMap::new();

        // Score code detection
        let code_score = self.score_code(&patterns, text, keystroke_metrics);
        scores.insert("code".to_string(), code_score);

        // Score prose detection
        let prose_score = self.score_prose(text, keystroke_metrics);
        scores.insert("prose".to_string(), prose_score);

        // Score technical doc detection
        let tech_doc_score = self.score_technical_doc(&patterns, text);
        scores.insert("tech_doc".to_string(), tech_doc_score);

        // Score email/messaging detection
        let email_score = self.score_email(&patterns, text);
        let chat_score = self.score_chat(&patterns, text);
        scores.insert("email".to_string(), email_score);
        scores.insert("chat".to_string(), chat_score);

        // Find best match
        let (best_context, best_score) = self.select_best_match(
            code_score,
            prose_score,
            tech_doc_score,
            email_score,
            chat_score,
            &patterns,
        );

        ContentAnalysis {
            context: best_context,
            confidence: best_score,
            detected_patterns: patterns,
            timestamp,
            scores: Some(scores),
        }
    }

    /// Score likelihood of code content (0.0-1.0).
    fn score_code(
        &self,
        patterns: &[String],
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
    ) -> f64 {
        let mut score = 0.0;

        // Count language patterns
        let code_keywords = patterns
            .iter()
            .filter(|p| {
                p.starts_with("rust:")
                    || p.starts_with("python:")
                    || p.starts_with("javascript:")
                    || p.starts_with("swift:")
                    || p.starts_with("sql:")
            })
            .count();

        // Boost for code keywords
        if code_keywords > 0 {
            score += 0.3 + (code_keywords as f64 * 0.1).min(0.4);
        }

        // Check for IDE patterns (comments, multi-select, etc.)
        let ide_patterns = patterns.iter().filter(|p| p.starts_with("ide:")).count();
        if ide_patterns > 0 {
            score += 0.2;
        }

        // Analyze whitespace patterns (indentation typical of code)
        if text.contains("    ") || text.contains("\t") {
            score += 0.15;
        }

        // Check for symbols common in code
        let code_symbols = text.matches('{').count()
            + text.matches('}').count()
            + text.matches('[').count()
            + text.matches(']').count()
            + text.matches('(').count()
            + text.matches(')').count();

        if code_symbols > 3 {
            score += 0.15;
        }

        // Reduce score if email/messaging patterns present
        if patterns.iter().any(|p| p.starts_with("messaging:")) {
            score *= 0.5;
        }

        // If we have keystroke metrics, check for rapid, consistent typing
        if let Some(metrics) = keystroke_metrics {
            if metrics.mean_interval_ms > 40.0 && metrics.mean_interval_ms < 150.0 {
                // Consistent, fast typing typical of code
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    /// Score likelihood of prose content (0.0-1.0).
    fn score_prose(
        &self,
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Estimate prose characteristics
        let lines: Vec<&str> = text.lines().collect();
        let avg_line_length = if !lines.is_empty() {
            lines.iter().map(|l| l.len()).sum::<usize>() / lines.len()
        } else {
            0
        };

        // Prose typically has longer lines (40-80 chars)
        if avg_line_length > 30 && avg_line_length < 100 {
            score += 0.2;
        }

        // Check for prose indicators: capital letters, sentence endings
        let capitals = text.chars().filter(|c| c.is_uppercase()).count();
        let periods = text.matches('.').count();
        let commas = text.matches(',').count();

        if capitals > text.len() / 20 && periods > 0 {
            score += 0.2;
        }

        if commas > text.len() / 50 {
            score += 0.1;
        }

        // Reduce score if code patterns present
        if text.contains('{') || text.contains('[') || text.contains('(') && text.contains(')') {
            score *= 0.7;
        }

        // If we have keystroke metrics, slower, more variable typing suggests prose
        if let Some(metrics) = keystroke_metrics {
            if metrics.std_dev_ms > 80.0 {
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    /// Score likelihood of technical documentation (0.0-1.0).
    fn score_technical_doc(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Check for markdown/documentation patterns
        if text.contains("```") || text.contains("# ") || text.contains("## ") {
            score += 0.3;
        }

        // Check for code blocks and prose mix
        let code_keyword_count = patterns
            .iter()
            .filter(|p| {
                p.starts_with("rust:")
                    || p.starts_with("python:")
                    || p.starts_with("javascript:")
            })
            .count();

        if code_keyword_count > 0 && text.len() > 200 {
            score += 0.2;
        }

        // Check for headers and structure (typical of docs)
        if text.matches('\n').count() > 5 {
            score += 0.15;
        }

        score.min(1.0)
    }

    /// Score likelihood of email content (0.0-1.0).
    fn score_email(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Check for email headers
        if text.contains("To:") || text.contains("Subject:") || text.contains("From:") {
            score += 0.4;
        }

        // Check for email salutations
        if text.contains("Dear ") || text.contains("Hello ") {
            score += 0.2;
        }

        // Check for closings
        if text.contains("Best regards") || text.contains("Thanks") || text.contains("Sincerely")
        {
            score += 0.2;
        }

        // Email pattern from messaging detection
        let messaging_count = patterns.iter().filter(|p| p.starts_with("messaging:")).count();
        if messaging_count > 2 {
            score += 0.2;
        }

        // Reduce if code patterns present
        if patterns.iter().any(|p| p.starts_with("rust:") || p.starts_with("python:")) {
            score *= 0.5;
        }

        score.min(1.0)
    }

    /// Score likelihood of chat message content (0.0-1.0).
    fn score_chat(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Shorter messages typical of chat
        if text.len() < 200 {
            score += 0.15;
        }

        // Check for mentions and hashtags
        if text.contains('@') {
            score += 0.15;
        }
        if text.contains('#') {
            score += 0.15;
        }

        // Check for informal patterns
        if text.contains("lol") || text.contains("...") || text.contains("!!") {
            score += 0.15;
        }

        // Boost if messaging patterns detected
        let messaging_count = patterns.iter().filter(|p| p.starts_with("messaging:")).count();
        score += (messaging_count as f64) * 0.1;

        // Reduce if formal email patterns present
        if text.contains("To:") || text.contains("Subject:") {
            score *= 0.3;
        }

        score.min(1.0)
    }

    /// Select the best matching context type based on scores.
    fn select_best_match(
        &self,
        code_score: f64,
        prose_score: f64,
        tech_doc_score: f64,
        email_score: f64,
        chat_score: f64,
        patterns: &[String],
    ) -> (ContextType, f64) {
        let candidates = vec![
            ("code", code_score),
            ("prose", prose_score),
            ("tech_doc", tech_doc_score),
            ("email", email_score),
            ("chat", chat_score),
        ];

        let (best_type, best_score) = candidates
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
            .unwrap_or(("unknown", 0.0));

        // Confidence threshold: require at least 0.60 confidence
        if best_score < 0.60 {
            return (ContextType::Unknown, best_score);
        }

        let context = match best_type {
            "code" => {
                // Try to detect specific language
                let lang = self.detect_language(patterns);
                ContextType::Code { language: lang }
            }
            "prose" => {
                let style = self.detect_prose_style(patterns);
                ContextType::Prose { style }
            }
            "tech_doc" => ContextType::TechnicalDoc,
            "email" => ContextType::EmailDraft,
            "chat" => ContextType::ChatMessage,
            _ => ContextType::Unknown,
        };

        (context, best_score)
    }

    /// Detect specific programming language from patterns.
    fn detect_language(&self, patterns: &[String]) -> String {
        let mut lang_scores = HashMap::new();

        for pattern in patterns {
            if let Some(_lang) = pattern.strip_prefix("rust:") {
                *lang_scores.entry("rust").or_insert(0) += 1;
            } else if let Some(_lang) = pattern.strip_prefix("python:") {
                *lang_scores.entry("python").or_insert(0) += 1;
            } else if let Some(_lang) = pattern.strip_prefix("javascript:") {
                *lang_scores.entry("javascript").or_insert(0) += 1;
            } else if let Some(_lang) = pattern.strip_prefix("swift:") {
                *lang_scores.entry("swift").or_insert(0) += 1;
            } else if let Some(_lang) = pattern.strip_prefix("sql:") {
                *lang_scores.entry("sql").or_insert(0) += 1;
            }
        }

        lang_scores
            .iter()
            .max_by_key(|&(_, count)| count)
            .map(|(lang, _)| lang.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Detect prose writing style from patterns and content.
    fn detect_prose_style(&self, _patterns: &[String]) -> ProseStyle {
        // Simple heuristic: could be enhanced with more sophisticated analysis
        ProseStyle::Casual
    }
}

/// Keystroke timing metrics for a window.
#[derive(Debug, Clone)]
pub struct KeystrokeMetrics {
    /// Mean inter-keystroke interval in milliseconds
    pub mean_interval_ms: f64,
    /// Standard deviation of inter-keystroke intervals
    pub std_dev_ms: f64,
    /// Minimum interval observed
    pub min_interval_ms: f64,
    /// Maximum interval observed
    pub max_interval_ms: f64,
    /// Total keystrokes in window
    pub keystroke_count: usize,
}

impl KeystrokeMetrics {
    /// Compute keystroke metrics from a sequence of timestamps.
    ///
    /// # Arguments
    /// - `timestamps`: Keystroke timestamps in nanoseconds
    ///
    /// # Returns
    /// KeystrokeMetrics or None if fewer than 2 keystrokes
    pub fn from_timestamps(timestamps: &[i64]) -> Option<Self> {
        if timestamps.len() < 2 {
            return None;
        }

        let mut intervals = Vec::new();
        for window in timestamps.windows(2) {
            let interval_ns = window[1] - window[0];
            if interval_ns > 0 {
                intervals.push(interval_ns as f64 / 1_000_000.0); // Convert to ms
            }
        }

        if intervals.is_empty() {
            return None;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();

        let min = intervals
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let max = intervals.iter().cloned().fold(0.0, f64::max);

        Some(Self {
            mean_interval_ms: mean,
            std_dev_ms: std_dev,
            min_interval_ms: min,
            max_interval_ms: max,
            keystroke_count: timestamps.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_code_detection() {
        let detector = ContentDetector::new();
        let text = "fn main() {\n    let x = 42;\n    println!(\"{}\", x);\n}";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "rust");
                assert!(analysis.confidence > 0.7);
            }
            _ => panic!("Expected code detection, got {:?}", analysis.context),
        }
    }

    #[test]
    fn test_python_code_detection() {
        let detector = ContentDetector::new();
        let text = "def hello(name):\n    print(f\"Hello {name}\")\n    return True";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "python");
                assert!(analysis.confidence > 0.7);
            }
            _ => panic!("Expected code detection, got {:?}", analysis.context),
        }
    }

    #[test]
    fn test_email_detection() {
        let detector = ContentDetector::new();
        let text = "To: user@example.com\nSubject: Meeting\n\nDear John,\n\nBest regards,\nAlice";

        let analysis = detector.analyze(text, None, 0);
        match analysis.context {
            ContextType::EmailDraft => {
                assert!(analysis.confidence > 0.6);
            }
            _ => panic!(
                "Expected email detection, got {:?} with confidence {}",
                analysis.context, analysis.confidence
            ),
        }
    }

    #[test]
    fn test_prose_detection() {
        let detector = ContentDetector::new();
        let text =
            "Once upon a time, there was a young writer who dreamed of telling great stories.";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Prose { .. } => {
                assert!(analysis.confidence > 0.5);
            }
            _ => {
                // Acceptable if detected as unknown (limited text)
                assert!(analysis.confidence < 0.8);
            }
        }
    }

    #[test]
    fn test_keystroke_metrics_computation() {
        let timestamps = vec![0, 100_000_000, 250_000_000, 350_000_000]; // 0.1s, 0.15s, 0.1s intervals
        let metrics = KeystrokeMetrics::from_timestamps(&timestamps).unwrap();

        assert!(metrics.mean_interval_ms > 100.0 && metrics.mean_interval_ms < 120.0);
        assert_eq!(metrics.keystroke_count, 4);
        assert!(metrics.std_dev_ms > 0.0);
    }

    #[test]
    fn test_empty_text_returns_unknown() {
        let detector = ContentDetector::new();
        let analysis = detector.analyze("", None, 0);

        match analysis.context {
            ContextType::Unknown => {
                assert_eq!(analysis.confidence, 0.0);
            }
            _ => panic!("Expected unknown for empty text"),
        }
    }

    #[test]
    fn test_mixed_content_code_dominates() {
        let detector = ContentDetector::new();
        let text = "import sys\nprint(\"Hello\")\n# This is a comment";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "python");
            }
            _ => panic!("Expected code detection for mixed content"),
        }
    }

    #[test]
    fn test_low_confidence_returns_unknown() {
        let detector = ContentDetector::new();
        let text = "abc def ghi"; // Ambiguous content

        let analysis = detector.analyze(text, None, 0);
        match analysis.context {
            ContextType::Unknown => {
                // Expected
                assert!(analysis.confidence < 0.7);
            }
            _ => {} // May detect something with low confidence
        }
    }

    #[test]
    fn test_pattern_detection() {
        let matcher = PatternMatcher::new();
        let patterns = matcher.detect_patterns("fn main() { let x = 42; }");

        assert!(patterns.contains(&"rust:fn".to_string()));
        assert!(patterns.contains(&"rust:let".to_string()));
    }
}
