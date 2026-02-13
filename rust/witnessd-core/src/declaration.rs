use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declaration {
    pub document_hash: [u8; 32],
    pub chain_hash: [u8; 32],
    pub title: String,
    pub input_modalities: Vec<InputModality>,
    pub ai_tools: Vec<AIToolUsage>,
    pub collaborators: Vec<Collaborator>,
    pub statement: String,
    pub created_at: DateTime<Utc>,
    pub version: u64,
    pub author_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputModality {
    #[serde(rename = "type")]
    pub modality_type: ModalityType,
    pub percentage: f64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModalityType {
    Keyboard,
    Dictation,
    Handwriting,
    Paste,
    Import,
    Mixed,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIToolUsage {
    pub tool: String,
    pub version: Option<String>,
    pub purpose: AIPurpose,
    pub interaction: Option<String>,
    pub extent: AIExtent,
    pub sections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AIPurpose {
    Ideation,
    Outline,
    Drafting,
    Feedback,
    Editing,
    Research,
    Formatting,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AIExtent {
    None,
    Minimal,
    Moderate,
    Substantial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    pub name: String,
    pub role: CollaboratorRole,
    pub sections: Vec<String>,
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollaboratorRole {
    #[serde(rename = "co-author")]
    CoAuthor,
    #[serde(rename = "editor")]
    Editor,
    #[serde(rename = "research_assistant")]
    ResearchAssistant,
    #[serde(rename = "reviewer")]
    Reviewer,
    #[serde(rename = "transcriber")]
    Transcriber,
    #[serde(rename = "other")]
    Other,
}

pub struct Builder {
    decl: Declaration,
    err: Option<String>,
}

impl Builder {
    pub fn new(document_hash: [u8; 32], chain_hash: [u8; 32], title: impl Into<String>) -> Self {
        Self {
            decl: Declaration {
                document_hash,
                chain_hash,
                title: title.into(),
                input_modalities: Vec::new(),
                ai_tools: Vec::new(),
                collaborators: Vec::new(),
                statement: String::new(),
                created_at: Utc::now(),
                version: 1,
                author_public_key: Vec::new(),
                signature: Vec::new(),
            },
            err: None,
        }
    }

    pub fn add_modality(
        mut self,
        modality_type: ModalityType,
        percentage: f64,
        note: Option<String>,
    ) -> Self {
        self.decl.input_modalities.push(InputModality {
            modality_type,
            percentage,
            note,
        });
        self
    }

    pub fn add_ai_tool(
        mut self,
        tool: impl Into<String>,
        version: Option<String>,
        purpose: AIPurpose,
        interaction: Option<String>,
        extent: AIExtent,
    ) -> Self {
        self.decl.ai_tools.push(AIToolUsage {
            tool: tool.into(),
            version,
            purpose,
            interaction,
            extent,
            sections: Vec::new(),
        });
        self
    }

    pub fn add_collaborator(
        mut self,
        name: impl Into<String>,
        role: CollaboratorRole,
        sections: Vec<String>,
    ) -> Self {
        self.decl.collaborators.push(Collaborator {
            name: name.into(),
            role,
            sections,
            public_key: None,
        });
        self
    }

    pub fn with_statement(mut self, statement: impl Into<String>) -> Self {
        self.decl.statement = statement.into();
        self
    }

    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Declaration, String> {
        if let Some(err) = self.err.take() {
            return Err(err);
        }

        self.validate()?;
        self.decl.author_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = self.decl.signing_payload();
        let signature = signing_key.sign(&payload);
        self.decl.signature = signature.to_bytes().to_vec();
        Ok(self.decl)
    }

    fn validate(&self) -> Result<(), String> {
        if self.decl.document_hash == [0u8; 32] {
            return Err("document hash is required".to_string());
        }
        if self.decl.chain_hash == [0u8; 32] {
            return Err("chain hash is required".to_string());
        }
        if self.decl.title.is_empty() {
            return Err("title is required".to_string());
        }
        if self.decl.input_modalities.is_empty() {
            return Err("at least one input modality is required".to_string());
        }
        if self.decl.statement.is_empty() {
            return Err("statement is required".to_string());
        }

        let mut total = 0.0;
        for modality in &self.decl.input_modalities {
            if modality.percentage < 0.0 || modality.percentage > 100.0 {
                return Err("modality percentage must be 0-100".to_string());
            }
            total += modality.percentage;
        }
        if !(95.0..=105.0).contains(&total) {
            return Err(format!(
                "modality percentages sum to {:.1}%, expected ~100%",
                total
            ));
        }

        Ok(())
    }
}

impl Declaration {
    pub fn verify(&self) -> bool {
        if self.author_public_key.len() != 32 || self.signature.len() != 64 {
            return false;
        }

        let pubkey_bytes: [u8; 32] = match self.author_public_key.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_payload(), &signature)
            .is_ok()
    }

    pub fn has_ai_usage(&self) -> bool {
        !self.ai_tools.is_empty()
    }

    pub fn max_ai_extent(&self) -> AIExtent {
        let mut max = AIExtent::None;
        for tool in &self.ai_tools {
            if extent_rank(&tool.extent) > extent_rank(&max) {
                max = tool.extent.clone();
            }
        }
        max
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Declaration, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    pub fn summary(&self) -> DeclarationSummary {
        let mut tools = Vec::new();
        for tool in &self.ai_tools {
            tools.push(tool.tool.clone());
        }

        DeclarationSummary {
            title: self.title.clone(),
            ai_usage: self.has_ai_usage(),
            ai_tools: tools,
            max_ai_extent: format!("{:?}", self.max_ai_extent()).to_lowercase(),
            collaborators: self.collaborators.len(),
            signature_valid: self.verify(),
        }
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-declaration-v2");
        hasher.update(self.document_hash);
        hasher.update(self.chain_hash);
        hasher.update(self.title.as_bytes());

        hasher.update((self.input_modalities.len() as u64).to_be_bytes());
        for modality in &self.input_modalities {
            hasher.update(modality_type_str(&modality.modality_type).as_bytes());
            let fixed = (modality.percentage * 1000.0) as u64;
            hasher.update(fixed.to_be_bytes());
            hasher.update(modality.note.as_deref().unwrap_or("").as_bytes());
        }

        hasher.update((self.ai_tools.len() as u64).to_be_bytes());
        for tool in &self.ai_tools {
            hasher.update(tool.tool.as_bytes());
            if let Some(version) = &tool.version {
                hasher.update(version.as_bytes());
            }
            hasher.update(ai_purpose_str(&tool.purpose).as_bytes());
            if let Some(interaction) = &tool.interaction {
                hasher.update(interaction.as_bytes());
            }
            hasher.update(ai_extent_str(&tool.extent).as_bytes());
            hasher.update((tool.sections.len() as u64).to_be_bytes());
            for section in &tool.sections {
                hasher.update(section.as_bytes());
            }
        }

        hasher.update((self.collaborators.len() as u64).to_be_bytes());
        for collaborator in &self.collaborators {
            hasher.update(collaborator.name.as_bytes());
            hasher.update(collaborator_role_str(&collaborator.role).as_bytes());
            hasher.update((collaborator.sections.len() as u64).to_be_bytes());
            for section in &collaborator.sections {
                hasher.update(section.as_bytes());
            }
            if let Some(key) = &collaborator.public_key {
                hasher.update(key);
            }
        }

        hasher.update(self.statement.as_bytes());
        hasher.update(
            self.created_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_be_bytes(),
        );
        hasher.update(self.version.to_be_bytes());
        hasher.update(&self.author_public_key);

        hasher.finalize().to_vec()
    }
}

fn extent_rank(extent: &AIExtent) -> i32 {
    match extent {
        AIExtent::None => 0,
        AIExtent::Minimal => 1,
        AIExtent::Moderate => 2,
        AIExtent::Substantial => 3,
    }
}

fn modality_type_str(modality: &ModalityType) -> &'static str {
    match modality {
        ModalityType::Keyboard => "keyboard",
        ModalityType::Dictation => "dictation",
        ModalityType::Handwriting => "handwriting",
        ModalityType::Paste => "paste",
        ModalityType::Import => "import",
        ModalityType::Mixed => "mixed",
        ModalityType::Other => "other",
    }
}

fn ai_purpose_str(purpose: &AIPurpose) -> &'static str {
    match purpose {
        AIPurpose::Ideation => "ideation",
        AIPurpose::Outline => "outline",
        AIPurpose::Drafting => "drafting",
        AIPurpose::Feedback => "feedback",
        AIPurpose::Editing => "editing",
        AIPurpose::Research => "research",
        AIPurpose::Formatting => "formatting",
        AIPurpose::Other => "other",
    }
}

fn ai_extent_str(extent: &AIExtent) -> &'static str {
    match extent {
        AIExtent::None => "none",
        AIExtent::Minimal => "minimal",
        AIExtent::Moderate => "moderate",
        AIExtent::Substantial => "substantial",
    }
}

fn collaborator_role_str(role: &CollaboratorRole) -> &'static str {
    match role {
        CollaboratorRole::CoAuthor => "co-author",
        CollaboratorRole::Editor => "editor",
        CollaboratorRole::ResearchAssistant => "research_assistant",
        CollaboratorRole::Reviewer => "reviewer",
        CollaboratorRole::Transcriber => "transcriber",
        CollaboratorRole::Other => "other",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationSummary {
    pub title: String,
    pub ai_usage: bool,
    pub ai_tools: Vec<String>,
    pub max_ai_extent: String,
    pub collaborators: usize,
    pub signature_valid: bool,
}

pub fn no_ai_declaration(
    document_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: impl Into<String>,
    statement: impl Into<String>,
) -> Builder {
    Builder::new(document_hash, chain_hash, title)
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .with_statement(statement)
}

pub fn ai_assisted_declaration(
    document_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: impl Into<String>,
) -> Builder {
    Builder::new(document_hash, chain_hash, title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn test_no_ai_declaration_creation_and_signing() {
        let doc_hash = [1u8; 32];
        let chain_hash = [2u8; 32];
        let signing_key = test_signing_key();

        let decl = no_ai_declaration(
            doc_hash,
            chain_hash,
            "Test Document",
            "I wrote this myself.",
        )
        .sign(&signing_key)
        .expect("sign declaration");

        assert_eq!(decl.title, "Test Document");
        assert_eq!(decl.statement, "I wrote this myself.");
        assert_eq!(decl.document_hash, doc_hash);
        assert_eq!(decl.chain_hash, chain_hash);
        assert!(!decl.has_ai_usage());
        assert_eq!(decl.max_ai_extent(), AIExtent::None);
    }

    #[test]
    fn test_declaration_verification() {
        let signing_key = test_signing_key();
        let decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        assert!(decl.verify());
    }

    #[test]
    fn test_declaration_verification_fails_with_tampered_signature() {
        let signing_key = test_signing_key();
        let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        // Tamper with signature
        decl.signature[0] ^= 0xFF;

        assert!(!decl.verify());
    }

    #[test]
    fn test_declaration_verification_fails_with_tampered_title() {
        let signing_key = test_signing_key();
        let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        // Tamper with title
        decl.title = "Tampered Title".to_string();

        assert!(!decl.verify());
    }

    #[test]
    fn test_declaration_verification_fails_with_tampered_statement() {
        let signing_key = test_signing_key();
        let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        // Tamper with statement
        decl.statement = "Tampered Statement".to_string();

        assert!(!decl.verify());
    }

    #[test]
    fn test_ai_assisted_declaration_with_tool() {
        let signing_key = test_signing_key();
        let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "AI Assisted Doc")
            .add_modality(ModalityType::Keyboard, 80.0, None)
            .add_modality(ModalityType::Paste, 20.0, Some("code snippets".to_string()))
            .add_ai_tool(
                "ChatGPT",
                Some("4.0".to_string()),
                AIPurpose::Feedback,
                Some("Asked for suggestions".to_string()),
                AIExtent::Moderate,
            )
            .with_statement("I used AI for feedback but wrote the content myself.")
            .sign(&signing_key)
            .expect("sign");

        assert!(decl.has_ai_usage());
        assert_eq!(decl.max_ai_extent(), AIExtent::Moderate);
        assert_eq!(decl.ai_tools.len(), 1);
        assert_eq!(decl.ai_tools[0].tool, "ChatGPT");
    }

    #[test]
    fn test_declaration_requires_document_hash() {
        let signing_key = test_signing_key();
        let err = Builder::new([0u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();

        assert!(err.contains("document hash is required"));
    }

    #[test]
    fn test_declaration_requires_chain_hash() {
        let signing_key = test_signing_key();
        let err = Builder::new([1u8; 32], [0u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();

        assert!(err.contains("chain hash is required"));
    }

    #[test]
    fn test_declaration_requires_title() {
        let signing_key = test_signing_key();
        let err = Builder::new([1u8; 32], [2u8; 32], "")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();

        assert!(err.contains("title is required"));
    }

    #[test]
    fn test_declaration_requires_modality() {
        let signing_key = test_signing_key();
        let err = Builder::new([1u8; 32], [2u8; 32], "Test")
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();

        assert!(err.contains("at least one input modality is required"));
    }

    #[test]
    fn test_declaration_requires_statement() {
        let signing_key = test_signing_key();
        let err = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .sign(&signing_key)
            .unwrap_err();

        assert!(err.contains("statement is required"));
    }

    #[test]
    fn test_modality_percentages_must_sum_to_100() {
        let signing_key = test_signing_key();

        // Too low
        let err = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 50.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();
        assert!(err.contains("percentages sum to"));

        // Too high
        let err = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 150.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();
        assert!(err.contains("modality percentage must be 0-100"));
    }

    #[test]
    fn test_modality_percentage_validation() {
        let signing_key = test_signing_key();

        // Negative percentage
        let err = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, -10.0, None)
            .with_statement("Statement")
            .sign(&signing_key)
            .unwrap_err();
        assert!(err.contains("modality percentage must be 0-100"));
    }

    #[test]
    fn test_multiple_modalities() {
        let signing_key = test_signing_key();
        let decl = Builder::new([1u8; 32], [2u8; 32], "Mixed Input")
            .add_modality(ModalityType::Keyboard, 60.0, None)
            .add_modality(
                ModalityType::Dictation,
                30.0,
                Some("voice notes".to_string()),
            )
            .add_modality(ModalityType::Paste, 10.0, None)
            .with_statement("I used multiple input methods.")
            .sign(&signing_key)
            .expect("sign");

        assert_eq!(decl.input_modalities.len(), 3);
        assert!(decl.verify());
    }

    #[test]
    fn test_multiple_ai_tools() {
        let signing_key = test_signing_key();
        let decl = Builder::new([1u8; 32], [2u8; 32], "Multi AI")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool(
                "ChatGPT",
                None,
                AIPurpose::Ideation,
                None,
                AIExtent::Minimal,
            )
            .add_ai_tool(
                "Grammarly",
                None,
                AIPurpose::Editing,
                None,
                AIExtent::Substantial,
            )
            .with_statement("I used multiple AI tools.")
            .sign(&signing_key)
            .expect("sign");

        assert_eq!(decl.ai_tools.len(), 2);
        assert_eq!(decl.max_ai_extent(), AIExtent::Substantial);
    }

    #[test]
    fn test_collaborator_addition() {
        let signing_key = test_signing_key();
        let decl = Builder::new([1u8; 32], [2u8; 32], "Collaborative")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_collaborator(
                "Alice",
                CollaboratorRole::CoAuthor,
                vec!["Chapter 1".to_string()],
            )
            .add_collaborator("Bob", CollaboratorRole::Editor, vec![])
            .with_statement("We wrote this together.")
            .sign(&signing_key)
            .expect("sign");

        assert_eq!(decl.collaborators.len(), 2);
        assert_eq!(decl.collaborators[0].name, "Alice");
    }

    #[test]
    fn test_declaration_encode_decode_roundtrip() {
        let signing_key = test_signing_key();
        let original = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        let encoded = original.encode().expect("encode");
        let decoded = Declaration::decode(&encoded).expect("decode");

        assert_eq!(decoded.title, original.title);
        assert_eq!(decoded.statement, original.statement);
        assert_eq!(decoded.document_hash, original.document_hash);
        assert_eq!(decoded.chain_hash, original.chain_hash);
        assert_eq!(decoded.signature, original.signature);
        assert!(decoded.verify());
    }

    #[test]
    fn test_declaration_summary() {
        let signing_key = test_signing_key();
        let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Summary Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool(
                "Claude",
                None,
                AIPurpose::Research,
                None,
                AIExtent::Moderate,
            )
            .add_collaborator("Alice", CollaboratorRole::Reviewer, vec![])
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign");

        let summary = decl.summary();
        assert_eq!(summary.title, "Summary Test");
        assert!(summary.ai_usage);
        assert_eq!(summary.ai_tools, vec!["Claude"]);
        assert_eq!(summary.max_ai_extent, "moderate");
        assert_eq!(summary.collaborators, 1);
        assert!(summary.signature_valid);
    }

    #[test]
    fn test_invalid_public_key_length() {
        let signing_key = test_signing_key();
        let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        // Set invalid public key length
        decl.author_public_key = vec![0u8; 16]; // Should be 32

        assert!(!decl.verify());
    }

    #[test]
    fn test_invalid_signature_length() {
        let signing_key = test_signing_key();
        let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
            .sign(&signing_key)
            .expect("sign");

        // Set invalid signature length
        decl.signature = vec![0u8; 32]; // Should be 64

        assert!(!decl.verify());
    }

    #[test]
    fn test_all_modality_types() {
        let signing_key = test_signing_key();

        for (modality, name) in [
            (ModalityType::Keyboard, "keyboard"),
            (ModalityType::Dictation, "dictation"),
            (ModalityType::Handwriting, "handwriting"),
            (ModalityType::Paste, "paste"),
            (ModalityType::Import, "import"),
            (ModalityType::Mixed, "mixed"),
            (ModalityType::Other, "other"),
        ] {
            let decl = Builder::new([1u8; 32], [2u8; 32], format!("Test {name}"))
                .add_modality(modality, 100.0, None)
                .with_statement("Test")
                .sign(&signing_key)
                .expect("sign");
            assert!(decl.verify());
        }
    }

    #[test]
    fn test_all_ai_purposes() {
        let signing_key = test_signing_key();

        for purpose in [
            AIPurpose::Ideation,
            AIPurpose::Outline,
            AIPurpose::Drafting,
            AIPurpose::Feedback,
            AIPurpose::Editing,
            AIPurpose::Research,
            AIPurpose::Formatting,
            AIPurpose::Other,
        ] {
            let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Test")
                .add_modality(ModalityType::Keyboard, 100.0, None)
                .add_ai_tool("Tool", None, purpose, None, AIExtent::Minimal)
                .with_statement("Test")
                .sign(&signing_key)
                .expect("sign");
            assert!(decl.verify());
        }
    }

    #[test]
    fn test_all_ai_extents() {
        let signing_key = test_signing_key();

        for (extent, expected_rank) in [
            (AIExtent::None, 0),
            (AIExtent::Minimal, 1),
            (AIExtent::Moderate, 2),
            (AIExtent::Substantial, 3),
        ] {
            let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Test")
                .add_modality(ModalityType::Keyboard, 100.0, None)
                .add_ai_tool("Tool", None, AIPurpose::Other, None, extent)
                .with_statement("Test")
                .sign(&signing_key)
                .expect("sign");
            assert_eq!(extent_rank(&decl.max_ai_extent()), expected_rank);
        }
    }

    #[test]
    fn test_all_collaborator_roles() {
        let signing_key = test_signing_key();

        for role in [
            CollaboratorRole::CoAuthor,
            CollaboratorRole::Editor,
            CollaboratorRole::ResearchAssistant,
            CollaboratorRole::Reviewer,
            CollaboratorRole::Transcriber,
            CollaboratorRole::Other,
        ] {
            let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
                .add_modality(ModalityType::Keyboard, 100.0, None)
                .add_collaborator("Person", role, vec![])
                .with_statement("Test")
                .sign(&signing_key)
                .expect("sign");
            assert!(decl.verify());
        }
    }

    #[test]
    fn test_modalities_near_100_percent() {
        let signing_key = test_signing_key();

        // Test at 95% (valid)
        let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 95.0, None)
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign at 95%");
        assert!(decl.verify());

        // Test at 100% (maximum allowed)
        let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign at 100%");
        assert!(decl.verify());

        // Test at 105% (should fail - over 100%)
        let result = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 105.0, None)
            .with_statement("Test")
            .sign(&signing_key);
        assert!(result.is_err(), "Expected error for 105%, got success");
    }
}
