// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::Utc;
use wld_protocol::crypto::PoPSigner;

use crate::error::Error;

use super::types::{
    AIExtent, AIPurpose, AIToolUsage, Collaborator, CollaboratorRole, Declaration,
    DeclarationJitter, InputModality, ModalityType,
};

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
                jitter_sealed: None,
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

    /// Attach jitter evidence collected during interactive declaration typing.
    pub fn with_jitter_seal(mut self, jitter: DeclarationJitter) -> Self {
        self.decl.jitter_sealed = Some(jitter);
        self
    }

    pub fn sign(mut self, signer: &dyn PoPSigner) -> crate::error::Result<Declaration> {
        if let Some(err) = self.err.take() {
            return Err(Error::validation(err));
        }

        self.validate()?;

        self.decl.author_public_key = signer.public_key();

        let payload = self.decl.signing_payload();
        let signature = signer
            .sign(&payload)
            .map_err(|e| Error::crypto(format!("signing failed: {e}")))?;

        self.decl.signature = signature;
        Ok(self.decl)
    }

    fn validate(&self) -> crate::error::Result<()> {
        if self.decl.document_hash == [0u8; 32] {
            return Err(Error::validation("document hash is required"));
        }
        if self.decl.chain_hash == [0u8; 32] {
            return Err(Error::validation("chain hash is required"));
        }
        if self.decl.title.is_empty() {
            return Err(Error::validation("title is required"));
        }
        if self.decl.input_modalities.is_empty() {
            return Err(Error::validation("at least one input modality is required"));
        }
        if self.decl.statement.is_empty() {
            return Err(Error::validation("statement is required"));
        }

        let mut total = 0.0;
        for modality in &self.decl.input_modalities {
            if modality.percentage < 0.0 || modality.percentage > 100.0 {
                return Err(Error::validation("modality percentage must be 0-100"));
            }
            total += modality.percentage;
        }
        if !(95.0..=105.0).contains(&total) {
            return Err(Error::validation(format!(
                "modality percentages sum to {:.1}%, expected ~100%",
                total
            )));
        }

        Ok(())
    }
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
