use serde::{Deserialize, Serialize};

use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectIdentityProfile {
    pub client_id: String,
    pub encryption_identity_key_b64: String,
    pub signing_identity_key_b64: String,
    pub created_at: String,
}

impl DirectIdentityProfile {
    pub fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct identity profile is missing client_id".to_string(),
            ));
        }

        if self.encryption_identity_key_b64.trim().is_empty()
            || self.signing_identity_key_b64.trim().is_empty()
        {
            return Err(ClientCoreError::State(
                "direct identity profile is missing public identity keys".to_string(),
            ));
        }

        if self.created_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct identity profile is missing creation timestamp".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPrekey {
    pub key_id: u32,
    pub public_key_b64: String,
    pub signature_b64: String,
    pub created_at: String,
    pub expires_at: String,
}

impl SignedPrekey {
    pub fn validate(&self) -> Result<()> {
        if self.key_id == 0 {
            return Err(ClientCoreError::State(
                "signed prekey key_id must be non-zero".to_string(),
            ));
        }

        if self.public_key_b64.trim().is_empty() || self.signature_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "signed prekey is missing public key or signature".to_string(),
            ));
        }

        if self.created_at.trim().is_empty() || self.expires_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "signed prekey is missing timestamps".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalSignedPrekey {
    pub key_id: u32,
    pub public_key_b64: String,
    pub private_key_b64: String,
    pub signature_b64: String,
    pub created_at: String,
    pub expires_at: String,
}

impl LocalSignedPrekey {
    pub fn validate(&self) -> Result<()> {
        if self.key_id == 0 {
            return Err(ClientCoreError::State(
                "local signed prekey key_id must be non-zero".to_string(),
            ));
        }

        if self.public_key_b64.trim().is_empty()
            || self.private_key_b64.trim().is_empty()
            || self.signature_b64.trim().is_empty()
        {
            return Err(ClientCoreError::State(
                "local signed prekey is missing key material or signature".to_string(),
            ));
        }

        if self.created_at.trim().is_empty() || self.expires_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "local signed prekey is missing timestamps".to_string(),
            ));
        }

        Ok(())
    }

    pub fn public_summary(&self) -> SignedPrekey {
        SignedPrekey {
            key_id: self.key_id,
            public_key_b64: self.public_key_b64.clone(),
            signature_b64: self.signature_b64.clone(),
            created_at: self.created_at.clone(),
            expires_at: self.expires_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OneTimePrekey {
    pub key_id: u32,
    pub public_key_b64: String,
    pub created_at: String,
}

impl OneTimePrekey {
    pub fn validate(&self) -> Result<()> {
        if self.key_id == 0 {
            return Err(ClientCoreError::State(
                "one-time prekey key_id must be non-zero".to_string(),
            ));
        }

        if self.public_key_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "one-time prekey is missing public key".to_string(),
            ));
        }

        if self.created_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "one-time prekey is missing creation timestamp".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalOneTimePrekey {
    pub key_id: u32,
    pub public_key_b64: String,
    pub private_key_b64: String,
    pub created_at: String,
}

impl LocalOneTimePrekey {
    pub fn validate(&self) -> Result<()> {
        if self.key_id == 0 {
            return Err(ClientCoreError::State(
                "local one-time prekey key_id must be non-zero".to_string(),
            ));
        }

        if self.public_key_b64.trim().is_empty() || self.private_key_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "local one-time prekey is missing key material".to_string(),
            ));
        }

        if self.created_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "local one-time prekey is missing creation timestamp".to_string(),
            ));
        }

        Ok(())
    }

    pub fn public_summary(&self) -> OneTimePrekey {
        OneTimePrekey {
            key_id: self.key_id,
            public_key_b64: self.public_key_b64.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsedOneTimePrekey {
    pub peer_client_id: String,
    pub key_id: u32,
    pub consumed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalBootstrapMaterial {
    pub profile: DirectIdentityProfile,
    pub encryption_identity_private_key_b64: String,
    pub signing_identity_private_key_b64: String,
    pub signed_prekey: LocalSignedPrekey,
    pub one_time_prekeys: Vec<LocalOneTimePrekey>,
    pub pq_prekey_public_b64: Option<String>,
    pub pq_prekey_private_b64: Option<String>,
    pub bundle_signature_b64: String,
    pub published_at: String,
}

impl LocalBootstrapMaterial {
    pub fn validate(&self) -> Result<()> {
        self.profile.validate()?;

        if self.encryption_identity_private_key_b64.trim().is_empty()
            || self.signing_identity_private_key_b64.trim().is_empty()
        {
            return Err(ClientCoreError::State(
                "local bootstrap material is missing identity private keys".to_string(),
            ));
        }

        self.signed_prekey.validate()?;

        for prekey in &self.one_time_prekeys {
            prekey.validate()?;
        }

        if self.bundle_signature_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "local bootstrap material is missing bundle signature".to_string(),
            ));
        }

        if self.published_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "local bootstrap material is missing published_at".to_string(),
            ));
        }

        match (
            self.pq_prekey_public_b64.as_deref(),
            self.pq_prekey_private_b64.as_deref(),
        ) {
            (Some(public_key), Some(private_key))
                if !public_key.trim().is_empty() && !private_key.trim().is_empty() => {}
            (None, None) => {}
            _ => {
                return Err(ClientCoreError::State(
                    "local bootstrap material must store both PQ public and private key or neither"
                        .to_string(),
                ))
            }
        }

        Ok(())
    }

    pub fn public_bundle(&self) -> Result<PeerPrekeyBundle> {
        self.validate()?;
        Ok(PeerPrekeyBundle {
            client_id: self.profile.client_id.clone(),
            signing_identity_key_b64: self.profile.signing_identity_key_b64.clone(),
            encryption_identity_key_b64: self.profile.encryption_identity_key_b64.clone(),
            signed_prekey: self.signed_prekey.public_summary(),
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(LocalOneTimePrekey::public_summary)
                .collect(),
            pq_prekey_b64: self.pq_prekey_public_b64.clone(),
            bundle_signature_b64: self.bundle_signature_b64.clone(),
            published_at: self.published_at.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqxdhInitPayload {
    pub protocol: String,
    pub sender_client_id: String,
    pub receiver_client_id: String,
    pub sender_encryption_identity_key_b64: String,
    pub sender_signing_identity_key_b64: String,
    pub receiver_signed_prekey_id: u32,
    pub receiver_one_time_prekey_id: Option<u32>,
    pub receiver_pq_prekey_present: bool,
}

impl PqxdhInitPayload {
    pub fn validate(&self) -> Result<()> {
        if self.protocol.trim().is_empty() {
            return Err(ClientCoreError::State(
                "PQXDH init payload is missing protocol identifier".to_string(),
            ));
        }

        if self.sender_client_id.trim().is_empty() || self.receiver_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "PQXDH init payload is missing sender or receiver id".to_string(),
            ));
        }

        if self.sender_encryption_identity_key_b64.trim().is_empty()
            || self.sender_signing_identity_key_b64.trim().is_empty()
        {
            return Err(ClientCoreError::State(
                "PQXDH init payload is missing sender identity keys".to_string(),
            ));
        }

        if self.receiver_signed_prekey_id == 0 {
            return Err(ClientCoreError::State(
                "PQXDH init payload is missing receiver signed prekey id".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqxdhInitAckPayload {
    pub protocol: String,
    pub sender_client_id: String,
    pub receiver_client_id: String,
    pub session_id: String,
}

impl PqxdhInitAckPayload {
    pub fn validate(&self) -> Result<()> {
        if self.protocol.trim().is_empty() {
            return Err(ClientCoreError::State(
                "PQXDH init ack payload is missing protocol identifier".to_string(),
            ));
        }

        if self.sender_client_id.trim().is_empty() || self.receiver_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "PQXDH init ack payload is missing sender or receiver id".to_string(),
            ));
        }

        if self.session_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "PQXDH init ack payload is missing session id".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectBootstrapMessage {
    PqxdhInit(PqxdhInitPayload),
    PqxdhInitAck(PqxdhInitAckPayload),
}

impl DirectBootstrapMessage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::PqxdhInit(payload) => payload.validate(),
            Self::PqxdhInitAck(payload) => payload.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerPrekeyBundle {
    pub client_id: String,
    pub signing_identity_key_b64: String,
    pub encryption_identity_key_b64: String,
    pub signed_prekey: SignedPrekey,
    pub one_time_prekeys: Vec<OneTimePrekey>,
    pub pq_prekey_b64: Option<String>,
    pub bundle_signature_b64: String,
    pub published_at: String,
}

impl PeerPrekeyBundle {
    pub fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "peer prekey bundle is missing client_id".to_string(),
            ));
        }

        if self.signing_identity_key_b64.trim().is_empty()
            || self.encryption_identity_key_b64.trim().is_empty()
        {
            return Err(ClientCoreError::State(
                "peer prekey bundle is missing identity keys".to_string(),
            ));
        }

        if self.bundle_signature_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "peer prekey bundle is missing bundle signature".to_string(),
            ));
        }

        if self.published_at.trim().is_empty() {
            return Err(ClientCoreError::State(
                "peer prekey bundle is missing published_at".to_string(),
            ));
        }

        self.signed_prekey.validate()?;
        for prekey in &self.one_time_prekeys {
            prekey.validate()?;
        }

        Ok(())
    }

    pub fn reserve_one_time_prekey(&mut self) -> Result<Option<OneTimePrekey>> {
        self.validate()?;
        if self.one_time_prekeys.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.one_time_prekeys.remove(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirectBootstrapMessage, LocalBootstrapMaterial, LocalOneTimePrekey, LocalSignedPrekey,
        OneTimePrekey, PeerPrekeyBundle, PqxdhInitAckPayload, PqxdhInitPayload, SignedPrekey,
    };

    fn sample_bundle() -> PeerPrekeyBundle {
        PeerPrekeyBundle {
            client_id: "peer-b".to_string(),
            signing_identity_key_b64: "signing".to_string(),
            encryption_identity_key_b64: "identity".to_string(),
            signed_prekey: SignedPrekey {
                key_id: 1,
                public_key_b64: "signed-prekey".to_string(),
                signature_b64: "sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![
                OneTimePrekey {
                    key_id: 11,
                    public_key_b64: "otp-1".to_string(),
                    created_at: "2026-03-25T00:00:00Z".to_string(),
                },
                OneTimePrekey {
                    key_id: 12,
                    public_key_b64: "otp-2".to_string(),
                    created_at: "2026-03-25T00:00:01Z".to_string(),
                },
            ],
            pq_prekey_b64: Some("ml-kem-placeholder".to_string()),
            bundle_signature_b64: "bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn reserve_one_time_prekey_removes_first_available_key() {
        let mut bundle = sample_bundle();
        let first = bundle
            .reserve_one_time_prekey()
            .expect("reserve should succeed")
            .expect("first prekey should exist");
        let second = bundle
            .reserve_one_time_prekey()
            .expect("reserve should succeed")
            .expect("second prekey should exist");

        assert_eq!(first.key_id, 11);
        assert_eq!(second.key_id, 12);
        assert!(bundle
            .reserve_one_time_prekey()
            .expect("reserve should succeed")
            .is_none());
    }

    #[test]
    fn pqxdh_init_payload_validates() {
        let message = DirectBootstrapMessage::PqxdhInit(PqxdhInitPayload {
            protocol: "PQXDH/1".to_string(),
            sender_client_id: "peer-a".to_string(),
            receiver_client_id: "peer-b".to_string(),
            sender_encryption_identity_key_b64: "enc-id".to_string(),
            sender_signing_identity_key_b64: "sig-id".to_string(),
            receiver_signed_prekey_id: 7,
            receiver_one_time_prekey_id: Some(9),
            receiver_pq_prekey_present: true,
        });

        assert!(message.validate().is_ok());
    }

    #[test]
    fn pqxdh_init_ack_payload_validates() {
        let message = DirectBootstrapMessage::PqxdhInitAck(PqxdhInitAckPayload {
            protocol: "PQXDH/1".to_string(),
            sender_client_id: "peer-b".to_string(),
            receiver_client_id: "peer-a".to_string(),
            session_id: "pqxdh::lobby::peer-a::peer-b".to_string(),
        });

        assert!(message.validate().is_ok());
    }

    #[test]
    fn local_bootstrap_material_builds_public_bundle() {
        let material = LocalBootstrapMaterial {
            profile: super::DirectIdentityProfile {
                client_id: "peer-b".to_string(),
                encryption_identity_key_b64: "identity".to_string(),
                signing_identity_key_b64: "signing".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
            },
            encryption_identity_private_key_b64: "identity-private".to_string(),
            signing_identity_private_key_b64: "signing-private".to_string(),
            signed_prekey: LocalSignedPrekey {
                key_id: 3,
                public_key_b64: "signed-public".to_string(),
                private_key_b64: "signed-private".to_string(),
                signature_b64: "sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![LocalOneTimePrekey {
                key_id: 4,
                public_key_b64: "otp-public".to_string(),
                private_key_b64: "otp-private".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
            }],
            pq_prekey_public_b64: Some("pq-public".to_string()),
            pq_prekey_private_b64: Some("pq-private".to_string()),
            bundle_signature_b64: "bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        };

        let bundle = material
            .public_bundle()
            .expect("public bundle should build from valid material");

        assert_eq!(bundle.client_id, "peer-b");
        assert_eq!(bundle.signed_prekey.key_id, 3);
        assert_eq!(bundle.one_time_prekeys.len(), 1);
        assert_eq!(bundle.pq_prekey_b64.as_deref(), Some("pq-public"));
    }
}
