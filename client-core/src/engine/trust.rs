use serde::{Deserialize, Serialize};

use crate::httpq::{
    verify_server_proof, ClientHello, RelayPin, ServerHello, ServerProof, VerifiedRelay,
};
use crate::kt::{
    verify_consistency_proof, verify_inclusion_proof, verify_witness_checkpoint,
    ConsistencyProof, InclusionProof, VerifiedTreeHead, WitnessCheckpoint,
};
use crate::storage::{SecretStore, StoredRelayPin};
use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustVerificationRequest {
    pub client: ClientHello,
    pub hello: ServerHello,
    pub proof: ServerProof,
    pub inclusion: InclusionProof,
    pub consistency: Option<ConsistencyProof>,
    pub witness_checkpoint: Option<WitnessCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustVerificationResult {
    pub client_id: String,
    pub relay: VerifiedRelay,
    pub tree_head: VerifiedTreeHead,
    pub pinned_now: bool,
    pub checkpoint_recorded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableTrustVerificationResult {
    pub client_id: String,
    pub verified: bool,
    pub relay_id: String,
    pub realm: String,
    pub kt_log_url: String,
    pub witness_url: String,
    pub tree_size: u64,
    pub root_hash_b64: String,
    pub pinned_now: bool,
    pub checkpoint_recorded: bool,
}

impl From<TrustVerificationResult> for PortableTrustVerificationResult {
    fn from(value: TrustVerificationResult) -> Self {
        Self {
            client_id: value.client_id,
            verified: true,
            relay_id: value.relay.relay_id,
            realm: value.relay.realm,
            kt_log_url: value.relay.kt_log_url,
            witness_url: value.relay.witness_url,
            tree_size: value.tree_head.tree_size,
            root_hash_b64: value.tree_head.root_hash_b64,
            pinned_now: value.pinned_now,
            checkpoint_recorded: value.checkpoint_recorded,
        }
    }
}

pub struct TrustEngine<S> {
    store: S,
}

impl<S> TrustEngine<S>
where
    S: SecretStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn verify_relay(
        &mut self,
        request: &TrustVerificationRequest,
    ) -> Result<TrustVerificationResult> {
        let stored_pin = self
            .store
            .load_relay_pin(&request.hello.relay_id)
            .map(RelayPin::from);

        let relay = verify_server_proof(
            &request.hello,
            &request.proof,
            &request.client,
            stored_pin.as_ref(),
        )?;

        let tree_head = verify_inclusion_proof(
            &request.inclusion,
            &relay.relay_id,
            &relay.relay_public_key_b64,
        )?;

        let stored_checkpoint = self.store.load_witness_checkpoint(&relay.kt_log_url);
        let witness_checkpoint = request
            .witness_checkpoint
            .as_ref()
            .or(stored_checkpoint.as_ref());
        verify_witness_checkpoint(
            &tree_head,
            witness_checkpoint,
            &relay.kt_log_url,
        )?;
        if let Some(previous_checkpoint) = stored_checkpoint.as_ref() {
            if tree_head.tree_size > previous_checkpoint.tree_size {
                let consistency = request.consistency.as_ref().ok_or_else(|| {
                    crate::ClientCoreError::Verification(
                        "missing KT consistency proof for newer tree head".to_string(),
                    )
                })?;
                verify_consistency_proof(consistency, previous_checkpoint, &tree_head)?;
            }
        }

        let pinned_now = stored_pin.is_none();
        if pinned_now {
            self.store.save_relay_pin(StoredRelayPin {
                relay_id: relay.relay_id.clone(),
                realm: relay.realm.clone(),
                public_key_b64: relay.relay_public_key_b64.clone(),
            });
        }

        if let Some(checkpoint) = request.witness_checkpoint.clone() {
            self.store.save_witness_checkpoint(checkpoint);
        }

        Ok(TrustVerificationResult {
            client_id: request.client.client_id.clone(),
            relay,
            tree_head,
            pinned_now,
            checkpoint_recorded: true,
        })
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    use crate::engine::PortableTrustVerificationResult;
    use crate::httpq::{transcript_bytes, ClientHello, ServerHello, ServerProof};
    use crate::kt::{witness_message, LoggedRelayRecord, SignedTreeHead, WitnessCheckpoint};
    use crate::storage::{MemorySecretStore, SecretStore};

    use super::{TrustEngine, TrustVerificationRequest};

    fn sample_request() -> TrustVerificationRequest {
        let relay_signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let kt_signing_key = SigningKey::from_bytes(&[2u8; 32]);
        let witness_signing_key = SigningKey::from_bytes(&[12u8; 32]);

        let client = ClientHello {
            client_id: "anon-1".to_string(),
            client_nonce_b64: STANDARD.encode([3u8; 32]),
        };
        let hello = ServerHello {
            relay_id: "relay-local".to_string(),
            realm: "secure-chat".to_string(),
            protocol_version: "HTTPq/1".to_string(),
            kt_log_url: "http://127.0.0.1:8081".to_string(),
            witness_url: "http://127.0.0.1:8082".to_string(),
            server_nonce_b64: STANDARD.encode([4u8; 32]),
            relay_public_key_b64: STANDARD.encode(relay_signing_key.verifying_key().to_bytes()),
        };
        let proof = ServerProof {
            relay_id: hello.relay_id.clone(),
            realm: hello.realm.clone(),
            client_id: client.client_id.clone(),
            client_nonce_b64: client.client_nonce_b64.clone(),
            server_nonce_b64: hello.server_nonce_b64.clone(),
            relay_public_key_b64: hello.relay_public_key_b64.clone(),
            signature_b64: STANDARD.encode(
                relay_signing_key
                    .sign(&transcript_bytes(
                        &hello.realm,
                        &client.client_id,
                        &client.client_nonce_b64,
                        &hello.server_nonce_b64,
                        &hello.relay_public_key_b64,
                    ))
                    .to_bytes(),
            ),
        };

        let record = LoggedRelayRecord {
            relay_id: hello.relay_id.clone(),
            public_key_b64: hello.relay_public_key_b64.clone(),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-03-25T00:00:00Z".to_string(),
        };
        let sibling = LoggedRelayRecord {
            relay_id: "relay-peer".to_string(),
            public_key_b64: STANDARD.encode([9u8; 32]),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-03-25T00:00:01Z".to_string(),
        };
        let record_bytes =
            serde_json::to_vec(&record).expect("record serialization should succeed");
        let sibling_bytes =
            serde_json::to_vec(&sibling).expect("sibling serialization should succeed");
        let leaf = sha2::Sha256::digest([b"\x00".as_slice(), record_bytes.as_slice()].concat());
        let sibling_leaf =
            sha2::Sha256::digest([b"\x00".as_slice(), sibling_bytes.as_slice()].concat());
        let root = sha2::Sha256::digest(
            [b"\x01".as_slice(), leaf.as_slice(), sibling_leaf.as_slice()].concat(),
        );
        let sth = SignedTreeHead {
            tree_size: 2,
            root_hash_b64: STANDARD.encode(root),
            signature_b64: STANDARD.encode(
                kt_signing_key
                    .sign(
                        &[
                            "KT-LOG/1".to_string(),
                            "2".to_string(),
                            STANDARD.encode(root),
                        ]
                        .join("\n")
                        .into_bytes(),
                    )
                    .to_bytes(),
            ),
        };

        TrustVerificationRequest {
            client,
            hello,
            proof,
            inclusion: crate::kt::InclusionProof {
                record,
                index: 0,
                proof_b64: vec![STANDARD.encode(sibling_leaf)],
                sth,
                signing_public_key_b64: STANDARD.encode(kt_signing_key.verifying_key().to_bytes()),
            },
            consistency: None,
            witness_checkpoint: Some(WitnessCheckpoint {
                log_id: "http://127.0.0.1:8081".to_string(),
                tree_size: 2,
                root_hash_b64: STANDARD.encode(root),
                signing_public_key_b64: STANDARD.encode(kt_signing_key.verifying_key().to_bytes()),
                witness_public_key_b64: STANDARD.encode(witness_signing_key.verifying_key().to_bytes()),
                witness_signature_b64: STANDARD.encode(
                    witness_signing_key
                        .sign(&witness_message(
                            "http://127.0.0.1:8081",
                            2,
                            &STANDARD.encode(root),
                            &STANDARD.encode(kt_signing_key.verifying_key().to_bytes()),
                        ))
                        .to_bytes(),
                ),
            }),
        }
    }

    #[test]
    fn first_verification_pins_and_records_checkpoint() {
        let mut engine = TrustEngine::new(MemorySecretStore::default());
        let result = engine
            .verify_relay(&sample_request())
            .expect("verification should succeed");

        assert!(result.pinned_now);
        let store = engine.into_store();
        assert!(store.load_relay_pin("relay-local").is_some());
        assert!(store.load_witness_checkpoint("http://127.0.0.1:8081").is_some());
    }

    #[test]
    fn later_verification_uses_existing_pin() {
        let request = sample_request();
        let mut store = MemorySecretStore::default();
        let mut engine = TrustEngine::new(store.clone());
        engine
            .verify_relay(&request)
            .expect("initial verification should succeed");
        store = engine.into_store();

        let mut second_engine = TrustEngine::new(store);
        let result = second_engine
            .verify_relay(&request)
            .expect("repeat verification should succeed");

        assert!(!result.pinned_now);
    }

    #[test]
    fn portable_trust_result_uses_python_compatible_fields() {
        let mut engine = TrustEngine::new(MemorySecretStore::default());
        let result = engine
            .verify_relay(&sample_request())
            .expect("verification should succeed");
        let portable = PortableTrustVerificationResult::from(result);

        assert_eq!(portable.client_id, "anon-1");
        assert!(portable.verified);
        assert_eq!(portable.relay_id, "relay-local");
        assert_eq!(portable.realm, "secure-chat");
        assert_eq!(portable.kt_log_url, "http://127.0.0.1:8081");
        assert_eq!(portable.witness_url, "http://127.0.0.1:8082");
        assert_eq!(portable.tree_size, 2);
        assert!(portable.pinned_now);
    }

    #[test]
    fn rejects_kt_record_with_wrong_public_key() {
        let mut request = sample_request();
        request.inclusion.record.public_key_b64 = STANDARD.encode([11u8; 32]);

        let mut engine = TrustEngine::new(MemorySecretStore::default());
        assert!(engine.verify_relay(&request).is_err());

        let store = engine.into_store();
        assert!(store.load_relay_pin("relay-local").is_none());
        assert!(store.load_witness_checkpoint("http://127.0.0.1:8081").is_none());
    }

    #[test]
    fn rejects_witness_checkpoint_with_different_signing_key() {
        let mut request = sample_request();
        request.witness_checkpoint = None;
        let mut store = MemorySecretStore::default();
        store.save_witness_checkpoint(WitnessCheckpoint {
            log_id: "http://127.0.0.1:8081".to_string(),
            tree_size: request.inclusion.sth.tree_size,
            root_hash_b64: request.inclusion.sth.root_hash_b64.clone(),
            signing_public_key_b64: STANDARD.encode([99u8; 32]),
            witness_public_key_b64: STANDARD.encode([3u8; 32]),
            witness_signature_b64: STANDARD.encode([4u8; 64]),
        });

        let mut engine = TrustEngine::new(store);
        assert!(engine.verify_relay(&request).is_err());
    }

    #[test]
    fn rejects_witness_checkpoint_newer_than_observed_tree() {
        let mut request = sample_request();
        request.witness_checkpoint = None;
        let mut store = MemorySecretStore::default();
        store.save_witness_checkpoint(WitnessCheckpoint {
            log_id: "http://127.0.0.1:8081".to_string(),
            tree_size: request.inclusion.sth.tree_size + 5,
            root_hash_b64: request.inclusion.sth.root_hash_b64.clone(),
            signing_public_key_b64: request.inclusion.signing_public_key_b64.clone(),
            witness_public_key_b64: STANDARD.encode([3u8; 32]),
            witness_signature_b64: STANDARD.encode([4u8; 64]),
        });

        let mut engine = TrustEngine::new(store);
        assert!(engine.verify_relay(&request).is_err());
    }
}
