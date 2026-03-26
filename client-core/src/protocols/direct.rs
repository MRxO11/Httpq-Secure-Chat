use std::collections::HashMap;

use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocols::DirectBootstrapMessage;
use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectPeerAnnouncement {
    pub client_id: String,
    pub username: String,
    pub room_id: String,
    pub encryption_key_b64: String,
    pub signing_key_b64: String,
    pub signature_b64: String,
}

impl DirectPeerAnnouncement {
    pub fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct peer announcement is missing client_id".to_string(),
            ));
        }

        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct peer announcement is missing room_id".to_string(),
            ));
        }

        if self.encryption_key_b64.trim().is_empty() || self.signing_key_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct peer announcement is missing public keys".to_string(),
            ));
        }

        if self.signature_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct peer announcement is missing signature".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectSessionHeader {
    pub session_id: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectEnvelopeAlgorithm {
    AuthenticatedStaticBridge,
    SessionChainBridge,
}

impl DirectEnvelopeAlgorithm {
    pub fn classify(value: &str) -> Option<Self> {
        match value.trim() {
            "x25519+hkdf+aes-256-gcm+ed25519" => Some(Self::AuthenticatedStaticBridge),
            "pqxdh-bridge+hkdf+aes-256-gcm+ed25519" => Some(Self::SessionChainBridge),
            _ => None,
        }
    }

    pub fn uses_session_chain(self) -> bool {
        matches!(self, Self::SessionChainBridge)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub header: DirectSessionHeader,
    pub sender_key_b64: String,
    pub sender_ratchet_key_b64: Option<String>,
    pub sender_signing_key_b64: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub signature_b64: String,
}

impl DirectEnvelope {
    pub fn classified_algorithm(&self) -> Option<DirectEnvelopeAlgorithm> {
        DirectEnvelopeAlgorithm::classify(&self.algorithm)
    }

    pub fn uses_session_chain(&self) -> bool {
        self.classified_algorithm()
            .is_some_and(DirectEnvelopeAlgorithm::uses_session_chain)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(ClientCoreError::State(
                "direct envelope version must be non-zero".to_string(),
            ));
        }

        if self.header.session_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct envelope is missing session_id".to_string(),
            ));
        }

        if self.signature_b64.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct envelope is missing signature".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectControlFrame {
    pub target_client_id: String,
    pub message: DirectBootstrapMessage,
}

impl DirectControlFrame {
    pub fn validate(&self) -> Result<()> {
        if self.target_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct control frame is missing target client id".to_string(),
            ));
        }

        self.message.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectApplicationFrame {
    pub target_client_id: String,
    pub envelope: DirectEnvelope,
}

impl DirectApplicationFrame {
    pub fn validate(&self) -> Result<()> {
        if self.target_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "direct application frame is missing target client id".to_string(),
            ));
        }

        self.envelope.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectTransportFrame {
    Control(DirectControlFrame),
    Application(DirectApplicationFrame),
}

impl DirectTransportFrame {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Control(frame) => frame.validate(),
            Self::Application(frame) => frame.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainKeyRef {
    pub generation: u64,
    pub key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedMessageKey {
    pub message_number: u64,
    pub chain_generation: u64,
    pub key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedMessageKey {
    pub sequence: u64,
    pub message_number: u64,
    pub key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectSession {
    pub peer_client_id: String,
    pub session_id: String,
    pub outbound_sequence: u64,
    pub highest_inbound_sequence: u64,
}

impl DirectSession {
    pub fn new(peer_client_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            peer_client_id: peer_client_id.into(),
            session_id: session_id.into(),
            outbound_sequence: 0,
            highest_inbound_sequence: 0,
        }
    }

    pub fn next_outbound_sequence(&mut self) -> u64 {
        self.outbound_sequence += 1;
        self.outbound_sequence
    }

    pub fn accept_inbound_sequence(&mut self, sequence: u64) -> Result<()> {
        if sequence <= self.highest_inbound_sequence {
            return Err(ClientCoreError::State(format!(
                "replayed or out-of-order direct message sequence: {} <= {}",
                sequence, self.highest_inbound_sequence
            )));
        }

        self.highest_inbound_sequence = sequence;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectRatchetState {
    pub peer_client_id: String,
    pub session_id: String,
    pub root_key_ref: String,
    pub dh_ratchet_turn: u64,
    pub local_ratchet_public_key_b64: String,
    pub local_ratchet_private_key_b64: String,
    pub remote_ratchet_public_key_b64: Option<String>,
    pub next_send_message_number: u64,
    pub next_receive_message_number: u64,
    pub send_chain_generation: u64,
    pub receive_chain_generation: u64,
    pub send_chain_key: ChainKeyRef,
    pub receive_chain_key: ChainKeyRef,
    pub last_derived_send_message_key: Option<DerivedMessageKey>,
    pub last_derived_receive_message_key: Option<DerivedMessageKey>,
    pub skipped_message_keys: Vec<SkippedMessageKey>,
    pub last_bootstrap_protocol: String,
}

impl DirectRatchetState {
    pub fn initialize(
        peer_client_id: impl Into<String>,
        session_id: impl Into<String>,
        root_key_ref: impl Into<String>,
        bootstrap_protocol: impl Into<String>,
    ) -> Self {
        let peer_client_id = peer_client_id.into();
        let session_id = session_id.into();
        let root_key_ref = root_key_ref.into();
        let (local_ratchet_private_key_b64, local_ratchet_public_key_b64) =
            derive_ratchet_key_pair(&root_key_ref, 0);
        Self {
            root_key_ref: root_key_ref.clone(),
            dh_ratchet_turn: 0,
            local_ratchet_public_key_b64,
            local_ratchet_private_key_b64,
            remote_ratchet_public_key_b64: None,
            peer_client_id,
            session_id,
            next_send_message_number: 1,
            next_receive_message_number: 1,
            send_chain_generation: 0,
            receive_chain_generation: 0,
            send_chain_key: ChainKeyRef {
                generation: 0,
                key_ref: derive_key_ref(&root_key_ref, "ck-send", 0, None),
            },
            receive_chain_key: ChainKeyRef {
                generation: 0,
                key_ref: derive_key_ref(&root_key_ref, "ck-recv", 0, None),
            },
            last_derived_send_message_key: None,
            last_derived_receive_message_key: None,
            skipped_message_keys: Vec::new(),
            last_bootstrap_protocol: bootstrap_protocol.into(),
        }
    }

    pub fn apply_remote_ratchet_key(&mut self, remote_ratchet_public_key_b64: &str) -> Result<bool> {
        if self
            .remote_ratchet_public_key_b64
            .as_deref()
            .is_some_and(|value| value == remote_ratchet_public_key_b64)
        {
            return Ok(false);
        }

        if self.remote_ratchet_public_key_b64.is_none() {
            self.remote_ratchet_public_key_b64 = Some(remote_ratchet_public_key_b64.to_string());
            self.dh_ratchet_turn += 1;
            return Ok(false);
        }

        let local_secret = decode_x25519_secret(&self.local_ratchet_private_key_b64)?;
        let remote_public = decode_x25519_public(remote_ratchet_public_key_b64)?;
        let shared_secret = local_secret.diffie_hellman(&remote_public);

        self.dh_ratchet_turn += 1;
        self.root_key_ref = derive_dh_ratchet_root_ref(
            &self.root_key_ref,
            self.dh_ratchet_turn,
            shared_secret.as_bytes(),
        )?;
        let (next_private, next_public) =
            derive_ratchet_key_pair(&self.root_key_ref, self.dh_ratchet_turn);
        self.local_ratchet_private_key_b64 = next_private;
        self.local_ratchet_public_key_b64 = next_public;
        self.remote_ratchet_public_key_b64 = Some(remote_ratchet_public_key_b64.to_string());
        self.next_send_message_number = 1;
        self.next_receive_message_number = 1;
        self.send_chain_generation = 0;
        self.receive_chain_generation = 0;
        self.send_chain_key = ChainKeyRef {
            generation: 0,
            key_ref: derive_key_ref(&self.root_key_ref, "ck-send", 0, None),
        };
        self.receive_chain_key = ChainKeyRef {
            generation: 0,
            key_ref: derive_key_ref(&self.root_key_ref, "ck-recv", 0, None),
        };
        self.last_derived_send_message_key = None;
        self.last_derived_receive_message_key = None;
        self.skipped_message_keys.clear();
        Ok(true)
    }

    pub fn next_send_step(&mut self) -> DerivedMessageKey {
        let message_key = DerivedMessageKey {
            message_number: self.next_send_message_number,
            chain_generation: self.send_chain_generation + 1,
            key_ref: derive_key_ref(
                &self.send_chain_key.key_ref,
                "mk-send",
                self.send_chain_generation + 1,
                Some(self.next_send_message_number),
            ),
        };
        self.send_chain_generation += 1;
        self.send_chain_key = ChainKeyRef {
            generation: self.send_chain_generation,
            key_ref: derive_key_ref(
                &self.send_chain_key.key_ref,
                "ck-send",
                self.send_chain_generation,
                None,
            ),
        };
        self.next_send_message_number += 1;
        self.last_derived_send_message_key = Some(message_key.clone());
        message_key
    }

    pub fn accept_receive_step(&mut self, generation: u64) -> Result<DerivedMessageKey> {
        if generation <= self.receive_chain_generation {
            return Err(ClientCoreError::State(format!(
                "replayed or out-of-order ratchet receive generation: {} <= {}",
                generation, self.receive_chain_generation
            )));
        }

        self.cache_skipped_until(generation);
        self.receive_chain_generation = generation;
        self.receive_chain_key = ChainKeyRef {
            generation,
            key_ref: derive_key_ref(
                &self.receive_chain_key.key_ref,
                "ck-recv",
                generation,
                None,
            ),
        };
        let message_key = DerivedMessageKey {
            message_number: self.next_receive_message_number,
            chain_generation: generation,
            key_ref: derive_key_ref(
                &self.receive_chain_key.key_ref,
                "mk-recv",
                generation,
                Some(self.next_receive_message_number),
            ),
        };
        self.next_receive_message_number += 1;
        self.last_derived_receive_message_key = Some(message_key.clone());
        Ok(message_key)
    }

    pub fn cache_skipped_until(&mut self, generation: u64) {
        let mut current = self.receive_chain_generation + 1;
        while current < generation {
            self.skipped_message_keys.push(SkippedMessageKey {
                sequence: current,
                message_number: self.next_receive_message_number,
                key_ref: derive_key_ref(
                    &self.receive_chain_key.key_ref,
                    "mk-skipped",
                    current,
                    Some(self.next_receive_message_number),
                ),
            });
            self.next_receive_message_number += 1;
            current += 1;
        }
    }

    pub fn try_consume_skipped_message_key(&mut self, generation: u64) -> Option<SkippedMessageKey> {
        let position = self
            .skipped_message_keys
            .iter()
            .position(|key| key.sequence == generation)?;
        Some(self.skipped_message_keys.remove(position))
    }
}

fn derive_key_ref(parent_ref: &str, label: &str, generation: u64, message_number: Option<u64>) -> String {
    let mut digest = Sha256::new();
    digest.update(parent_ref.as_bytes());
    digest.update(b"|");
    digest.update(label.as_bytes());
    digest.update(b"|");
    digest.update(generation.to_string().as_bytes());
    digest.update(b"|");
    digest.update(
        message_number
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
            .as_bytes(),
    );
    format!(
        "{}::{}::{}",
        label,
        generation,
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest.finalize())
    )
}

fn derive_ratchet_key_pair(root_key_ref: &str, turn: u64) -> (String, String) {
    let mut digest = Sha256::new();
    digest.update(root_key_ref.as_bytes());
    digest.update(b"|ratchet-key|");
    digest.update(turn.to_string().as_bytes());
    let seed = digest.finalize();
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&seed[..32]);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    (
        base64::engine::general_purpose::STANDARD.encode(secret.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
    )
}

fn derive_dh_ratchet_root_ref(
    previous_root_key_ref: &str,
    turn: u64,
    shared_secret: &[u8],
) -> Result<String> {
    let hk = Hkdf::<Sha256>::new(Some(previous_root_key_ref.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(format!("secure-chat::dh-ratchet::{turn}").as_bytes(), &mut okm)
        .map_err(|_| ClientCoreError::State("failed to derive DH ratchet root key".to_string()))?;
    Ok(format!(
        "rk::dh::{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(okm)
    ))
}

fn decode_x25519_secret(value_b64: &str) -> Result<StaticSecret> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|_| ClientCoreError::State("invalid X25519 secret key encoding".to_string()))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::State("invalid X25519 secret key length".to_string()))?;
    Ok(StaticSecret::from(array))
}

fn decode_x25519_public(value_b64: &str) -> Result<PublicKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|_| ClientCoreError::State("invalid X25519 public key encoding".to_string()))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::State("invalid X25519 public key length".to_string()))?;
    Ok(PublicKey::from(array))
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeerDirectory {
    peers: HashMap<String, DirectPeerAnnouncement>,
}

impl PeerDirectory {
    pub fn upsert(&mut self, peer: DirectPeerAnnouncement) -> Result<()> {
        peer.validate()?;
        self.peers.insert(peer.client_id.clone(), peer);
        Ok(())
    }

    pub fn remove(&mut self, client_id: &str) -> Option<DirectPeerAnnouncement> {
        self.peers.remove(client_id)
    }

    pub fn get(&self, client_id: &str) -> Option<&DirectPeerAnnouncement> {
        self.peers.get(client_id)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &DirectPeerAnnouncement)> {
        self.peers.iter()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::protocols::{
        DirectBootstrapMessage, DirectControlFrame, DirectTransportFrame, PqxdhInitPayload,
    };

    use super::{DirectApplicationFrame, DirectEnvelope, DirectEnvelopeAlgorithm, DirectPeerAnnouncement, DirectRatchetState, DirectSession, DirectSessionHeader, PeerDirectory};

    #[test]
    fn direct_session_rejects_replay() {
        let mut session = DirectSession::new("peer-b", "dm::lobby::a::b");
        assert_eq!(session.next_outbound_sequence(), 1);
        assert!(session.accept_inbound_sequence(1).is_ok());
        assert!(session.accept_inbound_sequence(1).is_err());
    }

    #[test]
    fn peer_directory_upserts_valid_peer() {
        let mut directory = PeerDirectory::default();
        let peer = DirectPeerAnnouncement {
            client_id: "anon-1".to_string(),
            username: "alice".to_string(),
            room_id: "lobby".to_string(),
            encryption_key_b64: "enc".to_string(),
            signing_key_b64: "sig".to_string(),
            signature_b64: "signed".to_string(),
        };

        assert!(directory.upsert(peer).is_ok());
        assert_eq!(directory.len(), 1);
        assert!(directory.get("anon-1").is_some());
    }

    #[test]
    fn ratchet_state_advances_send_and_receive_generations() {
        let mut ratchet =
            DirectRatchetState::initialize("peer-b", "pqxdh::lobby::a::b", "rk::test", "PQXDH/1");
        let send = ratchet.next_send_step();
        assert_eq!(send.message_number, 1);
        assert_eq!(send.chain_generation, 1);
        assert_eq!(ratchet.dh_ratchet_turn, 0);
        let recv = ratchet.accept_receive_step(1).expect("receive step should work");
        assert_eq!(recv.message_number, 1);
        assert_eq!(recv.chain_generation, 1);
        assert!(ratchet.accept_receive_step(1).is_err());
    }

    #[test]
    fn ratchet_state_caches_skipped_message_keys() {
        let mut ratchet =
            DirectRatchetState::initialize("peer-b", "pqxdh::lobby::a::b", "rk::test", "PQXDH/1");
        assert!(ratchet.accept_receive_step(3).is_ok());
        assert_eq!(ratchet.skipped_message_keys.len(), 2);
        assert_eq!(ratchet.skipped_message_keys[0].message_number, 1);
        assert_eq!(ratchet.skipped_message_keys[1].message_number, 2);
        assert!(ratchet.try_consume_skipped_message_key(1).is_some());
        assert!(ratchet.try_consume_skipped_message_key(2).is_some());
    }

    #[test]
    fn ratchet_state_applies_remote_ratchet_key_turn() {
        let mut ratchet =
            DirectRatchetState::initialize("peer-b", "pqxdh::lobby::a::b", "rk::test", "PQXDH/1");
        let remote_public =
            PublicKey::from(&StaticSecret::from([9u8; 32]));
        let remote_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(remote_public.as_bytes());
        let previous_root = ratchet.root_key_ref.clone();

        let changed = ratchet
            .apply_remote_ratchet_key(&remote_public_b64)
            .expect("remote ratchet key should apply");

        assert!(!changed);
        assert_eq!(ratchet.dh_ratchet_turn, 1);
        assert_eq!(ratchet.root_key_ref, previous_root);
        assert_eq!(
            ratchet.remote_ratchet_public_key_b64.as_deref(),
            Some(remote_public_b64.as_str())
        );
    }

    #[test]
    fn direct_envelope_detects_session_chain_algorithm() {
        let static_envelope = DirectEnvelope {
            version: 1,
            algorithm: "x25519+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: "dm::lobby::a::b".to_string(),
                sequence: 1,
            },
            sender_key_b64: "enc".to_string(),
            sender_ratchet_key_b64: None,
            sender_signing_key_b64: "sig".to_string(),
            salt_b64: "salt".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "cipher".to_string(),
            signature_b64: "signed".to_string(),
        };
        let chained_envelope = DirectEnvelope {
            version: 1,
            algorithm: "pqxdh-bridge+hkdf+aes-256-gcm+ed25519".to_string(),
            ..static_envelope.clone()
        };

        assert_eq!(
            static_envelope.classified_algorithm(),
            Some(DirectEnvelopeAlgorithm::AuthenticatedStaticBridge)
        );
        assert!(!static_envelope.uses_session_chain());
        assert_eq!(
            chained_envelope.classified_algorithm(),
            Some(DirectEnvelopeAlgorithm::SessionChainBridge)
        );
        assert!(chained_envelope.uses_session_chain());
    }

    #[test]
    fn direct_transport_frames_validate() {
        let control = DirectTransportFrame::Control(DirectControlFrame {
            target_client_id: "peer-b".to_string(),
            message: DirectBootstrapMessage::PqxdhInit(PqxdhInitPayload {
                protocol: "PQXDH/1".to_string(),
                sender_client_id: "peer-a".to_string(),
                receiver_client_id: "peer-b".to_string(),
                sender_encryption_identity_key_b64: "enc-id".to_string(),
                sender_signing_identity_key_b64: "sig-id".to_string(),
                receiver_signed_prekey_id: 1,
                receiver_one_time_prekey_id: None,
                receiver_pq_prekey_present: false,
            }),
        });
        let application = DirectTransportFrame::Application(DirectApplicationFrame {
            target_client_id: "peer-b".to_string(),
            envelope: DirectEnvelope {
                version: 1,
                algorithm: "test".to_string(),
                header: DirectSessionHeader {
                    session_id: "dm::lobby::a::b".to_string(),
                    sequence: 1,
                },
                sender_key_b64: "enc".to_string(),
                sender_ratchet_key_b64: None,
                sender_signing_key_b64: "sig".to_string(),
                salt_b64: "salt".to_string(),
                nonce_b64: "nonce".to_string(),
                ciphertext_b64: "cipher".to_string(),
                signature_b64: "signed".to_string(),
            },
        });

        assert!(control.validate().is_ok());
        assert!(application.validate().is_ok());
    }
}
