use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoggedRelayRecord {
    pub relay_id: String,
    pub public_key_b64: String,
    pub algorithm: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    pub record: LoggedRelayRecord,
    pub index: u64,
    pub proof_b64: Vec<String>,
    pub sth: SignedTreeHead,
    pub signing_public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub from_tree_size: u64,
    pub to_tree_size: u64,
    pub proof_b64: Vec<String>,
    pub old_root_hash_b64: String,
    pub new_root_hash_b64: String,
    pub signing_public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessCheckpoint {
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash_b64: String,
    pub signing_public_key_b64: String,
    pub witness_public_key_b64: String,
    pub witness_signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedTreeHead {
    pub tree_size: u64,
    pub root_hash_b64: String,
    pub signing_public_key_b64: String,
}

pub fn verify_inclusion_proof(
    payload: &InclusionProof,
    expected_relay_id: &str,
    expected_public_key_b64: &str,
) -> Result<VerifiedTreeHead> {
    if payload.record.relay_id != expected_relay_id {
        return Err(ClientCoreError::Verification(
            "KT log returned a different relay record".to_string(),
        ));
    }

    if payload.record.public_key_b64 != expected_public_key_b64 {
        return Err(ClientCoreError::Verification(
            "KT log public key does not match relay proof".to_string(),
        ));
    }

    verify_sth(&payload.sth, &payload.signing_public_key_b64)?;

    let root_hash = decode_b64(&payload.sth.root_hash_b64, "KT root hash")?;
    let proof = payload
        .proof_b64
        .iter()
        .map(|node| decode_b64(node, "KT proof node"))
        .collect::<Result<Vec<_>>>()?;

    let record_bytes =
        serde_json::to_vec(&payload.record).map_err(|_| {
            ClientCoreError::Verification("unable to canonicalize KT relay record".to_string())
        })?;
    let calculated_root = merkle_root_from_proof(&record_bytes, payload.index, &proof);
    if calculated_root != root_hash {
        return Err(ClientCoreError::Verification(
            "KT inclusion proof does not match signed tree head".to_string(),
        ));
    }

    Ok(VerifiedTreeHead {
        tree_size: payload.sth.tree_size,
        root_hash_b64: payload.sth.root_hash_b64.clone(),
        signing_public_key_b64: payload.signing_public_key_b64.clone(),
    })
}

pub fn verify_sth(sth: &SignedTreeHead, signing_public_key_b64: &str) -> Result<()> {
    if sth.tree_size == 0 {
        return Err(ClientCoreError::Verification(
            "invalid tree size for STH".to_string(),
        ));
    }

    let root_hash = decode_b64(&sth.root_hash_b64, "KT root hash")?;
    let verifying_key = decode_verifying_key(signing_public_key_b64)?;
    let signature = decode_signature(&sth.signature_b64)?;
    verifying_key
        .verify(&sth_message(sth.tree_size, &root_hash), &signature)
        .map_err(|_| {
            ClientCoreError::Verification("KT log STH signature verification failed".to_string())
        })?;
    Ok(())
}

pub fn verify_witness_checkpoint(
    observed: &VerifiedTreeHead,
    checkpoint: Option<&WitnessCheckpoint>,
    log_id: &str,
) -> Result<()> {
    if let Some(checkpoint) = checkpoint {
        verify_witness_signature(checkpoint)?;

        if checkpoint.log_id != log_id {
            return Err(ClientCoreError::Verification(
                "witness checkpoint log id does not match KT log".to_string(),
            ));
        }

        if checkpoint.signing_public_key_b64 != observed.signing_public_key_b64 {
            return Err(ClientCoreError::Verification(
                "witness observed a different KT signing key".to_string(),
            ));
        }

        if observed.tree_size < checkpoint.tree_size {
            return Err(ClientCoreError::Verification(
                "KT log view is older than witness checkpoint".to_string(),
            ));
        }

        if observed.tree_size == checkpoint.tree_size
            && observed.root_hash_b64 != checkpoint.root_hash_b64
        {
            return Err(ClientCoreError::Verification(
                "witness detected a split-view tree head".to_string(),
            ));
        }
    }

    Ok(())
}

pub fn verify_witness_signature(checkpoint: &WitnessCheckpoint) -> Result<()> {
    if checkpoint.witness_public_key_b64.is_empty() || checkpoint.witness_signature_b64.is_empty() {
        return Err(ClientCoreError::Verification(
            "witness checkpoint is missing witness signature".to_string(),
        ));
    }

    let verifying_key = decode_verifying_key_from_label(
        &checkpoint.witness_public_key_b64,
        "witness public key",
    )?;
    let signature = decode_signature_from_label(
        &checkpoint.witness_signature_b64,
        "witness signature",
    )?;
    verifying_key
        .verify(
            &witness_message(
                &checkpoint.log_id,
                checkpoint.tree_size,
                &checkpoint.root_hash_b64,
                &checkpoint.signing_public_key_b64,
            ),
            &signature,
        )
        .map_err(|_| {
            ClientCoreError::Verification(
                "witness checkpoint signature verification failed".to_string(),
            )
        })?;
    Ok(())
}

pub fn verify_consistency_proof(
    proof: &ConsistencyProof,
    previous: &WitnessCheckpoint,
    observed: &VerifiedTreeHead,
) -> Result<()> {
    if proof.from_tree_size != previous.tree_size || proof.to_tree_size != observed.tree_size {
        return Err(ClientCoreError::Verification(
            "KT consistency proof tree sizes do not match expected tree heads".to_string(),
        ));
    }
    if proof.old_root_hash_b64 != previous.root_hash_b64 || proof.new_root_hash_b64 != observed.root_hash_b64 {
        return Err(ClientCoreError::Verification(
            "KT consistency proof roots do not match expected tree heads".to_string(),
        ));
    }
    if proof.signing_public_key_b64 != observed.signing_public_key_b64 {
        return Err(ClientCoreError::Verification(
            "KT consistency proof signing key does not match observed tree head".to_string(),
        ));
    }

    let old_root = decode_b64(&previous.root_hash_b64, "KT old root hash")?;
    let new_root = decode_b64(&observed.root_hash_b64, "KT new root hash")?;
    let nodes = proof
        .proof_b64
        .iter()
        .map(|node| decode_b64(node, "KT consistency proof node"))
        .collect::<Result<Vec<_>>>()?;

    if !verify_consistency_path(proof.from_tree_size, proof.to_tree_size, &old_root, &new_root, &nodes) {
        return Err(ClientCoreError::Verification(
            "KT consistency proof does not verify append-only history".to_string(),
        ));
    }

    Ok(())
}

pub fn sth_message(tree_size: u64, root_hash: &[u8]) -> Vec<u8> {
    [
        "KT-LOG/1".to_string(),
        tree_size.to_string(),
        STANDARD.encode(root_hash),
    ]
    .join("\n")
    .into_bytes()
}

pub fn witness_message(
    log_id: &str,
    tree_size: u64,
    root_hash_b64: &str,
    signing_public_key_b64: &str,
) -> Vec<u8> {
    [
        "WITNESS/1".to_string(),
        log_id.to_string(),
        tree_size.to_string(),
        root_hash_b64.to_string(),
        signing_public_key_b64.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

pub fn merkle_root_from_proof(record_bytes: &[u8], index: u64, proof: &[Vec<u8>]) -> Vec<u8> {
    let mut current = hash_leaf(record_bytes);
    let mut position = index;

    for sibling in proof {
        current = if position % 2 == 0 {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
        position /= 2;
    }

    current
}

fn hash_leaf(leaf: &[u8]) -> Vec<u8> {
    Sha256::digest([b"\x00".as_slice(), leaf].concat()).to_vec()
}

fn hash_node(left: &[u8], right: &[u8]) -> Vec<u8> {
    Sha256::digest([b"\x01".as_slice(), left, right].concat()).to_vec()
}

fn decode_b64(value: &str, label: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| {
        ClientCoreError::Verification(format!("{label} is not valid base64"))
    })
}

fn decode_verifying_key(public_key_b64: &str) -> Result<VerifyingKey> {
    decode_verifying_key_from_label(public_key_b64, "KT signing public key")
}

fn decode_verifying_key_from_label(public_key_b64: &str, label: &str) -> Result<VerifyingKey> {
    let bytes = decode_b64(public_key_b64, "KT signing public key")?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::Verification(format!("{label} has invalid length")))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| ClientCoreError::Verification(format!("{label} is invalid")))
}

fn decode_signature(signature_b64: &str) -> Result<Signature> {
    decode_signature_from_label(signature_b64, "KT signature")
}

fn decode_signature_from_label(signature_b64: &str, label: &str) -> Result<Signature> {
    let bytes = decode_b64(signature_b64, "KT signature")?;
    let array: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::Verification(format!("{label} has invalid length")))?;
    Ok(Signature::from_bytes(&array))
}

fn verify_consistency_path(
    old_tree_size: u64,
    new_tree_size: u64,
    old_root_hash: &[u8],
    new_root_hash: &[u8],
    proof: &[Vec<u8>],
) -> bool {
    if old_tree_size == 0 || new_tree_size == 0 || old_tree_size > new_tree_size {
        return false;
    }
    if old_tree_size == new_tree_size {
        return old_root_hash == new_root_hash && proof.is_empty();
    }

    let mut fn_index = old_tree_size - 1;
    let mut sn_index = new_tree_size - 1;
    while fn_index % 2 == 1 {
        fn_index /= 2;
        sn_index /= 2;
    }

    if proof.is_empty() {
        return false;
    }

    let mut old_hash = proof[0].clone();
    let mut new_hash = proof[0].clone();
    let mut proof_index = 1usize;

    while fn_index != 0 {
        if proof_index >= proof.len() {
            return false;
        }
        if fn_index % 2 == 1 {
            old_hash = hash_node(&proof[proof_index], &old_hash);
            new_hash = hash_node(&proof[proof_index], &new_hash);
            proof_index += 1;
        } else if fn_index < sn_index {
            new_hash = hash_node(&new_hash, &proof[proof_index]);
            proof_index += 1;
        }
        fn_index /= 2;
        sn_index /= 2;
    }

    while sn_index != 0 {
        if proof_index >= proof.len() {
            return false;
        }
        new_hash = hash_node(&new_hash, &proof[proof_index]);
        proof_index += 1;
        sn_index /= 2;
    }

    old_hash == old_root_hash && new_hash == new_root_hash
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    use super::{
        hash_leaf, hash_node, merkle_root_from_proof, sth_message, verify_consistency_proof,
        verify_inclusion_proof, verify_witness_checkpoint, witness_message, ConsistencyProof,
        InclusionProof, LoggedRelayRecord, SignedTreeHead, VerifiedTreeHead, WitnessCheckpoint,
    };

    fn sample_payload() -> InclusionProof {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let record = LoggedRelayRecord {
            relay_id: "relay-local".to_string(),
            public_key_b64: STANDARD.encode([7u8; 32]),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-03-25T00:00:00Z".to_string(),
        };
        let record_bytes = serde_json::to_vec(&record).expect("record serialization should succeed");
        let sibling_record = LoggedRelayRecord {
            relay_id: "relay-peer".to_string(),
            public_key_b64: STANDARD.encode([8u8; 32]),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-03-25T00:00:01Z".to_string(),
        };
        let sibling_bytes =
            serde_json::to_vec(&sibling_record).expect("sibling serialization should succeed");
        let root = hash_node(&hash_leaf(&record_bytes), &hash_leaf(&sibling_bytes));
        let sth = SignedTreeHead {
            tree_size: 2,
            root_hash_b64: STANDARD.encode(&root),
            signature_b64: STANDARD.encode(signing_key.sign(&sth_message(2, &root)).to_bytes()),
        };

        InclusionProof {
            record,
            index: 0,
            proof_b64: vec![STANDARD.encode(hash_leaf(&sibling_bytes))],
            sth,
            signing_public_key_b64: STANDARD.encode(signing_key.verifying_key().to_bytes()),
        }
    }

    #[test]
    fn verifies_valid_inclusion_proof() {
        let payload = sample_payload();
        let verified = verify_inclusion_proof(
            &payload,
            "relay-local",
            &STANDARD.encode([7u8; 32]),
        )
        .expect("inclusion proof should verify");
        assert_eq!(verified.tree_size, 2);
    }

    #[test]
    fn rejects_split_view_checkpoint() {
        let observed = VerifiedTreeHead {
            tree_size: 2,
            root_hash_b64: STANDARD.encode([1u8; 32]),
            signing_public_key_b64: STANDARD.encode([9u8; 32]),
        };
        let witness_key = SigningKey::from_bytes(&[6u8; 32]);
        let checkpoint = WitnessCheckpoint {
            log_id: "http://127.0.0.1:8081".to_string(),
            tree_size: 2,
            root_hash_b64: STANDARD.encode([2u8; 32]),
            signing_public_key_b64: STANDARD.encode([9u8; 32]),
            witness_public_key_b64: STANDARD.encode(witness_key.verifying_key().to_bytes()),
            witness_signature_b64: STANDARD.encode(
                witness_key
                    .sign(&witness_message(
                        "http://127.0.0.1:8081",
                        2,
                        &STANDARD.encode([2u8; 32]),
                        &STANDARD.encode([9u8; 32]),
                    ))
                    .to_bytes(),
            ),
        };

        assert!(verify_witness_checkpoint(
            &observed,
            Some(&checkpoint),
            "http://127.0.0.1:8081"
        )
        .is_err());
    }

    #[test]
    fn merkle_root_matches_manual_fold() {
        let record = b"first";
        let sibling = hash_leaf(b"second");
        let root = merkle_root_from_proof(record, 0, &[sibling.clone()]);
        assert_eq!(root, hash_node(&hash_leaf(record), &sibling));
    }

    #[test]
    fn verifies_same_size_empty_consistency_proof() {
        let observed = VerifiedTreeHead {
            tree_size: 2,
            root_hash_b64: STANDARD.encode([1u8; 32]),
            signing_public_key_b64: STANDARD.encode([9u8; 32]),
        };
        let previous = WitnessCheckpoint {
            log_id: "http://127.0.0.1:8081".to_string(),
            tree_size: 2,
            root_hash_b64: observed.root_hash_b64.clone(),
            signing_public_key_b64: observed.signing_public_key_b64.clone(),
            witness_public_key_b64: STANDARD.encode([7u8; 32]),
            witness_signature_b64: STANDARD.encode([8u8; 64]),
        };
        let proof = ConsistencyProof {
            from_tree_size: 2,
            to_tree_size: 2,
            proof_b64: vec![],
            old_root_hash_b64: previous.root_hash_b64.clone(),
            new_root_hash_b64: observed.root_hash_b64.clone(),
            signing_public_key_b64: observed.signing_public_key_b64.clone(),
        };
        assert!(verify_consistency_proof(&proof, &previous, &observed).is_ok());
    }
}
