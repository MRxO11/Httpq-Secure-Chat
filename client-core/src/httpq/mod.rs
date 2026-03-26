use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPin {
    pub relay_id: String,
    pub realm: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientHello {
    pub client_id: String,
    pub client_nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHello {
    pub relay_id: String,
    pub realm: String,
    pub protocol_version: String,
    pub kt_log_url: String,
    pub witness_url: String,
    pub server_nonce_b64: String,
    pub relay_public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerProof {
    pub relay_id: String,
    pub realm: String,
    pub client_id: String,
    pub client_nonce_b64: String,
    pub server_nonce_b64: String,
    pub relay_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedRelay {
    pub relay_id: String,
    pub realm: String,
    pub protocol_version: String,
    pub kt_log_url: String,
    pub witness_url: String,
    pub relay_public_key_b64: String,
    pub relay_public_key_fingerprint_hex: String,
}

pub fn verify_server_proof(
    hello: &ServerHello,
    proof: &ServerProof,
    client: &ClientHello,
    pin: Option<&RelayPin>,
) -> Result<VerifiedRelay> {
    if hello.protocol_version.trim().is_empty() {
        return Err(ClientCoreError::Verification(
            "HTTPq server hello is missing protocol version".to_string(),
        ));
    }

    if hello.protocol_version != "HTTPq/1" {
        return Err(ClientCoreError::Verification(format!(
            "unsupported HTTPq protocol version: {}",
            hello.protocol_version
        )));
    }

    if proof.relay_id != hello.relay_id {
        return Err(ClientCoreError::Verification(
            "relay id changed during handshake".to_string(),
        ));
    }

    if proof.realm != hello.realm {
        return Err(ClientCoreError::Verification(
            "relay realm changed during handshake".to_string(),
        ));
    }

    if proof.client_id != client.client_id {
        return Err(ClientCoreError::Verification(
            "relay proof references a different client id".to_string(),
        ));
    }

    if proof.client_nonce_b64 != client.client_nonce_b64 {
        return Err(ClientCoreError::Verification(
            "relay proof references a different client nonce".to_string(),
        ));
    }

    if proof.server_nonce_b64 != hello.server_nonce_b64 {
        return Err(ClientCoreError::Verification(
            "server nonce changed during handshake".to_string(),
        ));
    }

    if proof.relay_public_key_b64 != hello.relay_public_key_b64 {
        return Err(ClientCoreError::Verification(
            "relay key changed during handshake".to_string(),
        ));
    }

    let public_key = decode_verifying_key(&proof.relay_public_key_b64)?;
    let signature = decode_signature(&proof.signature_b64)?;
    public_key
        .verify(
            &transcript_bytes(
                &proof.realm,
                &proof.client_id,
                &proof.client_nonce_b64,
                &proof.server_nonce_b64,
                &proof.relay_public_key_b64,
            ),
            &signature,
        )
        .map_err(|_| {
            ClientCoreError::Verification("relay signature verification failed".to_string())
        })?;

    if let Some(pin) = pin {
        verify_pin(pin, &hello.relay_id, &hello.realm, &hello.relay_public_key_b64)?;
    }

    Ok(VerifiedRelay {
        relay_id: hello.relay_id.clone(),
        realm: hello.realm.clone(),
        protocol_version: hello.protocol_version.clone(),
        kt_log_url: hello.kt_log_url.clone(),
        witness_url: hello.witness_url.clone(),
        relay_public_key_b64: hello.relay_public_key_b64.clone(),
        relay_public_key_fingerprint_hex: fingerprint_public_key(&hello.relay_public_key_b64)?,
    })
}

pub fn verify_pin(
    pin: &RelayPin,
    relay_id: &str,
    realm: &str,
    relay_public_key_b64: &str,
) -> Result<()> {
    if pin.relay_id != relay_id {
        return Err(ClientCoreError::Verification(
            "relay id does not match pinned identity".to_string(),
        ));
    }

    if pin.realm != realm {
        return Err(ClientCoreError::Verification(
            "relay realm does not match pinned identity".to_string(),
        ));
    }

    if pin.public_key_b64 != relay_public_key_b64 {
        return Err(ClientCoreError::Verification(
            "relay public key does not match pinned identity".to_string(),
        ));
    }

    Ok(())
}

pub fn transcript_bytes(
    realm: &str,
    client_id: &str,
    client_nonce_b64: &str,
    server_nonce_b64: &str,
    relay_public_key_b64: &str,
) -> Vec<u8> {
    [
        "HTTPq/1",
        realm,
        client_id,
        client_nonce_b64,
        server_nonce_b64,
        relay_public_key_b64,
    ]
    .join("\n")
    .into_bytes()
}

pub fn fingerprint_public_key(public_key_b64: &str) -> Result<String> {
    let public_key = STANDARD
        .decode(public_key_b64)
        .map_err(|_| ClientCoreError::Verification("relay public key is not valid base64".to_string()))?;
    let digest = Sha256::digest(public_key);
    Ok(hex_encode(&digest))
}

fn decode_verifying_key(public_key_b64: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD
        .decode(public_key_b64)
        .map_err(|_| ClientCoreError::Verification("relay public key is not valid base64".to_string()))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::Verification("relay public key has invalid length".to_string()))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| ClientCoreError::Verification("relay public key is invalid".to_string()))
}

fn decode_signature(signature_b64: &str) -> Result<Signature> {
    let bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| ClientCoreError::Verification("relay signature is not valid base64".to_string()))?;
    let array: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientCoreError::Verification("relay signature has invalid length".to_string()))?;
    Ok(Signature::from_bytes(&array))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    use super::{fingerprint_public_key, verify_server_proof, ClientHello, RelayPin, ServerHello, ServerProof};

    fn sample_handshake() -> (ServerHello, ServerProof, ClientHello, RelayPin) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().to_bytes());
        let client = ClientHello {
            client_id: "anon-1".to_string(),
            client_nonce_b64: STANDARD.encode([1u8; 32]),
        };
        let hello = ServerHello {
            relay_id: "relay-local".to_string(),
            realm: "secure-chat".to_string(),
            protocol_version: "HTTPq/1".to_string(),
            kt_log_url: "http://127.0.0.1:8081".to_string(),
            witness_url: "http://127.0.0.1:8082".to_string(),
            server_nonce_b64: STANDARD.encode([2u8; 32]),
            relay_public_key_b64: public_key_b64.clone(),
        };
        let transcript = super::transcript_bytes(
            &hello.realm,
            &client.client_id,
            &client.client_nonce_b64,
            &hello.server_nonce_b64,
            &hello.relay_public_key_b64,
        );
        let proof = ServerProof {
            relay_id: hello.relay_id.clone(),
            realm: hello.realm.clone(),
            client_id: client.client_id.clone(),
            client_nonce_b64: client.client_nonce_b64.clone(),
            server_nonce_b64: hello.server_nonce_b64.clone(),
            relay_public_key_b64: hello.relay_public_key_b64.clone(),
            signature_b64: STANDARD.encode(signing_key.sign(&transcript).to_bytes()),
        };
        let pin = RelayPin {
            relay_id: hello.relay_id.clone(),
            realm: hello.realm.clone(),
            public_key_b64: hello.relay_public_key_b64.clone(),
        };
        (hello, proof, client, pin)
    }

    #[test]
    fn verifies_valid_server_proof() {
        let (hello, proof, client, pin) = sample_handshake();
        let verified = verify_server_proof(&hello, &proof, &client, Some(&pin))
            .expect("server proof should verify");
        assert_eq!(verified.relay_id, "relay-local");
        assert_eq!(
            verified.relay_public_key_fingerprint_hex,
            fingerprint_public_key(&hello.relay_public_key_b64).expect("fingerprint should compute")
        );
    }

    #[test]
    fn rejects_pinned_key_mismatch() {
        let (hello, proof, client, mut pin) = sample_handshake();
        pin.public_key_b64 = STANDARD.encode([9u8; 32]);
        assert!(verify_server_proof(&hello, &proof, &client, Some(&pin)).is_err());
    }

    #[test]
    fn rejects_client_nonce_swap() {
        let (hello, proof, mut client, pin) = sample_handshake();
        client.client_nonce_b64 = STANDARD.encode([8u8; 32]);
        assert!(verify_server_proof(&hello, &proof, &client, Some(&pin)).is_err());
    }
}
