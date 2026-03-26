use serde::{Deserialize, Serialize};

use crate::protocols::{
    DirectIdentityProfile, LocalBootstrapMaterial, PeerPrekeyBundle, UsedOneTimePrekey,
};
use crate::storage::SecretStore;
use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundBootstrapPlan {
    pub peer_client_id: String,
    pub peer_signed_prekey_id: u32,
    pub peer_one_time_prekey_id: Option<u32>,
    pub pq_prekey_present: bool,
}

pub struct BootstrapEngine<S> {
    store: S,
}

impl<S> BootstrapEngine<S>
where
    S: SecretStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn save_local_identity(&mut self, profile: DirectIdentityProfile) -> Result<()> {
        profile.validate()?;
        self.store.save_direct_identity_profile(profile);
        Ok(())
    }

    pub fn local_identity(&self) -> Option<DirectIdentityProfile> {
        self.store.load_direct_identity_profile()
    }

    pub fn save_local_bootstrap_material(&mut self, material: LocalBootstrapMaterial) -> Result<()> {
        material.validate()?;
        self.store
            .save_direct_identity_profile(material.profile.clone());
        self.store.save_local_bootstrap_material(material);
        Ok(())
    }

    pub fn local_bootstrap_material(&self) -> Option<LocalBootstrapMaterial> {
        self.store.load_local_bootstrap_material()
    }

    pub fn publish_local_bundle(&mut self) -> Result<PeerPrekeyBundle> {
        let material = self
            .store
            .load_local_bootstrap_material()
            .ok_or_else(|| {
                ClientCoreError::State(
                    "cannot publish local bundle without local bootstrap material".to_string(),
                )
            })?;
        let bundle = material.public_bundle()?;
        self.store.save_peer_prekey_bundle(bundle.clone());
        Ok(bundle)
    }

    pub fn publish_peer_bundle(&mut self, bundle: PeerPrekeyBundle) -> Result<()> {
        bundle.validate()?;
        self.store.save_peer_prekey_bundle(bundle);
        Ok(())
    }

    pub fn peer_bundle(&self, peer_client_id: &str) -> Option<PeerPrekeyBundle> {
        self.store.load_peer_prekey_bundle(peer_client_id)
    }

    pub fn prepare_outbound_bootstrap(
        &mut self,
        peer_client_id: &str,
        consumed_at: &str,
    ) -> Result<OutboundBootstrapPlan> {
        let mut bundle = self
            .store
            .load_peer_prekey_bundle(peer_client_id)
            .ok_or_else(|| {
                ClientCoreError::State(format!(
                    "cannot bootstrap direct session without a prekey bundle for peer: {}",
                    peer_client_id
                ))
            })?;

        bundle.validate()?;
        let one_time = bundle.reserve_one_time_prekey()?;
        let plan = OutboundBootstrapPlan {
            peer_client_id: bundle.client_id.clone(),
            peer_signed_prekey_id: bundle.signed_prekey.key_id,
            peer_one_time_prekey_id: one_time.as_ref().map(|key| key.key_id),
            pq_prekey_present: bundle.pq_prekey_b64.is_some(),
        };

        if let Some(key) = one_time {
            self.store.record_used_one_time_prekey(UsedOneTimePrekey {
                peer_client_id: bundle.client_id.clone(),
                key_id: key.key_id,
                consumed_at: consumed_at.to_string(),
            });
        }

        self.store.save_peer_prekey_bundle(bundle);
        Ok(plan)
    }

    pub fn used_one_time_prekeys(&self, peer_client_id: &str) -> Vec<UsedOneTimePrekey> {
        self.store.used_one_time_prekeys(peer_client_id)
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

#[cfg(test)]
mod tests {
    use crate::protocols::{
        DirectIdentityProfile, LocalBootstrapMaterial, LocalOneTimePrekey, LocalSignedPrekey,
        OneTimePrekey, PeerPrekeyBundle, SignedPrekey,
    };
    use crate::storage::MemorySecretStore;

    use super::BootstrapEngine;

    fn local_identity() -> DirectIdentityProfile {
        DirectIdentityProfile {
            client_id: "anon-a".to_string(),
            encryption_identity_key_b64: "enc-id".to_string(),
            signing_identity_key_b64: "sig-id".to_string(),
            created_at: "2026-03-25T00:00:00Z".to_string(),
        }
    }

    fn bundle() -> PeerPrekeyBundle {
        PeerPrekeyBundle {
            client_id: "anon-b".to_string(),
            signing_identity_key_b64: "peer-sign".to_string(),
            encryption_identity_key_b64: "peer-enc".to_string(),
            signed_prekey: SignedPrekey {
                key_id: 5,
                public_key_b64: "spk".to_string(),
                signature_b64: "spk-sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![
                OneTimePrekey {
                    key_id: 6,
                    public_key_b64: "otp-1".to_string(),
                    created_at: "2026-03-25T00:00:00Z".to_string(),
                },
                OneTimePrekey {
                    key_id: 7,
                    public_key_b64: "otp-2".to_string(),
                    created_at: "2026-03-25T00:00:01Z".to_string(),
                },
            ],
            pq_prekey_b64: Some("pq-prekey".to_string()),
            bundle_signature_b64: "bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        }
    }

    fn local_bootstrap_material() -> LocalBootstrapMaterial {
        LocalBootstrapMaterial {
            profile: local_identity(),
            encryption_identity_private_key_b64: "enc-id-private".to_string(),
            signing_identity_private_key_b64: "sig-id-private".to_string(),
            signed_prekey: LocalSignedPrekey {
                key_id: 9,
                public_key_b64: "local-spk-public".to_string(),
                private_key_b64: "local-spk-private".to_string(),
                signature_b64: "local-spk-sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![LocalOneTimePrekey {
                key_id: 10,
                public_key_b64: "local-otp-public".to_string(),
                private_key_b64: "local-otp-private".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
            }],
            pq_prekey_public_b64: Some("pq-public".to_string()),
            pq_prekey_private_b64: Some("pq-private".to_string()),
            bundle_signature_b64: "bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn stores_local_identity_profile() {
        let mut engine = BootstrapEngine::new(MemorySecretStore::default());
        engine
            .save_local_identity(local_identity())
            .expect("identity should save");

        let saved = engine.local_identity().expect("identity should load");
        assert_eq!(saved.client_id, "anon-a");
    }

    #[test]
    fn stores_local_bootstrap_material_and_builds_public_bundle() {
        let mut engine = BootstrapEngine::new(MemorySecretStore::default());
        engine
            .save_local_bootstrap_material(local_bootstrap_material())
            .expect("local bootstrap material should save");

        let saved = engine
            .local_bootstrap_material()
            .expect("local bootstrap material should load");
        let bundle = engine
            .publish_local_bundle()
            .expect("public bundle should publish");

        assert_eq!(saved.profile.client_id, "anon-a");
        assert_eq!(bundle.client_id, "anon-a");
        assert_eq!(bundle.signed_prekey.key_id, 9);
        assert_eq!(bundle.one_time_prekeys.len(), 1);
    }

    #[test]
    fn reserves_one_time_prekeys_in_order() {
        let mut engine = BootstrapEngine::new(MemorySecretStore::default());
        engine.publish_peer_bundle(bundle()).expect("bundle should save");

        let first = engine
            .prepare_outbound_bootstrap("anon-b", "2026-03-25T00:10:00Z")
            .expect("first bootstrap should succeed");
        let second = engine
            .prepare_outbound_bootstrap("anon-b", "2026-03-25T00:11:00Z")
            .expect("second bootstrap should succeed");
        let third = engine
            .prepare_outbound_bootstrap("anon-b", "2026-03-25T00:12:00Z")
            .expect("third bootstrap should succeed");

        assert_eq!(first.peer_one_time_prekey_id, Some(6));
        assert_eq!(second.peer_one_time_prekey_id, Some(7));
        assert_eq!(third.peer_one_time_prekey_id, None);
        assert_eq!(engine.used_one_time_prekeys("anon-b").len(), 2);
    }
}
