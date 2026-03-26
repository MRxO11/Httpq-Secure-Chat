use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::httpq::RelayPin;
use crate::kt::WitnessCheckpoint;
use crate::protocols::{
    DirectIdentityProfile, DirectRatchetState, DirectSession, GroupState, LocalBootstrapMaterial,
    PeerPrekeyBundle, UsedOneTimePrekey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRelayPin {
    pub relay_id: String,
    pub realm: String,
    pub public_key_b64: String,
}

impl From<RelayPin> for StoredRelayPin {
    fn from(value: RelayPin) -> Self {
        Self {
            relay_id: value.relay_id,
            realm: value.realm,
            public_key_b64: value.public_key_b64,
        }
    }
}

impl From<StoredRelayPin> for RelayPin {
    fn from(value: StoredRelayPin) -> Self {
        Self {
            relay_id: value.relay_id,
            realm: value.realm,
            public_key_b64: value.public_key_b64,
        }
    }
}

pub trait SecretStore {
    fn load_relay_pin(&self, relay_id: &str) -> Option<StoredRelayPin>;
    fn save_relay_pin(&mut self, pin: StoredRelayPin);
    fn load_witness_checkpoint(&self, log_id: &str) -> Option<WitnessCheckpoint>;
    fn save_witness_checkpoint(&mut self, checkpoint: WitnessCheckpoint);
    fn load_direct_identity_profile(&self) -> Option<DirectIdentityProfile>;
    fn save_direct_identity_profile(&mut self, profile: DirectIdentityProfile);
    fn load_local_bootstrap_material(&self) -> Option<LocalBootstrapMaterial>;
    fn save_local_bootstrap_material(&mut self, material: LocalBootstrapMaterial);
    fn load_peer_prekey_bundle(&self, peer_client_id: &str) -> Option<PeerPrekeyBundle>;
    fn save_peer_prekey_bundle(&mut self, bundle: PeerPrekeyBundle);
    fn record_used_one_time_prekey(&mut self, used: UsedOneTimePrekey);
    fn used_one_time_prekeys(&self, peer_client_id: &str) -> Vec<UsedOneTimePrekey>;
    fn load_direct_session(&self, peer_client_id: &str) -> Option<DirectSession>;
    fn save_direct_session(&mut self, session: DirectSession);
    fn load_direct_ratchet_state(&self, peer_client_id: &str) -> Option<DirectRatchetState>;
    fn save_direct_ratchet_state(&mut self, state: DirectRatchetState);
    fn load_group_state(&self, room_id: &str) -> Option<GroupState>;
    fn save_group_state(&mut self, state: GroupState);
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SecretStoreData {
    relay_pins: HashMap<String, StoredRelayPin>,
    witness_checkpoints: HashMap<String, WitnessCheckpoint>,
    direct_identity_profile: Option<DirectIdentityProfile>,
    local_bootstrap_material: Option<LocalBootstrapMaterial>,
    peer_prekey_bundles: HashMap<String, PeerPrekeyBundle>,
    used_one_time_prekeys: HashMap<String, Vec<UsedOneTimePrekey>>,
    direct_sessions: HashMap<String, DirectSession>,
    direct_ratchets: HashMap<String, DirectRatchetState>,
    group_states: HashMap<String, GroupState>,
}

#[derive(Debug, Default, Clone)]
pub struct MemorySecretStore {
    data: SecretStoreData,
}

impl SecretStore for MemorySecretStore {
    fn load_relay_pin(&self, relay_id: &str) -> Option<StoredRelayPin> {
        self.data.relay_pins.get(relay_id).cloned()
    }

    fn save_relay_pin(&mut self, pin: StoredRelayPin) {
        self.data.relay_pins.insert(pin.relay_id.clone(), pin);
    }

    fn load_witness_checkpoint(&self, log_id: &str) -> Option<WitnessCheckpoint> {
        self.data.witness_checkpoints.get(log_id).cloned()
    }

    fn save_witness_checkpoint(&mut self, checkpoint: WitnessCheckpoint) {
        self.data
            .witness_checkpoints
            .insert(checkpoint.log_id.clone(), checkpoint);
    }

    fn load_direct_identity_profile(&self) -> Option<DirectIdentityProfile> {
        self.data.direct_identity_profile.clone()
    }

    fn save_direct_identity_profile(&mut self, profile: DirectIdentityProfile) {
        self.data.direct_identity_profile = Some(profile);
    }

    fn load_local_bootstrap_material(&self) -> Option<LocalBootstrapMaterial> {
        self.data.local_bootstrap_material.clone()
    }

    fn save_local_bootstrap_material(&mut self, material: LocalBootstrapMaterial) {
        self.data.local_bootstrap_material = Some(material);
    }

    fn load_peer_prekey_bundle(&self, peer_client_id: &str) -> Option<PeerPrekeyBundle> {
        self.data.peer_prekey_bundles.get(peer_client_id).cloned()
    }

    fn save_peer_prekey_bundle(&mut self, bundle: PeerPrekeyBundle) {
        self.data
            .peer_prekey_bundles
            .insert(bundle.client_id.clone(), bundle);
    }

    fn record_used_one_time_prekey(&mut self, used: UsedOneTimePrekey) {
        self.data
            .used_one_time_prekeys
            .entry(used.peer_client_id.clone())
            .or_default()
            .push(used);
    }

    fn used_one_time_prekeys(&self, peer_client_id: &str) -> Vec<UsedOneTimePrekey> {
        self.data
            .used_one_time_prekeys
            .get(peer_client_id)
            .cloned()
            .unwrap_or_default()
    }

    fn load_direct_session(&self, peer_client_id: &str) -> Option<DirectSession> {
        self.data.direct_sessions.get(peer_client_id).cloned()
    }

    fn save_direct_session(&mut self, session: DirectSession) {
        self.data
            .direct_sessions
            .insert(session.peer_client_id.clone(), session);
    }

    fn load_direct_ratchet_state(&self, peer_client_id: &str) -> Option<DirectRatchetState> {
        self.data.direct_ratchets.get(peer_client_id).cloned()
    }

    fn save_direct_ratchet_state(&mut self, state: DirectRatchetState) {
        self.data
            .direct_ratchets
            .insert(state.peer_client_id.clone(), state);
    }

    fn load_group_state(&self, room_id: &str) -> Option<GroupState> {
        self.data.group_states.get(room_id).cloned()
    }

    fn save_group_state(&mut self, state: GroupState) {
        self.data.group_states.insert(state.room_id.clone(), state);
    }
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("failed to read secret store file: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to create secret store directory: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("failed to serialize secret store: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("failed to deserialize secret store: {0}")]
    Deserialize(#[source] serde_json::Error),
    #[error("failed to write secret store file: {0}")]
    Write(#[source] std::io::Error),
    #[error("failed to replace secret store file: {0}")]
    Replace(#[source] std::io::Error),
    #[error("platform secret protection failed: {0}")]
    Protect(String),
    #[error("platform secret unprotection failed: {0}")]
    Unprotect(String),
}

#[derive(Debug, Clone)]
pub struct EncryptedFileSecretStore {
    path: PathBuf,
    data: SecretStoreData,
}

impl EncryptedFileSecretStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SecretStoreError> {
        let path = path.into();
        let data = if path.exists() {
            let ciphertext = fs::read(&path).map_err(SecretStoreError::Read)?;
            let plaintext = platform::unprotect_bytes(&ciphertext)?;
            serde_json::from_slice(&plaintext).map_err(SecretStoreError::Deserialize)?
        } else {
            SecretStoreData::default()
        };
        Ok(Self { path, data })
    }

    pub fn flush(&self) -> Result<(), SecretStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(SecretStoreError::CreateDir)?;
        }

        let plaintext = serde_json::to_vec_pretty(&self.data).map_err(SecretStoreError::Serialize)?;
        let ciphertext = platform::protect_bytes(&plaintext)?;

        let tmp_path = self.temporary_path();
        fs::write(&tmp_path, ciphertext).map_err(SecretStoreError::Write)?;
        fs::rename(&tmp_path, &self.path).map_err(SecretStoreError::Replace)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn temporary_path(&self) -> PathBuf {
        let mut tmp = self.path.clone();
        let ext = self
            .path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("dat");
        tmp.set_extension(format!("{ext}.tmp"));
        tmp
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn load_relay_pin(&self, relay_id: &str) -> Option<StoredRelayPin> {
        self.data.relay_pins.get(relay_id).cloned()
    }

    fn save_relay_pin(&mut self, pin: StoredRelayPin) {
        self.data.relay_pins.insert(pin.relay_id.clone(), pin);
    }

    fn load_witness_checkpoint(&self, log_id: &str) -> Option<WitnessCheckpoint> {
        self.data.witness_checkpoints.get(log_id).cloned()
    }

    fn save_witness_checkpoint(&mut self, checkpoint: WitnessCheckpoint) {
        self.data
            .witness_checkpoints
            .insert(checkpoint.log_id.clone(), checkpoint);
    }

    fn load_direct_identity_profile(&self) -> Option<DirectIdentityProfile> {
        self.data.direct_identity_profile.clone()
    }

    fn save_direct_identity_profile(&mut self, profile: DirectIdentityProfile) {
        self.data.direct_identity_profile = Some(profile);
    }

    fn load_local_bootstrap_material(&self) -> Option<LocalBootstrapMaterial> {
        self.data.local_bootstrap_material.clone()
    }

    fn save_local_bootstrap_material(&mut self, material: LocalBootstrapMaterial) {
        self.data.local_bootstrap_material = Some(material);
    }

    fn load_peer_prekey_bundle(&self, peer_client_id: &str) -> Option<PeerPrekeyBundle> {
        self.data.peer_prekey_bundles.get(peer_client_id).cloned()
    }

    fn save_peer_prekey_bundle(&mut self, bundle: PeerPrekeyBundle) {
        self.data
            .peer_prekey_bundles
            .insert(bundle.client_id.clone(), bundle);
    }

    fn record_used_one_time_prekey(&mut self, used: UsedOneTimePrekey) {
        self.data
            .used_one_time_prekeys
            .entry(used.peer_client_id.clone())
            .or_default()
            .push(used);
    }

    fn used_one_time_prekeys(&self, peer_client_id: &str) -> Vec<UsedOneTimePrekey> {
        self.data
            .used_one_time_prekeys
            .get(peer_client_id)
            .cloned()
            .unwrap_or_default()
    }

    fn load_direct_session(&self, peer_client_id: &str) -> Option<DirectSession> {
        self.data.direct_sessions.get(peer_client_id).cloned()
    }

    fn save_direct_session(&mut self, session: DirectSession) {
        self.data
            .direct_sessions
            .insert(session.peer_client_id.clone(), session);
    }

    fn load_direct_ratchet_state(&self, peer_client_id: &str) -> Option<DirectRatchetState> {
        self.data.direct_ratchets.get(peer_client_id).cloned()
    }

    fn save_direct_ratchet_state(&mut self, state: DirectRatchetState) {
        self.data
            .direct_ratchets
            .insert(state.peer_client_id.clone(), state);
    }

    fn load_group_state(&self, room_id: &str) -> Option<GroupState> {
        self.data.group_states.get(room_id).cloned()
    }

    fn save_group_state(&mut self, state: GroupState) {
        self.data.group_states.insert(state.room_id.clone(), state);
    }
}

#[cfg(windows)]
mod platform {
    use std::ptr;
    use std::slice;

    use super::SecretStoreError;

    type Dword = u32;
    type Bool = i32;
    type Lpcwstr = *const u16;

    #[repr(C)]
    struct DataBlob {
        cb_data: Dword,
        pb_data: *mut u8,
    }

    #[link(name = "Crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: Lpcwstr,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *mut core::ffi::c_void,
            dw_flags: Dword,
            p_data_out: *mut DataBlob,
        ) -> Bool;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut Lpcwstr,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *mut core::ffi::c_void,
            dw_flags: Dword,
            p_data_out: *mut DataBlob,
        ) -> Bool;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    pub fn protect_bytes(plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let mut input = DataBlob {
            cb_data: plaintext.len() as Dword,
            pb_data: plaintext.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &mut input,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretStoreError::Protect(
                "CryptProtectData returned failure".to_string(),
            ));
        }

        let bytes = unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            LocalFree(output.pb_data as *mut core::ffi::c_void);
        }
        Ok(bytes)
    }

    pub fn unprotect_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let mut input = DataBlob {
            cb_data: ciphertext.len() as Dword,
            pb_data: ciphertext.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretStoreError::Unprotect(
                "CryptUnprotectData returned failure".to_string(),
            ));
        }

        let bytes = unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            LocalFree(output.pb_data as *mut core::ffi::c_void);
        }
        Ok(bytes)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SecretStoreError;

    pub fn protect_bytes(_plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        Err(SecretStoreError::Protect(
            "encrypted file secret store currently requires Windows DPAPI".to_string(),
        ))
    }

    pub fn unprotect_bytes(_ciphertext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        Err(SecretStoreError::Unprotect(
            "encrypted file secret store currently requires Windows DPAPI".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{EncryptedFileSecretStore, SecretStore, StoredRelayPin};
    use crate::kt::WitnessCheckpoint;

    fn unique_temp_path(file_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("secure-chat-{nanos}-{file_name}"))
    }

    use std::path::PathBuf;

    #[cfg(windows)]
    #[test]
    fn encrypted_file_secret_store_round_trips_protected_data() {
        let path = unique_temp_path("secrets.json");
        let mut store = EncryptedFileSecretStore::open(&path).expect("store should open");
        store.save_relay_pin(StoredRelayPin {
            relay_id: "relay-local".to_string(),
            realm: "secure-chat".to_string(),
            public_key_b64: "public-key".to_string(),
        });
        store.save_witness_checkpoint(WitnessCheckpoint {
            log_id: "http://127.0.0.1:8081".to_string(),
            tree_size: 4,
            root_hash_b64: "root-hash".to_string(),
            signing_public_key_b64: "kt-key".to_string(),
            witness_public_key_b64: "witness-key".to_string(),
            witness_signature_b64: "witness-signature".to_string(),
        });
        store.flush().expect("store should flush");

        let ciphertext = std::fs::read(&path).expect("ciphertext file should exist");
        let file_text = String::from_utf8_lossy(&ciphertext);
        assert!(!file_text.contains("relay-local"));
        assert!(!file_text.contains("public-key"));

        let reloaded = EncryptedFileSecretStore::open(&path).expect("store should reopen");
        let relay_pin = reloaded
            .load_relay_pin("relay-local")
            .expect("relay pin should round trip");
        let checkpoint = reloaded
            .load_witness_checkpoint("http://127.0.0.1:8081")
            .expect("checkpoint should round trip");

        assert_eq!(relay_pin.realm, "secure-chat");
        assert_eq!(checkpoint.tree_size, 4);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(windows))]
    #[test]
    fn encrypted_file_secret_store_requires_windows_dpapi() {
        let path = unique_temp_path("secrets.json");
        let mut store = EncryptedFileSecretStore::open(&path).expect("store should open");
        store.save_relay_pin(StoredRelayPin {
            relay_id: "relay-local".to_string(),
            realm: "secure-chat".to_string(),
            public_key_b64: "public-key".to_string(),
        });

        let error = store.flush().expect_err("non-windows flush should fail");
        assert!(error
            .to_string()
            .contains("Windows DPAPI"));
    }
}
