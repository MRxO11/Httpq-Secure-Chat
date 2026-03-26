use base64::Engine;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::protocols::{
    GroupApplicationMessage, GroupCommitMessage, GroupControlMessage, GroupMemberCredential,
    GroupMode, GroupProposalMessage, GroupState, GroupWelcomeMessage,
};
use crate::storage::SecretStore;
use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub room_id: String,
    pub mode: GroupMode,
    pub epoch: u64,
    pub epoch_key_ref: Option<String>,
    pub epoch_secret_ref: Option<String>,
    pub commit_secret_ref: Option<String>,
    pub welcome_secret_ref: Option<String>,
    pub application_secret_ref: Option<String>,
    pub local_member_client_id: Option<String>,
    pub members: Vec<GroupMemberCredential>,
    pub pending_commit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableGroupSnapshot {
    pub room_id: String,
    pub mode: String,
    pub epoch: u64,
    pub epoch_key_ref: Option<String>,
    pub epoch_secret_ref: Option<String>,
    pub commit_secret_ref: Option<String>,
    pub welcome_secret_ref: Option<String>,
    pub application_secret_ref: Option<String>,
    pub local_member_client_id: Option<String>,
    pub member_count: usize,
    pub pending_commit: bool,
}

impl PortableGroupSnapshot {
    fn mode_label(mode: GroupMode) -> &'static str {
        match mode {
            GroupMode::Placeholder => "room-aes-256-gcm+scrypt",
            GroupMode::Mls => "mls-placeholder",
        }
    }
}

impl From<GroupSnapshot> for PortableGroupSnapshot {
    fn from(value: GroupSnapshot) -> Self {
        Self {
            room_id: value.room_id,
            mode: Self::mode_label(value.mode).to_string(),
            epoch: value.epoch,
            epoch_key_ref: value.epoch_key_ref,
            epoch_secret_ref: value.epoch_secret_ref,
            commit_secret_ref: value.commit_secret_ref,
            welcome_secret_ref: value.welcome_secret_ref,
            application_secret_ref: value.application_secret_ref,
            local_member_client_id: value.local_member_client_id,
            member_count: value.members.len(),
            pending_commit: value.pending_commit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundGroupEvent {
    pub room_id: String,
    pub epoch: u64,
    pub mode: GroupMode,
    pub epoch_key_ref: Option<String>,
    pub epoch_secret_ref: Option<String>,
    pub commit_secret_ref: Option<String>,
    pub welcome_secret_ref: Option<String>,
    pub application_secret_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundGroupControlEvent {
    pub room_id: String,
    pub message_type: String,
    pub mode: GroupMode,
    pub epoch: u64,
    pub epoch_key_ref: Option<String>,
    pub epoch_secret_ref: Option<String>,
    pub commit_secret_ref: Option<String>,
    pub welcome_secret_ref: Option<String>,
    pub application_secret_ref: Option<String>,
    pub payload: GroupControlMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableOutboundGroupControlEvent {
    pub room_id: String,
    pub message_type: String,
    pub mode: String,
    pub epoch: u64,
    pub epoch_key_ref: Option<String>,
    pub epoch_secret_ref: Option<String>,
    pub commit_secret_ref: Option<String>,
    pub welcome_secret_ref: Option<String>,
    pub application_secret_ref: Option<String>,
}

impl From<OutboundGroupControlEvent> for PortableOutboundGroupControlEvent {
    fn from(value: OutboundGroupControlEvent) -> Self {
        Self {
            room_id: value.room_id,
            message_type: value.message_type,
            mode: PortableGroupSnapshot::mode_label(value.mode).to_string(),
            epoch: value.epoch,
            epoch_key_ref: value.epoch_key_ref,
            epoch_secret_ref: value.epoch_secret_ref,
            commit_secret_ref: value.commit_secret_ref,
            welcome_secret_ref: value.welcome_secret_ref,
            application_secret_ref: value.application_secret_ref,
        }
    }
}

#[derive(Debug, Default)]
pub struct GroupEngine<S> {
    store: S,
}

impl<S> GroupEngine<S>
where
    S: SecretStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn ensure_group(
        &mut self,
        room_id: &str,
        local_member_client_id: Option<&str>,
        mode: GroupMode,
    ) -> Result<GroupSnapshot> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        state.local_member_client_id = local_member_client_id.map(str::to_string);
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());
        Ok(snapshot_from_state(state))
    }

    pub fn upsert_member(
        &mut self,
        room_id: &str,
        member: GroupMemberCredential,
        mode: GroupMode,
    ) -> Result<GroupSnapshot> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        state.upsert_member(member)?;
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());
        Ok(snapshot_from_state(state))
    }

    pub fn remove_member(&mut self, room_id: &str, client_id: &str) -> Result<GroupSnapshot> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, GroupMode::Placeholder));
        state.remove_member(client_id);
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());
        Ok(snapshot_from_state(state))
    }

    pub fn advance_epoch(
        &mut self,
        room_id: &str,
        mode: GroupMode,
        epoch_key_ref: &str,
    ) -> Result<GroupSnapshot> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        state.advance_epoch(epoch_key_ref.to_string());
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());
        Ok(snapshot_from_state(state))
    }

    pub fn prepare_proposal(
        &mut self,
        room_id: &str,
        sender_client_id: &str,
        proposal_id: &str,
        proposal_kind: &str,
        target_client_id: Option<&str>,
        mode: GroupMode,
    ) -> Result<OutboundGroupControlEvent> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        state.pending_commit = true;
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());

        let payload = GroupControlMessage::Proposal(GroupProposalMessage {
            room_id: room_id.to_string(),
            proposal_id: proposal_id.to_string(),
            proposal_kind: proposal_kind.to_string(),
            sender_client_id: sender_client_id.to_string(),
            target_client_id: target_client_id.map(str::to_string),
            mode,
        });
        payload.validate()?;
        Ok(control_event_from_state(
            state,
            "RoomProposal",
            payload,
        ))
    }

    pub fn prepare_commit(
        &mut self,
        room_id: &str,
        sender_client_id: &str,
        mode: GroupMode,
        epoch_key_ref: &str,
        proposal_ids: Vec<String>,
    ) -> Result<OutboundGroupControlEvent> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        state.advance_epoch(epoch_key_ref.to_string());
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        self.store.save_group_state(state.clone());

        let payload = GroupControlMessage::Commit(GroupCommitMessage {
            room_id: room_id.to_string(),
            epoch: state.epoch,
            epoch_key_ref: epoch_key_ref.to_string(),
            sender_client_id: sender_client_id.to_string(),
            mode,
            proposal_ids,
        });
        payload.validate()?;
        Ok(control_event_from_state(state, "RoomCommit", payload))
    }

    pub fn prepare_welcome(
        &mut self,
        room_id: &str,
        sender_client_id: &str,
        recipient_client_id: &str,
        mode: GroupMode,
    ) -> Result<OutboundGroupControlEvent> {
        let mut state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, mode));
        state.mode = mode;
        ensure_group_secret_refs(&mut state);
        state.validate()?;
        let epoch_key_ref = state.epoch_key_ref.clone().ok_or_else(|| {
            crate::ClientCoreError::State(
                "group welcome requires an epoch_key_ref".to_string(),
            )
        })?;
        self.store.save_group_state(state.clone());

        let payload = GroupControlMessage::Welcome(GroupWelcomeMessage {
            room_id: room_id.to_string(),
            epoch: state.epoch,
            epoch_key_ref,
            sender_client_id: sender_client_id.to_string(),
            recipient_client_id: recipient_client_id.to_string(),
            mode,
        });
        payload.validate()?;
        Ok(control_event_from_state(state, "RoomWelcome", payload))
    }

    pub fn apply_control(&mut self, payload: GroupControlMessage) -> Result<GroupSnapshot> {
        payload.validate()?;
        match payload {
            GroupControlMessage::Proposal(message) => {
                let mut state = self
                    .store
                    .load_group_state(&message.room_id)
                    .unwrap_or_else(|| GroupState::new(&message.room_id, message.mode));
                state.mode = message.mode;
                state.pending_commit = true;
                ensure_group_secret_refs(&mut state);
                state.validate()?;
                self.store.save_group_state(state.clone());
                Ok(snapshot_from_state(state))
            }
            GroupControlMessage::Commit(message) => {
                let mut state = self
                    .store
                    .load_group_state(&message.room_id)
                    .unwrap_or_else(|| GroupState::new(&message.room_id, message.mode));
                validate_inbound_epoch_transition(
                    &state,
                    message.epoch,
                    &message.epoch_key_ref,
                    message.mode,
                )?;
                if message.epoch > state.epoch {
                    state.mode = message.mode;
                    state.epoch = message.epoch;
                    state.epoch_key_ref = Some(message.epoch_key_ref.clone());
                    state.epoch_secret_ref = None;
                    state.commit_secret_ref = None;
                    state.welcome_secret_ref = None;
                    state.application_secret_ref = None;
                    state.pending_commit = false;
                }
                ensure_group_secret_refs(&mut state);
                state.validate()?;
                self.store.save_group_state(state.clone());
                Ok(snapshot_from_state(state))
            }
            GroupControlMessage::Welcome(message) => {
                let mut state = self
                    .store
                    .load_group_state(&message.room_id)
                    .unwrap_or_else(|| GroupState::new(&message.room_id, message.mode));
                validate_inbound_epoch_transition(
                    &state,
                    message.epoch,
                    &message.epoch_key_ref,
                    message.mode,
                )?;
                if message.epoch > state.epoch {
                    state.mode = message.mode;
                    state.epoch = message.epoch;
                    state.epoch_key_ref = Some(message.epoch_key_ref.clone());
                    state.epoch_secret_ref = None;
                    state.commit_secret_ref = None;
                    state.welcome_secret_ref = None;
                    state.application_secret_ref = None;
                    state.pending_commit = false;
                }
                ensure_group_secret_refs(&mut state);
                state.validate()?;
                self.store.save_group_state(state.clone());
                Ok(snapshot_from_state(state))
            }
        }
    }

    pub fn prepare_outbound(
        &mut self,
        room_id: &str,
        sender_client_id: &str,
        ciphertext: &str,
    ) -> Result<OutboundGroupEvent> {
        let state = self
            .store
            .load_group_state(room_id)
            .unwrap_or_else(|| GroupState::new(room_id, GroupMode::Placeholder));
        let message = GroupApplicationMessage {
            room_id: room_id.to_string(),
            epoch: state.epoch,
            sender_client_id: sender_client_id.to_string(),
            ciphertext: ciphertext.to_string(),
        };
        message.validate()?;
        Ok(OutboundGroupEvent {
            room_id: room_id.to_string(),
            epoch: state.epoch,
            mode: state.mode,
            epoch_key_ref: state.epoch_key_ref,
            epoch_secret_ref: state.epoch_secret_ref,
            commit_secret_ref: state.commit_secret_ref,
            welcome_secret_ref: state.welcome_secret_ref,
            application_secret_ref: state.application_secret_ref,
        })
    }

    pub fn snapshot(&self, room_id: &str) -> Option<GroupSnapshot> {
        self.store
            .load_group_state(room_id)
            .map(snapshot_from_state)
    }
}

fn control_event_from_state(
    state: GroupState,
    message_type: &str,
    payload: GroupControlMessage,
) -> OutboundGroupControlEvent {
    OutboundGroupControlEvent {
        room_id: state.room_id.clone(),
        message_type: message_type.to_string(),
        mode: state.mode,
        epoch: state.epoch,
        epoch_key_ref: state.epoch_key_ref.clone(),
        epoch_secret_ref: state.epoch_secret_ref.clone(),
        commit_secret_ref: state.commit_secret_ref.clone(),
        welcome_secret_ref: state.welcome_secret_ref.clone(),
        application_secret_ref: state.application_secret_ref.clone(),
        payload,
    }
}

fn validate_inbound_epoch_transition(
    state: &GroupState,
    epoch: u64,
    epoch_key_ref: &str,
    mode: GroupMode,
) -> Result<()> {
    if epoch == state.epoch
        && state.epoch_key_ref.as_deref().is_some()
        && (state.epoch_key_ref.as_deref() != Some(epoch_key_ref) || state.mode != mode)
    {
        return Err(ClientCoreError::State(
            "conflicting room epoch update for current epoch".to_string(),
        ));
    }
    Ok(())
}

fn snapshot_from_state(state: GroupState) -> GroupSnapshot {
    GroupSnapshot {
        room_id: state.room_id,
        mode: state.mode,
        epoch: state.epoch,
        epoch_key_ref: state.epoch_key_ref,
        epoch_secret_ref: state.epoch_secret_ref,
        commit_secret_ref: state.commit_secret_ref,
        welcome_secret_ref: state.welcome_secret_ref,
        application_secret_ref: state.application_secret_ref,
        local_member_client_id: state.local_member_client_id,
        members: state.members,
        pending_commit: state.pending_commit,
    }
}

fn ensure_group_secret_refs(state: &mut GroupState) {
    if state.epoch == 0 {
        state.epoch_secret_ref = None;
        state.commit_secret_ref = None;
        state.welcome_secret_ref = None;
        state.application_secret_ref = None;
        return;
    }
    let Some(epoch_key_ref) = state.epoch_key_ref.as_deref() else {
        return;
    };
    let epoch_secret_ref = state.epoch_secret_ref.clone().unwrap_or_else(|| {
        derive_epoch_secret_ref(&state.room_id, epoch_key_ref, state.epoch, state.mode)
    });
    let commit_secret_ref = state.commit_secret_ref.clone().unwrap_or_else(|| {
        derive_commit_secret_ref(
            &state.room_id,
            &epoch_secret_ref,
            epoch_key_ref,
            state.epoch,
            state.mode,
        )
    });
    let welcome_secret_ref = state.welcome_secret_ref.clone().unwrap_or_else(|| {
        derive_welcome_secret_ref(
            &state.room_id,
            &commit_secret_ref,
            state.epoch,
            state.mode,
        )
    });
    let application_secret_ref = state.application_secret_ref.clone().unwrap_or_else(|| {
        derive_application_secret_ref(
            &state.room_id,
            &welcome_secret_ref,
            state.epoch,
            state.mode,
        )
    });
    state.epoch_secret_ref = Some(epoch_secret_ref);
    state.commit_secret_ref = Some(commit_secret_ref);
    state.welcome_secret_ref = Some(welcome_secret_ref);
    state.application_secret_ref = Some(application_secret_ref);
}

fn derive_epoch_secret_ref(
    room_id: &str,
    epoch_key_ref: &str,
    epoch: u64,
    mode: GroupMode,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"group-epoch-secret/v1");
    hasher.update(room_id.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch_key_ref.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(match mode {
        GroupMode::Placeholder => b"placeholder".as_slice(),
        GroupMode::Mls => b"mls".as_slice(),
    });
    format!(
        "ges::{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    )
}

fn derive_commit_secret_ref(
    room_id: &str,
    epoch_secret_ref: &str,
    epoch_key_ref: &str,
    epoch: u64,
    mode: GroupMode,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"group-commit-secret/v1");
    hasher.update(room_id.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch_secret_ref.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch_key_ref.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(match mode {
        GroupMode::Placeholder => b"placeholder".as_slice(),
        GroupMode::Mls => b"mls".as_slice(),
    });
    format!(
        "gcs::{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    )
}

fn derive_welcome_secret_ref(
    room_id: &str,
    commit_secret_ref: &str,
    epoch: u64,
    mode: GroupMode,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"group-welcome-secret/v1");
    hasher.update(room_id.as_bytes());
    hasher.update(b"|");
    hasher.update(commit_secret_ref.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(match mode {
        GroupMode::Placeholder => b"placeholder".as_slice(),
        GroupMode::Mls => b"mls".as_slice(),
    });
    format!(
        "gws::{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    )
}

fn derive_application_secret_ref(
    room_id: &str,
    welcome_secret_ref: &str,
    epoch: u64,
    mode: GroupMode,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"group-application-secret/v1");
    hasher.update(room_id.as_bytes());
    hasher.update(b"|");
    hasher.update(welcome_secret_ref.as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(match mode {
        GroupMode::Placeholder => b"placeholder".as_slice(),
        GroupMode::Mls => b"mls".as_slice(),
    });
    format!(
        "gas::{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    )
}

#[cfg(test)]
mod tests {
    use crate::engine::{GroupEngine, PortableGroupSnapshot, PortableOutboundGroupControlEvent};
    use crate::protocols::{
        GroupCommitMessage, GroupControlMessage, GroupMemberCredential, GroupMode,
    };
    use crate::storage::MemorySecretStore;

    #[test]
    fn group_engine_tracks_members_and_epoch() {
        let store = MemorySecretStore::default();
        let mut engine = GroupEngine::new(store);

        engine
            .ensure_group("lobby", Some("peer-a"), GroupMode::Mls)
            .expect("group should initialize");
        engine
            .upsert_member(
                "lobby",
                GroupMemberCredential {
                    client_id: "peer-a".to_string(),
                    username: "alice".to_string(),
                    signing_key_b64: Some("sig-a".to_string()),
                },
                GroupMode::Mls,
            )
            .expect("member should upsert");
        let snapshot = engine
            .advance_epoch("lobby", GroupMode::Mls, "mls-epoch::1")
            .expect("epoch should advance");

        assert_eq!(snapshot.epoch, 1);
        assert!(snapshot
            .epoch_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ges::")));
        assert!(snapshot
            .commit_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gcs::")));
        assert!(snapshot
            .welcome_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gws::")));
        assert!(snapshot
            .application_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gas::")));
        assert_eq!(snapshot.local_member_client_id.as_deref(), Some("peer-a"));
        assert_eq!(snapshot.members.len(), 1);

        let portable = PortableGroupSnapshot::from(snapshot);
        assert_eq!(portable.mode, "mls-placeholder");
        assert_eq!(portable.member_count, 1);
        assert!(portable
            .epoch_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ges::")));
        assert!(portable
            .commit_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gcs::")));
        assert!(portable
            .welcome_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gws::")));
        assert!(portable
            .application_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gas::")));
    }

    #[test]
    fn outbound_group_event_carries_epoch_secret_ref() {
        let store = MemorySecretStore::default();
        let mut engine = GroupEngine::new(store);

        engine
            .advance_epoch("lobby", GroupMode::Mls, "mls-epoch::1")
            .expect("epoch should advance");
        let outbound = engine
            .prepare_outbound("lobby", "peer-a", "ciphertext")
            .expect("outbound should succeed");

        assert_eq!(outbound.epoch, 1);
        assert!(outbound
            .epoch_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ges::")));
        assert!(outbound
            .commit_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gcs::")));
        assert!(outbound
            .welcome_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gws::")));
        assert!(outbound
            .application_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gas::")));
    }

    #[test]
    fn prepare_commit_and_welcome_carry_portable_secret_material() {
        let store = MemorySecretStore::default();
        let mut engine = GroupEngine::new(store);

        let commit = engine
            .prepare_commit(
                "lobby",
                "peer-a",
                GroupMode::Mls,
                "mls-epoch::1",
                vec!["proposal-1".to_string()],
            )
            .expect("commit should succeed");
        let portable_commit = PortableOutboundGroupControlEvent::from(commit.clone());

        assert_eq!(portable_commit.message_type, "RoomCommit");
        assert!(portable_commit
            .epoch_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ges::")));
        assert!(portable_commit
            .commit_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gcs::")));
        assert!(portable_commit
            .application_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gas::")));
        assert!(matches!(commit.payload, GroupControlMessage::Commit(_)));

        let welcome = engine
            .prepare_welcome("lobby", "peer-a", "peer-b", GroupMode::Mls)
            .expect("welcome should succeed");
        let portable_welcome = PortableOutboundGroupControlEvent::from(welcome.clone());

        assert_eq!(portable_welcome.message_type, "RoomWelcome");
        assert!(portable_welcome
            .welcome_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gws::")));
        assert!(portable_welcome
            .application_secret_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("gas::")));
        assert!(matches!(welcome.payload, GroupControlMessage::Welcome(_)));
    }

    #[test]
    fn member_updates_do_not_rekey_existing_epoch() {
        let store = MemorySecretStore::default();
        let mut engine = GroupEngine::new(store);

        let before = engine
            .advance_epoch("lobby", GroupMode::Mls, "mls-epoch::1")
            .expect("epoch should advance");
        let before_app = before.application_secret_ref.clone();

        let after = engine
            .upsert_member(
                "lobby",
                GroupMemberCredential {
                    client_id: "peer-a".to_string(),
                    username: "alice".to_string(),
                    signing_key_b64: Some("sig-a".to_string()),
                },
                GroupMode::Mls,
            )
            .expect("member update should succeed");

        assert_eq!(after.application_secret_ref, before_app);
    }

    #[test]
    fn conflicting_same_epoch_commit_is_rejected() {
        let store = MemorySecretStore::default();
        let mut engine = GroupEngine::new(store);

        engine
            .apply_control(GroupControlMessage::Commit(GroupCommitMessage {
                room_id: "lobby".to_string(),
                epoch: 1,
                epoch_key_ref: "mls-epoch::1".to_string(),
                sender_client_id: "peer-a".to_string(),
                mode: GroupMode::Mls,
                proposal_ids: vec![],
            }))
            .expect("first commit should apply");

        let error = engine
            .apply_control(GroupControlMessage::Commit(GroupCommitMessage {
                room_id: "lobby".to_string(),
                epoch: 1,
                epoch_key_ref: "mls-epoch::forged".to_string(),
                sender_client_id: "peer-a".to_string(),
                mode: GroupMode::Mls,
                proposal_ids: vec![],
            }))
            .expect_err("conflicting same-epoch commit should be rejected");

        assert!(error
            .to_string()
            .contains("conflicting room epoch update"));
    }
}
