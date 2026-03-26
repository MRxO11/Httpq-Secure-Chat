use serde::{Deserialize, Serialize};

use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupMode {
    Placeholder,
    Mls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMemberCredential {
    pub client_id: String,
    pub username: String,
    pub signing_key_b64: Option<String>,
}

impl GroupMemberCredential {
    pub fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group member credential is missing client_id".to_string(),
            ));
        }

        if self.username.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group member credential is missing username".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState {
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

impl GroupState {
    pub fn new(room_id: impl Into<String>, mode: GroupMode) -> Self {
        Self {
            room_id: room_id.into(),
            mode,
            epoch: 0,
            epoch_key_ref: None,
            epoch_secret_ref: None,
            commit_secret_ref: None,
            welcome_secret_ref: None,
            application_secret_ref: None,
            local_member_client_id: None,
            members: Vec::new(),
            pending_commit: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group state is missing room_id".to_string(),
            ));
        }

        for member in &self.members {
            member.validate()?;
        }

        Ok(())
    }

    pub fn upsert_member(&mut self, member: GroupMemberCredential) -> Result<()> {
        member.validate()?;
        if let Some(existing) = self
            .members
            .iter_mut()
            .find(|existing| existing.client_id == member.client_id)
        {
            *existing = member;
        } else {
            self.members.push(member);
        }
        self.members.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        Ok(())
    }

    pub fn remove_member(&mut self, client_id: &str) -> bool {
        let before = self.members.len();
        self.members.retain(|member| member.client_id != client_id);
        before != self.members.len()
    }

    pub fn advance_epoch(&mut self, epoch_key_ref: impl Into<String>) {
        self.epoch += 1;
        self.epoch_key_ref = Some(epoch_key_ref.into());
        self.epoch_secret_ref = None;
        self.commit_secret_ref = None;
        self.welcome_secret_ref = None;
        self.application_secret_ref = None;
        self.pending_commit = false;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupApplicationMessage {
    pub room_id: String,
    pub epoch: u64,
    pub sender_client_id: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupProposalMessage {
    pub room_id: String,
    pub proposal_id: String,
    pub proposal_kind: String,
    pub sender_client_id: String,
    pub target_client_id: Option<String>,
    pub mode: GroupMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupCommitMessage {
    pub room_id: String,
    pub epoch: u64,
    pub epoch_key_ref: String,
    pub sender_client_id: String,
    pub mode: GroupMode,
    pub proposal_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupWelcomeMessage {
    pub room_id: String,
    pub epoch: u64,
    pub epoch_key_ref: String,
    pub sender_client_id: String,
    pub recipient_client_id: String,
    pub mode: GroupMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupControlMessage {
    Proposal(GroupProposalMessage),
    Commit(GroupCommitMessage),
    Welcome(GroupWelcomeMessage),
}

impl GroupProposalMessage {
    pub fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group proposal is missing room_id".to_string(),
            ));
        }
        if self.proposal_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group proposal is missing proposal_id".to_string(),
            ));
        }
        if self.proposal_kind.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group proposal is missing proposal_kind".to_string(),
            ));
        }
        if self.sender_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group proposal is missing sender_client_id".to_string(),
            ));
        }
        Ok(())
    }
}

impl GroupCommitMessage {
    pub fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group commit is missing room_id".to_string(),
            ));
        }
        if self.epoch == 0 {
            return Err(ClientCoreError::State(
                "group commit requires a positive epoch".to_string(),
            ));
        }
        if self.epoch_key_ref.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group commit is missing epoch_key_ref".to_string(),
            ));
        }
        if self.sender_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group commit is missing sender_client_id".to_string(),
            ));
        }
        Ok(())
    }
}

impl GroupWelcomeMessage {
    pub fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group welcome is missing room_id".to_string(),
            ));
        }
        if self.epoch == 0 {
            return Err(ClientCoreError::State(
                "group welcome requires a positive epoch".to_string(),
            ));
        }
        if self.epoch_key_ref.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group welcome is missing epoch_key_ref".to_string(),
            ));
        }
        if self.sender_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group welcome is missing sender_client_id".to_string(),
            ));
        }
        if self.recipient_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group welcome is missing recipient_client_id".to_string(),
            ));
        }
        Ok(())
    }
}

impl GroupControlMessage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Proposal(message) => message.validate(),
            Self::Commit(message) => message.validate(),
            Self::Welcome(message) => message.validate(),
        }
    }
}

impl GroupApplicationMessage {
    pub fn validate(&self) -> Result<()> {
        if self.room_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group application message is missing room_id".to_string(),
            ));
        }

        if self.sender_client_id.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group application message is missing sender_client_id".to_string(),
            ));
        }

        if self.ciphertext.trim().is_empty() {
            return Err(ClientCoreError::State(
                "group application message is missing ciphertext".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GroupApplicationMessage, GroupCommitMessage, GroupControlMessage, GroupMemberCredential,
        GroupMode, GroupProposalMessage, GroupState, GroupWelcomeMessage,
    };

    #[test]
    fn group_state_upserts_members_and_advances_epoch() {
        let mut state = GroupState::new("lobby", GroupMode::Mls);
        state
            .upsert_member(GroupMemberCredential {
                client_id: "peer-b".to_string(),
                username: "bob".to_string(),
                signing_key_b64: Some("sig-b".to_string()),
            })
            .expect("member should validate");
        state
            .upsert_member(GroupMemberCredential {
                client_id: "peer-a".to_string(),
                username: "alice".to_string(),
                signing_key_b64: Some("sig-a".to_string()),
            })
            .expect("member should validate");
        state.advance_epoch("epoch::1");

        assert_eq!(state.epoch, 1);
        assert_eq!(state.epoch_key_ref.as_deref(), Some("epoch::1"));
        assert_eq!(state.members.len(), 2);
        assert_eq!(state.members[0].client_id, "peer-a");
    }

    #[test]
    fn group_message_requires_ciphertext() {
        let message = GroupApplicationMessage {
            room_id: "lobby".to_string(),
            epoch: 1,
            sender_client_id: "peer-a".to_string(),
            ciphertext: "".to_string(),
        };

        assert!(message.validate().is_err());
    }

    #[test]
    fn group_control_messages_validate() {
        assert!(GroupControlMessage::Proposal(GroupProposalMessage {
            room_id: "lobby".to_string(),
            proposal_id: "proposal-1".to_string(),
            proposal_kind: "add-member".to_string(),
            sender_client_id: "peer-a".to_string(),
            target_client_id: Some("peer-b".to_string()),
            mode: GroupMode::Mls,
        })
        .validate()
        .is_ok());

        assert!(GroupControlMessage::Commit(GroupCommitMessage {
            room_id: "lobby".to_string(),
            epoch: 1,
            epoch_key_ref: "epoch::1".to_string(),
            sender_client_id: "peer-a".to_string(),
            mode: GroupMode::Mls,
            proposal_ids: vec!["proposal-1".to_string()],
        })
        .validate()
        .is_ok());

        assert!(GroupControlMessage::Welcome(GroupWelcomeMessage {
            room_id: "lobby".to_string(),
            epoch: 1,
            epoch_key_ref: "epoch::1".to_string(),
            sender_client_id: "peer-a".to_string(),
            recipient_client_id: "peer-b".to_string(),
            mode: GroupMode::Mls,
        })
        .validate()
        .is_ok());
    }
}
