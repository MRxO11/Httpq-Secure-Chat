use serde::{Deserialize, Serialize};

pub mod direct;
pub mod bootstrap;
pub mod group;

pub use bootstrap::{
    DirectBootstrapMessage, DirectIdentityProfile, LocalBootstrapMaterial, LocalOneTimePrekey,
    LocalSignedPrekey, OneTimePrekey, PeerPrekeyBundle, PqxdhInitAckPayload,
    PqxdhInitPayload, SignedPrekey, UsedOneTimePrekey,
};
pub use direct::{
    DirectApplicationFrame, DirectControlFrame, DirectEnvelope, DirectPeerAnnouncement,
    DirectRatchetState, DirectSession, DirectSessionHeader, DirectTransportFrame, PeerDirectory,
};
pub use group::{
    GroupApplicationMessage, GroupCommitMessage, GroupControlMessage, GroupMemberCredential,
    GroupMode, GroupProposalMessage, GroupState, GroupWelcomeMessage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectMessageMode {
    Placeholder,
    SignedStaticSession,
    PqxdhDoubleRatchet,
}
