use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::engine::bootstrap::OutboundBootstrapPlan;
use crate::protocols::{
    DirectApplicationFrame, DirectBootstrapMessage, DirectControlFrame, DirectEnvelope,
    DirectMessageMode, DirectPeerAnnouncement, DirectRatchetState, DirectSession,
    DirectTransportFrame, PeerDirectory, PqxdhInitAckPayload, PqxdhInitPayload, UsedOneTimePrekey,
};
use crate::storage::SecretStore;
use crate::{ClientCoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEvent {
    pub room_id: String,
    pub peer: DirectPeerAnnouncement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundDirectEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub mode: DirectMessageMode,
    pub bootstrap: Option<OutboundBootstrapPlan>,
    pub bootstrap_message: Option<DirectBootstrapMessage>,
    pub ratchet_generation: Option<u64>,
    pub ratchet_message_number: Option<u64>,
    pub message_key_ref: Option<String>,
    pub ratchet_public_key_b64: Option<String>,
    pub transport: Option<DirectTransportFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableOutboundDirectEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub mode: String,
    pub ratchet_generation: Option<u64>,
    pub ratchet_message_number: Option<u64>,
    pub message_key_ref: Option<String>,
    pub ratchet_public_key_b64: Option<String>,
    pub has_bootstrap_message: bool,
}

impl OutboundDirectEvent {
    pub fn application_transport(&self, envelope: DirectEnvelope) -> Result<DirectTransportFrame> {
        envelope.validate()?;

        if envelope.header.session_id != self.session_id {
            return Err(ClientCoreError::State(
                "direct application frame session id does not match outbound event".to_string(),
            ));
        }

        if envelope.header.sequence != self.sequence {
            return Err(ClientCoreError::State(
                "direct application frame sequence does not match outbound event".to_string(),
            ));
        }

        let frame = DirectTransportFrame::Application(DirectApplicationFrame {
            target_client_id: self.peer_client_id.clone(),
            envelope,
        });
        frame.validate()?;
        Ok(frame)
    }

    pub fn bootstrap_transport(&self) -> Result<Option<DirectTransportFrame>> {
        let Some(message) = self.bootstrap_message.clone() else {
            return Ok(None);
        };

        let frame = DirectTransportFrame::Control(DirectControlFrame {
            target_client_id: self.peer_client_id.clone(),
            message,
        });
        frame.validate()?;
        Ok(Some(frame))
    }
}

impl From<OutboundDirectEvent> for PortableOutboundDirectEvent {
    fn from(value: OutboundDirectEvent) -> Self {
        Self {
            peer_client_id: value.peer_client_id,
            session_id: value.session_id,
            sequence: value.sequence,
            mode: PortableSessionSnapshot::mode_label(value.mode).to_string(),
            ratchet_generation: value.ratchet_generation,
            ratchet_message_number: value.ratchet_message_number,
            message_key_ref: value.message_key_ref,
            ratchet_public_key_b64: value.ratchet_public_key_b64,
            has_bootstrap_message: value.bootstrap_message.is_some(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundDirectEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub mode: DirectMessageMode,
    pub ratchet_generation: Option<u64>,
    pub used_skipped_message_key: bool,
    pub ratchet_message_number: Option<u64>,
    pub message_key_ref: Option<String>,
    pub ratchet_public_key_b64: Option<String>,
    pub transport: Option<DirectTransportFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableInboundDirectEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub mode: String,
    pub ratchet_generation: Option<u64>,
    pub used_skipped_message_key: bool,
    pub ratchet_message_number: Option<u64>,
    pub message_key_ref: Option<String>,
    pub ratchet_public_key_b64: Option<String>,
}

impl From<InboundDirectEvent> for PortableInboundDirectEvent {
    fn from(value: InboundDirectEvent) -> Self {
        Self {
            peer_client_id: value.peer_client_id,
            session_id: value.session_id,
            sequence: value.sequence,
            mode: PortableSessionSnapshot::mode_label(value.mode).to_string(),
            ratchet_generation: value.ratchet_generation,
            used_skipped_message_key: value.used_skipped_message_key,
            ratchet_message_number: value.ratchet_message_number,
            message_key_ref: value.message_key_ref,
            ratchet_public_key_b64: value.ratchet_public_key_b64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundBootstrapEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub mode: DirectMessageMode,
    pub received: DirectBootstrapMessage,
    pub response: Option<DirectBootstrapMessage>,
    pub transport: Option<DirectTransportFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableInboundBootstrapEvent {
    pub peer_client_id: String,
    pub session_id: String,
    pub mode: String,
    pub received_type: String,
    pub has_response: bool,
    pub response_type: Option<String>,
    pub response_sequence: Option<u64>,
    pub response_ratchet_generation: Option<u64>,
    pub response_message_number: Option<u64>,
}

impl InboundBootstrapEvent {
    pub fn response_transport(&self) -> Result<Option<DirectTransportFrame>> {
        let Some(message) = self.response.clone() else {
            return Ok(None);
        };

        let frame = DirectTransportFrame::Control(DirectControlFrame {
            target_client_id: self.peer_client_id.clone(),
            message,
        });
        frame.validate()?;
        Ok(Some(frame))
    }
}

impl PortableInboundBootstrapEvent {
    fn message_type_label(message: &DirectBootstrapMessage) -> &'static str {
        match message {
            DirectBootstrapMessage::PqxdhInit(_) => "PqxdhInit",
            DirectBootstrapMessage::PqxdhInitAck(_) => "PqxdhInitAck",
        }
    }
}

impl From<InboundBootstrapEvent> for PortableInboundBootstrapEvent {
    fn from(value: InboundBootstrapEvent) -> Self {
        Self {
            peer_client_id: value.peer_client_id,
            session_id: value.session_id,
            mode: PortableSessionSnapshot::mode_label(value.mode).to_string(),
            received_type: Self::message_type_label(&value.received).to_string(),
            has_response: value.response.is_some(),
            response_type: value
                .response
                .as_ref()
                .map(|message| Self::message_type_label(message).to_string()),
            response_sequence: None,
            response_ratchet_generation: None,
            response_message_number: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub peer_client_id: String,
    pub session_id: String,
    pub outbound_sequence: u64,
    pub highest_inbound_sequence: u64,
    pub mode: DirectMessageMode,
    pub bootstrap_ready: bool,
    pub ratchet_initialized: bool,
    pub dh_ratchet_turn: u64,
    pub local_ratchet_public_key_b64: Option<String>,
    pub remote_ratchet_public_key_b64: Option<String>,
    pub send_chain_generation: u64,
    pub receive_chain_generation: u64,
    pub send_chain_key_ref: Option<String>,
    pub receive_chain_key_ref: Option<String>,
    pub skipped_message_keys: usize,
    pub last_send_message_number: Option<u64>,
    pub last_receive_message_number: Option<u64>,
    pub last_send_message_key_ref: Option<String>,
    pub last_receive_message_key_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableSessionSnapshot {
    pub peer_client_id: String,
    pub session_id: String,
    pub outbound_sequence: u64,
    pub highest_inbound_sequence: u64,
    pub mode: String,
    pub bootstrap_ready: bool,
    pub ratchet_initialized: bool,
    pub dh_ratchet_turn: u64,
    pub local_ratchet_public_key_b64: Option<String>,
    pub remote_ratchet_public_key_b64: Option<String>,
    pub send_chain_generation: u64,
    pub receive_chain_generation: u64,
    pub send_chain_key_ref: Option<String>,
    pub receive_chain_key_ref: Option<String>,
    pub skipped_message_keys: usize,
    pub last_send_message_number: Option<u64>,
    pub last_receive_message_number: Option<u64>,
    pub last_send_message_key_ref: Option<String>,
    pub last_receive_message_key_ref: Option<String>,
}

impl PortableSessionSnapshot {
    pub fn mode_label(mode: DirectMessageMode) -> &'static str {
        match mode {
            DirectMessageMode::Placeholder => "placeholder",
            DirectMessageMode::SignedStaticSession => "signed-static-session",
            DirectMessageMode::PqxdhDoubleRatchet => "pqxdh-bridge-session",
        }
    }
}

impl From<SessionSnapshot> for PortableSessionSnapshot {
    fn from(value: SessionSnapshot) -> Self {
        Self {
            peer_client_id: value.peer_client_id,
            session_id: value.session_id,
            outbound_sequence: value.outbound_sequence,
            highest_inbound_sequence: value.highest_inbound_sequence,
            mode: Self::mode_label(value.mode).to_string(),
            bootstrap_ready: value.bootstrap_ready,
            ratchet_initialized: value.ratchet_initialized,
            dh_ratchet_turn: value.dh_ratchet_turn,
            local_ratchet_public_key_b64: value.local_ratchet_public_key_b64,
            remote_ratchet_public_key_b64: value.remote_ratchet_public_key_b64,
            send_chain_generation: value.send_chain_generation,
            receive_chain_generation: value.receive_chain_generation,
            send_chain_key_ref: value.send_chain_key_ref,
            receive_chain_key_ref: value.receive_chain_key_ref,
            skipped_message_keys: value.skipped_message_keys,
            last_send_message_number: value.last_send_message_number,
            last_receive_message_number: value.last_receive_message_number,
            last_send_message_key_ref: value.last_send_message_key_ref,
            last_receive_message_key_ref: value.last_receive_message_key_ref,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionBootstrap {
    pub peer_client_id: String,
    pub room_id: String,
    pub local_client_id: String,
}

pub trait DirectSessionDriver {
    fn mode(&self) -> DirectMessageMode;
    fn ensure_session<S>(&self, store: &mut S, bootstrap: &SessionBootstrap) -> Result<DirectSession>
    where
        S: SecretStore;
    fn prepare_outbound<S>(
        &self,
        store: &mut S,
        bootstrap: &SessionBootstrap,
    ) -> Result<OutboundDirectEvent>
    where
        S: SecretStore;
    fn accept_inbound<S>(
        &self,
        store: &mut S,
        peer_client_id: &str,
        envelope: &DirectEnvelope,
    ) -> Result<InboundDirectEvent>
    where
        S: SecretStore;
    fn accept_bootstrap_message<S>(
        &self,
        store: &mut S,
        bootstrap: &SessionBootstrap,
        message: &DirectBootstrapMessage,
    ) -> Result<InboundBootstrapEvent>
    where
        S: SecretStore;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SignedStaticSessionDriver;

impl DirectSessionDriver for SignedStaticSessionDriver {
    fn mode(&self) -> DirectMessageMode {
        DirectMessageMode::SignedStaticSession
    }

    fn ensure_session<S>(&self, store: &mut S, bootstrap: &SessionBootstrap) -> Result<DirectSession>
    where
        S: SecretStore,
    {
        let session_id = session_id_for(
            &bootstrap.room_id,
            &bootstrap.local_client_id,
            &bootstrap.peer_client_id,
        );

        let session = store
            .load_direct_session(&bootstrap.peer_client_id)
            .unwrap_or_else(|| {
                DirectSession::new(bootstrap.peer_client_id.clone(), session_id.clone())
            });

        if session.session_id != session_id {
            let reset = DirectSession::new(bootstrap.peer_client_id.clone(), session_id);
            store.save_direct_session(reset.clone());
            return Ok(reset);
        }

        store.save_direct_session(session.clone());
        Ok(session)
    }

    fn prepare_outbound<S>(
        &self,
        store: &mut S,
        bootstrap: &SessionBootstrap,
    ) -> Result<OutboundDirectEvent>
    where
        S: SecretStore,
    {
        let mut session = self.ensure_session(store, bootstrap)?;
        let sequence = session.next_outbound_sequence();
        store.save_direct_session(session.clone());

        Ok(OutboundDirectEvent {
            peer_client_id: bootstrap.peer_client_id.clone(),
            session_id: session.session_id,
            sequence,
            mode: self.mode(),
            bootstrap: None,
            bootstrap_message: None,
            ratchet_generation: None,
            ratchet_message_number: None,
            message_key_ref: None,
            ratchet_public_key_b64: None,
            transport: None,
        })
    }

    fn accept_inbound<S>(
        &self,
        store: &mut S,
        peer_client_id: &str,
        envelope: &DirectEnvelope,
    ) -> Result<InboundDirectEvent>
    where
        S: SecretStore,
    {
        envelope.validate()?;

        let mut session = store
            .load_direct_session(peer_client_id)
            .unwrap_or_else(|| {
                DirectSession::new(peer_client_id.to_string(), envelope.header.session_id.clone())
            });

        if session.session_id != envelope.header.session_id {
            session =
                DirectSession::new(peer_client_id.to_string(), envelope.header.session_id.clone());
        }

        session.accept_inbound_sequence(envelope.header.sequence)?;
        store.save_direct_session(session.clone());

        Ok(InboundDirectEvent {
            peer_client_id: peer_client_id.to_string(),
            session_id: session.session_id,
            sequence: envelope.header.sequence,
            mode: self.mode(),
            ratchet_generation: None,
            used_skipped_message_key: false,
            ratchet_message_number: None,
            message_key_ref: None,
            ratchet_public_key_b64: None,
            transport: Some(DirectTransportFrame::Application(DirectApplicationFrame {
                target_client_id: peer_client_id.to_string(),
                envelope: envelope.clone(),
            })),
        })
    }

    fn accept_bootstrap_message<S>(
        &self,
        _store: &mut S,
        _bootstrap: &SessionBootstrap,
        _message: &DirectBootstrapMessage,
    ) -> Result<InboundBootstrapEvent>
    where
        S: SecretStore,
    {
        Err(ClientCoreError::State(
            "signed static sessions do not use bootstrap messages".to_string(),
        ))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PqxdhSessionDriver;

impl DirectSessionDriver for PqxdhSessionDriver {
    fn mode(&self) -> DirectMessageMode {
        DirectMessageMode::PqxdhDoubleRatchet
    }

    fn ensure_session<S>(&self, store: &mut S, bootstrap: &SessionBootstrap) -> Result<DirectSession>
    where
        S: SecretStore,
    {
        ensure_bootstrap_material(store, &bootstrap.peer_client_id)?;
        let session_id = pqxdh_session_id_for(
            &bootstrap.room_id,
            &bootstrap.local_client_id,
            &bootstrap.peer_client_id,
        );

        let session = store
            .load_direct_session(&bootstrap.peer_client_id)
            .unwrap_or_else(|| {
                DirectSession::new(bootstrap.peer_client_id.clone(), session_id.clone())
            });

        if session.session_id != session_id {
            let reset = DirectSession::new(bootstrap.peer_client_id.clone(), session_id);
            store.save_direct_session(reset.clone());
            let root_key_ref = derive_outbound_root_key_ref(store, bootstrap, None)?;
            ensure_ratchet_state(
                store,
                &bootstrap.peer_client_id,
                &reset.session_id,
                &root_key_ref,
                "PQXDH/1",
            )?;
            return Ok(reset);
        }

        let root_key_ref = derive_outbound_root_key_ref(store, bootstrap, None)?;
        store.save_direct_session(session.clone());
        ensure_ratchet_state(
            store,
            &bootstrap.peer_client_id,
            &session.session_id,
            &root_key_ref,
            "PQXDH/1",
        )?;
        Ok(session)
    }

    fn prepare_outbound<S>(
        &self,
        store: &mut S,
        bootstrap: &SessionBootstrap,
    ) -> Result<OutboundDirectEvent>
    where
        S: SecretStore,
    {
        ensure_bootstrap_material(store, &bootstrap.peer_client_id)?;
        let session_id = pqxdh_session_id_for(
            &bootstrap.room_id,
            &bootstrap.local_client_id,
            &bootstrap.peer_client_id,
        );

        let existing = store.load_direct_session(&bootstrap.peer_client_id);
        let needs_bootstrap = existing
            .as_ref()
            .map(|session| session.session_id != session_id)
            .unwrap_or(true);

        let bootstrap_plan = if needs_bootstrap {
            Some(consume_bootstrap_material(
                store,
                &bootstrap.local_client_id,
                &bootstrap.peer_client_id,
            )?)
        } else {
            None
        };
        let bootstrap_message = bootstrap_plan
            .as_ref()
            .map(|plan| pqxdh_init_message(store, bootstrap, plan))
            .transpose()?;
        let root_key_ref =
            derive_outbound_root_key_ref(store, bootstrap, bootstrap_plan.as_ref())?;

        let mut session = self.ensure_session(store, bootstrap)?;
        let sequence = session.next_outbound_sequence();
        store.save_direct_session(session.clone());
        let mut ratchet = ensure_ratchet_state(
            store,
            &bootstrap.peer_client_id,
            &session.session_id,
            &root_key_ref,
            "PQXDH/1",
        )?;
        let message_key = ratchet.next_send_step();
        let ratchet_generation = message_key.chain_generation;
        let ratchet_message_number = message_key.message_number;
        let message_key_ref = message_key.key_ref.clone();
        let ratchet_public_key_b64 = ratchet.local_ratchet_public_key_b64.clone();
        store.save_direct_ratchet_state(ratchet);

        Ok(OutboundDirectEvent {
            peer_client_id: bootstrap.peer_client_id.clone(),
            session_id: session.session_id,
            sequence,
            mode: self.mode(),
            bootstrap: bootstrap_plan,
            bootstrap_message,
            ratchet_generation: Some(ratchet_generation),
            ratchet_message_number: Some(ratchet_message_number),
            message_key_ref: Some(message_key_ref),
            ratchet_public_key_b64: Some(ratchet_public_key_b64),
            transport: None,
        })
    }

    fn accept_inbound<S>(
        &self,
        store: &mut S,
        peer_client_id: &str,
        envelope: &DirectEnvelope,
    ) -> Result<InboundDirectEvent>
    where
        S: SecretStore,
    {
        envelope.validate()?;
        ensure_bootstrap_material(store, peer_client_id)?;

        let mut session = store
            .load_direct_session(peer_client_id)
            .unwrap_or_else(|| {
                DirectSession::new(peer_client_id.to_string(), envelope.header.session_id.clone())
            });

        if session.session_id != envelope.header.session_id {
            session =
                DirectSession::new(peer_client_id.to_string(), envelope.header.session_id.clone());
        }

        let mut ratchet = ensure_ratchet_state(
            store,
            peer_client_id,
            &session.session_id,
            &derive_inbound_root_key_ref_from_session(store, peer_client_id, &session.session_id)?,
            "PQXDH/1",
        )?;
        if let Some(remote_ratchet_key_b64) = envelope.sender_ratchet_key_b64.as_deref() {
            let _ = ratchet.apply_remote_ratchet_key(remote_ratchet_key_b64)?;
        }
        if !envelope.uses_session_chain() {
            session.accept_inbound_sequence(envelope.header.sequence)?;
            let ratchet_public_key_b64 = ratchet.local_ratchet_public_key_b64.clone();
            store.save_direct_session(session.clone());
            store.save_direct_ratchet_state(ratchet);

            return Ok(InboundDirectEvent {
                peer_client_id: peer_client_id.to_string(),
                session_id: session.session_id,
                sequence: envelope.header.sequence,
                mode: self.mode(),
                ratchet_generation: None,
                used_skipped_message_key: false,
                ratchet_message_number: None,
                message_key_ref: None,
                ratchet_public_key_b64: Some(ratchet_public_key_b64),
                transport: Some(DirectTransportFrame::Application(DirectApplicationFrame {
                    target_client_id: peer_client_id.to_string(),
                    envelope: envelope.clone(),
                })),
            });
        }
        let used_skipped_message_key = ratchet
            .try_consume_skipped_message_key(envelope.header.sequence)
            .map(|key| (key.message_number, key.key_ref));
        let (ratchet_generation, ratchet_message_number, message_key_ref, used_skipped_message_key) =
            if let Some((message_number, key_ref)) = used_skipped_message_key {
                (Some(envelope.header.sequence), Some(message_number), Some(key_ref), true)
            } else {
                session.accept_inbound_sequence(envelope.header.sequence)?;
                let message_key = ratchet.accept_receive_step(envelope.header.sequence)?;
                (
                    Some(message_key.chain_generation),
                    Some(message_key.message_number),
                    Some(message_key.key_ref),
                    false,
                )
            };
        let ratchet_public_key_b64 = ratchet.local_ratchet_public_key_b64.clone();
        store.save_direct_session(session.clone());
        store.save_direct_ratchet_state(ratchet);

        Ok(InboundDirectEvent {
            peer_client_id: peer_client_id.to_string(),
            session_id: session.session_id,
            sequence: envelope.header.sequence,
            mode: self.mode(),
            ratchet_generation,
            used_skipped_message_key,
            ratchet_message_number,
            message_key_ref,
            ratchet_public_key_b64: Some(ratchet_public_key_b64),
            transport: Some(DirectTransportFrame::Application(DirectApplicationFrame {
                target_client_id: peer_client_id.to_string(),
                envelope: envelope.clone(),
            })),
        })
    }

    fn accept_bootstrap_message<S>(
        &self,
        store: &mut S,
        bootstrap: &SessionBootstrap,
        message: &DirectBootstrapMessage,
    ) -> Result<InboundBootstrapEvent>
    where
        S: SecretStore,
    {
        ensure_bootstrap_material(store, &bootstrap.peer_client_id)?;
        message.validate()?;

        match message {
            DirectBootstrapMessage::PqxdhInit(payload) => {
                validate_pqxdh_init(store, bootstrap, payload)?;
                let session_id = pqxdh_session_id_for(
                    &bootstrap.room_id,
                    &bootstrap.local_client_id,
                    &bootstrap.peer_client_id,
                );
                let root_key_ref = derive_inbound_root_key_ref(store, bootstrap, payload)?;
                let session =
                    DirectSession::new(bootstrap.peer_client_id.clone(), session_id.clone());
                store.save_direct_session(session);
                store.save_direct_ratchet_state(DirectRatchetState::initialize(
                    bootstrap.peer_client_id.clone(),
                    session_id.clone(),
                    root_key_ref,
                    payload.protocol.clone(),
                ));

                Ok(InboundBootstrapEvent {
                    peer_client_id: bootstrap.peer_client_id.clone(),
                    session_id: session_id.clone(),
                    mode: self.mode(),
                    received: message.clone(),
                    response: Some(DirectBootstrapMessage::PqxdhInitAck(
                        PqxdhInitAckPayload {
                            protocol: "PQXDH/1".to_string(),
                            sender_client_id: bootstrap.local_client_id.clone(),
                            receiver_client_id: bootstrap.peer_client_id.clone(),
                            session_id,
                        },
                    )),
                    transport: Some(DirectTransportFrame::Control(DirectControlFrame {
                        target_client_id: bootstrap.peer_client_id.clone(),
                        message: message.clone(),
                    })),
                })
            }
            DirectBootstrapMessage::PqxdhInitAck(payload) => {
                validate_pqxdh_init_ack(bootstrap, payload)?;
                let session = store
                    .load_direct_session(&bootstrap.peer_client_id)
                    .ok_or_else(|| {
                        ClientCoreError::State(
                            "received PQXDH init ack without an existing session".to_string(),
                        )
                    })?;
                if session.session_id != payload.session_id {
                    return Err(ClientCoreError::State(
                        "received PQXDH init ack for a different session".to_string(),
                    ));
                }
                ensure_ratchet_state(
                    store,
                    &bootstrap.peer_client_id,
                    &payload.session_id,
                    &derive_inbound_root_key_ref_from_session(
                        store,
                        &bootstrap.peer_client_id,
                        &payload.session_id,
                    )?,
                    &payload.protocol,
                )?;

                Ok(InboundBootstrapEvent {
                    peer_client_id: bootstrap.peer_client_id.clone(),
                    session_id: payload.session_id.clone(),
                    mode: self.mode(),
                    received: message.clone(),
                    response: None,
                    transport: Some(DirectTransportFrame::Control(DirectControlFrame {
                        target_client_id: bootstrap.peer_client_id.clone(),
                        message: message.clone(),
                    })),
                })
            }
        }
    }
}

pub struct DirectEngine<S, D = SignedStaticSessionDriver> {
    store: S,
    peers: PeerDirectory,
    driver: D,
}

impl<S> DirectEngine<S, SignedStaticSessionDriver>
where
    S: SecretStore,
{
    pub fn new(store: S) -> Self {
        Self::with_driver(store, SignedStaticSessionDriver)
    }
}

impl<S, D> DirectEngine<S, D>
where
    S: SecretStore,
    D: DirectSessionDriver,
{
    pub fn with_driver(store: S, driver: D) -> Self {
        Self {
            store,
            peers: PeerDirectory::default(),
            driver,
        }
    }

    pub fn mode(&self) -> DirectMessageMode {
        self.driver.mode()
    }

    pub fn upsert_peer(&mut self, peer: DirectPeerAnnouncement) -> Result<PeerEvent> {
        let room_id = peer.room_id.clone();
        self.peers.upsert(peer.clone())?;
        Ok(PeerEvent { room_id, peer })
    }

    pub fn remove_peer(&mut self, client_id: &str) -> Option<DirectPeerAnnouncement> {
        self.peers.remove(client_id)
    }

    pub fn peer(&self, client_id: &str) -> Option<&DirectPeerAnnouncement> {
        self.peers.get(client_id)
    }

    pub fn prepare_outbound(
        &mut self,
        peer_client_id: &str,
        room_id: &str,
        local_client_id: &str,
    ) -> Result<OutboundDirectEvent> {
        if self.peers.get(peer_client_id).is_none() {
            return Err(ClientCoreError::State(format!(
                "cannot prepare outbound direct message for unknown peer: {}",
                peer_client_id
            )));
        }

        self.driver.prepare_outbound(
            &mut self.store,
            &SessionBootstrap {
                peer_client_id: peer_client_id.to_string(),
                room_id: room_id.to_string(),
                local_client_id: local_client_id.to_string(),
            },
        )
    }

    pub fn prepare_outbound_application(
        &mut self,
        peer_client_id: &str,
        room_id: &str,
        local_client_id: &str,
        envelope: DirectEnvelope,
    ) -> Result<OutboundDirectEvent> {
        let mut event = self.prepare_outbound(peer_client_id, room_id, local_client_id)?;
        let transport = event.application_transport(envelope)?;
        event.transport = Some(transport);
        Ok(event)
    }

    pub fn accept_inbound(
        &mut self,
        peer_client_id: &str,
        envelope: &DirectEnvelope,
    ) -> Result<InboundDirectEvent> {
        self.driver
            .accept_inbound(&mut self.store, peer_client_id, envelope)
    }

    pub fn accept_bootstrap_message(
        &mut self,
        peer_client_id: &str,
        room_id: &str,
        local_client_id: &str,
        message: &DirectBootstrapMessage,
    ) -> Result<InboundBootstrapEvent> {
        if self.peers.get(peer_client_id).is_none() {
            return Err(ClientCoreError::State(format!(
                "cannot accept bootstrap message for unknown peer: {}",
                peer_client_id
            )));
        }

        self.driver.accept_bootstrap_message(
            &mut self.store,
            &SessionBootstrap {
                peer_client_id: peer_client_id.to_string(),
                room_id: room_id.to_string(),
                local_client_id: local_client_id.to_string(),
            },
            message,
        )
    }

    pub fn ensure_session(
        &mut self,
        peer_client_id: &str,
        room_id: &str,
        local_client_id: &str,
    ) -> Result<SessionSnapshot> {
        let session = self.driver.ensure_session(
            &mut self.store,
            &SessionBootstrap {
                peer_client_id: peer_client_id.to_string(),
                room_id: room_id.to_string(),
                local_client_id: local_client_id.to_string(),
            },
        )?;

        Ok(SessionSnapshot {
            peer_client_id: session.peer_client_id,
            session_id: session.session_id,
            outbound_sequence: session.outbound_sequence,
            highest_inbound_sequence: session.highest_inbound_sequence,
            mode: self.driver.mode(),
            bootstrap_ready: bootstrap_ready(&self.store, peer_client_id),
            ratchet_initialized: self.store.load_direct_ratchet_state(peer_client_id).is_some(),
            dh_ratchet_turn: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.dh_ratchet_turn)
                .unwrap_or(0),
            local_ratchet_public_key_b64: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.local_ratchet_public_key_b64),
            remote_ratchet_public_key_b64: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .and_then(|state| state.remote_ratchet_public_key_b64),
            send_chain_generation: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.send_chain_generation)
                .unwrap_or(0),
            receive_chain_generation: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.receive_chain_generation)
                .unwrap_or(0),
            send_chain_key_ref: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.send_chain_key.key_ref),
            receive_chain_key_ref: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.receive_chain_key.key_ref),
            skipped_message_keys: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .map(|state| state.skipped_message_keys.len())
                .unwrap_or(0),
            last_send_message_number: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .and_then(|state| state.last_derived_send_message_key.map(|key| key.message_number)),
            last_receive_message_number: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .and_then(|state| state.last_derived_receive_message_key.map(|key| key.message_number)),
            last_send_message_key_ref: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .and_then(|state| state.last_derived_send_message_key.map(|key| key.key_ref)),
            last_receive_message_key_ref: self
                .store
                .load_direct_ratchet_state(peer_client_id)
                .and_then(|state| state.last_derived_receive_message_key.map(|key| key.key_ref)),
        })
    }

    pub fn session_snapshot(&self, peer_client_id: &str) -> Option<SessionSnapshot> {
        self.store
            .load_direct_session(peer_client_id)
            .map(|session| SessionSnapshot {
                peer_client_id: session.peer_client_id,
                session_id: session.session_id,
                outbound_sequence: session.outbound_sequence,
                highest_inbound_sequence: session.highest_inbound_sequence,
                mode: self.driver.mode(),
                bootstrap_ready: bootstrap_ready(&self.store, peer_client_id),
                ratchet_initialized: self.store.load_direct_ratchet_state(peer_client_id).is_some(),
                dh_ratchet_turn: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.dh_ratchet_turn)
                    .unwrap_or(0),
                local_ratchet_public_key_b64: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.local_ratchet_public_key_b64),
                remote_ratchet_public_key_b64: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .and_then(|state| state.remote_ratchet_public_key_b64),
                send_chain_generation: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.send_chain_generation)
                    .unwrap_or(0),
                receive_chain_generation: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.receive_chain_generation)
                    .unwrap_or(0),
                send_chain_key_ref: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.send_chain_key.key_ref),
                receive_chain_key_ref: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.receive_chain_key.key_ref),
                skipped_message_keys: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .map(|state| state.skipped_message_keys.len())
                    .unwrap_or(0),
                last_send_message_number: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .and_then(|state| {
                        state
                            .last_derived_send_message_key
                            .map(|key| key.message_number)
                    }),
                last_receive_message_number: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .and_then(|state| {
                        state
                            .last_derived_receive_message_key
                            .map(|key| key.message_number)
                    }),
                last_send_message_key_ref: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .and_then(|state| state.last_derived_send_message_key.map(|key| key.key_ref)),
                last_receive_message_key_ref: self
                    .store
                    .load_direct_ratchet_state(peer_client_id)
                    .and_then(|state| {
                        state
                            .last_derived_receive_message_key
                            .map(|key| key.key_ref)
                    }),
            })
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

fn session_id_for(room_id: &str, local_client_id: &str, peer_client_id: &str) -> String {
    let mut ids = [local_client_id, peer_client_id];
    ids.sort_unstable();
    format!("dm::{}::{}::{}", room_id, ids[0], ids[1])
}

fn pqxdh_session_id_for(room_id: &str, local_client_id: &str, peer_client_id: &str) -> String {
    let mut ids = [local_client_id, peer_client_id];
    ids.sort_unstable();
    format!("pqxdh::{}::{}::{}", room_id, ids[0], ids[1])
}

fn bootstrap_ready<S>(store: &S, peer_client_id: &str) -> bool
where
    S: SecretStore,
{
    store.load_local_bootstrap_material().is_some()
        && store.load_peer_prekey_bundle(peer_client_id).is_some()
}

fn ensure_bootstrap_material<S>(store: &S, peer_client_id: &str) -> Result<()>
where
    S: SecretStore,
{
    if store.load_local_bootstrap_material().is_none() {
        return Err(ClientCoreError::State(
            "cannot initialize PQXDH session without local bootstrap material".to_string(),
        ));
    }

    let bundle = store.load_peer_prekey_bundle(peer_client_id).ok_or_else(|| {
        ClientCoreError::State(format!(
            "cannot initialize PQXDH session without a peer prekey bundle: {}",
            peer_client_id
        ))
    })?;
    bundle.validate()?;
    Ok(())
}

fn consume_bootstrap_material<S>(
    store: &mut S,
    _local_client_id: &str,
    peer_client_id: &str,
) -> Result<OutboundBootstrapPlan>
where
    S: SecretStore,
{
    let mut bundle = store
        .load_peer_prekey_bundle(peer_client_id)
        .ok_or_else(|| {
            ClientCoreError::State(format!(
                "cannot bootstrap PQXDH session without a prekey bundle for peer: {}",
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
        store.record_used_one_time_prekey(UsedOneTimePrekey {
            peer_client_id: bundle.client_id.clone(),
            key_id: key.key_id,
            consumed_at: "session-bootstrap".to_string(),
        });
    }

    store.save_peer_prekey_bundle(bundle);
    Ok(plan)
}

fn pqxdh_init_message<S>(
    store: &S,
    bootstrap: &SessionBootstrap,
    plan: &OutboundBootstrapPlan,
) -> Result<DirectBootstrapMessage>
where
    S: SecretStore,
{
    let identity = store.load_direct_identity_profile().ok_or_else(|| {
        ClientCoreError::State("cannot build PQXDH init message without a local direct identity profile".to_string())
    })?;

    let payload = PqxdhInitPayload {
        protocol: "PQXDH/1".to_string(),
        sender_client_id: bootstrap.local_client_id.clone(),
        receiver_client_id: bootstrap.peer_client_id.clone(),
        sender_encryption_identity_key_b64: identity.encryption_identity_key_b64,
        sender_signing_identity_key_b64: identity.signing_identity_key_b64,
        receiver_signed_prekey_id: plan.peer_signed_prekey_id,
        receiver_one_time_prekey_id: plan.peer_one_time_prekey_id,
        receiver_pq_prekey_present: plan.pq_prekey_present,
    };
    payload.validate()?;
    Ok(DirectBootstrapMessage::PqxdhInit(payload))
}

fn ensure_ratchet_state<S>(
    store: &mut S,
    peer_client_id: &str,
    session_id: &str,
    root_key_ref: &str,
    protocol: &str,
) -> Result<DirectRatchetState>
where
    S: SecretStore,
{
    if let Some(state) = store.load_direct_ratchet_state(peer_client_id) {
        if state.session_id == session_id {
            return Ok(state);
        }
    }

    let state = DirectRatchetState::initialize(
        peer_client_id.to_string(),
        session_id.to_string(),
        root_key_ref.to_string(),
        protocol.to_string(),
    );
    store.save_direct_ratchet_state(state.clone());
    Ok(state)
}

fn derive_outbound_root_key_ref<S>(
    store: &S,
    bootstrap: &SessionBootstrap,
    consumed_plan: Option<&OutboundBootstrapPlan>,
) -> Result<String>
where
    S: SecretStore,
{
    let local = store.load_local_bootstrap_material().ok_or_else(|| {
        ClientCoreError::State("cannot derive outbound PQXDH root key without local bootstrap material".to_string())
    })?;
    let peer = store.load_peer_prekey_bundle(&bootstrap.peer_client_id).ok_or_else(|| {
        ClientCoreError::State(format!(
            "cannot derive outbound PQXDH root key without a peer prekey bundle: {}",
            bootstrap.peer_client_id
        ))
    })?;

    local.validate()?;
    peer.validate()?;

    let one_time_prekey_id = consumed_plan
        .and_then(|plan| plan.peer_one_time_prekey_id)
        .or_else(|| peer.one_time_prekeys.first().map(|key| key.key_id));
    let selected_one_time_public = one_time_prekey_id.and_then(|selected_id| {
        peer.one_time_prekeys
            .iter()
            .find(|key| key.key_id == selected_id)
            .map(|key| key.public_key_b64.as_str())
    });

    derive_outbound_pqxdh_root_key_ref(
        &pqxdh_session_id_for(
            &bootstrap.room_id,
            &bootstrap.local_client_id,
            &bootstrap.peer_client_id,
        ),
        &bootstrap.local_client_id,
        &bootstrap.peer_client_id,
        &local.encryption_identity_private_key_b64,
        &local.profile.encryption_identity_key_b64,
        &peer.encryption_identity_key_b64,
        &peer.signed_prekey.public_key_b64,
        selected_one_time_public,
        peer.signed_prekey.key_id,
        one_time_prekey_id,
        peer.pq_prekey_b64.is_some(),
    )
}

fn derive_inbound_root_key_ref<S>(
    store: &S,
    bootstrap: &SessionBootstrap,
    payload: &PqxdhInitPayload,
) -> Result<String>
where
    S: SecretStore,
{
    let local = store.load_local_bootstrap_material().ok_or_else(|| {
        ClientCoreError::State("cannot derive inbound PQXDH root key without local bootstrap material".to_string())
    })?;
    local.validate()?;

    let selected_one_time_private = payload.receiver_one_time_prekey_id.and_then(|selected_id| {
        local.one_time_prekeys
            .iter()
            .find(|key| key.key_id == selected_id)
            .map(|key| key.private_key_b64.as_str())
    });

    derive_inbound_pqxdh_root_key_ref(
        &pqxdh_session_id_for(
            &bootstrap.room_id,
            &bootstrap.local_client_id,
            &bootstrap.peer_client_id,
        ),
        &payload.sender_client_id,
        &payload.receiver_client_id,
        &local.encryption_identity_private_key_b64,
        &local.signed_prekey.private_key_b64,
        &payload.sender_encryption_identity_key_b64,
        &local.profile.encryption_identity_key_b64,
        &local.signed_prekey.public_key_b64,
        selected_one_time_private,
        payload.receiver_signed_prekey_id,
        payload.receiver_one_time_prekey_id,
        payload.receiver_pq_prekey_present,
    )
}

fn derive_inbound_root_key_ref_from_session<S>(
    store: &S,
    peer_client_id: &str,
    session_id: &str,
) -> Result<String>
where
    S: SecretStore,
{
    if let Some(state) = store.load_direct_ratchet_state(peer_client_id) {
        if state.session_id == session_id {
            return Ok(state.root_key_ref);
        }
    }
    Err(ClientCoreError::State(
        "cannot recover PQXDH root key ref for session without initialized ratchet state".to_string(),
    ))
}

fn derive_outbound_pqxdh_root_key_ref(
    session_id: &str,
    sender_client_id: &str,
    receiver_client_id: &str,
    local_identity_private_key_b64: &str,
    _sender_encryption_identity_key_b64: &str,
    receiver_encryption_identity_key_b64: &str,
    receiver_signed_prekey_public_key_b64: &str,
    receiver_one_time_key_material_b64: Option<&str>,
    receiver_signed_prekey_id: u32,
    receiver_one_time_prekey_id: Option<u32>,
    receiver_pq_prekey_present: bool,
) -> Result<String> {
    let local_secret = decode_x25519_secret(local_identity_private_key_b64)?;
    let receiver_signed_public = decode_x25519_public(receiver_signed_prekey_public_key_b64)?;
    let receiver_identity_public = decode_x25519_public(receiver_encryption_identity_key_b64)?;

    let mut ikm = Vec::new();
    ikm.extend_from_slice(local_secret.diffie_hellman(&receiver_signed_public).as_bytes());
    ikm.extend_from_slice(local_secret.diffie_hellman(&receiver_identity_public).as_bytes());
    if let Some(key_material_b64) = receiver_one_time_key_material_b64 {
        let one_time_public = decode_x25519_public(key_material_b64)?;
        ikm.extend_from_slice(local_secret.diffie_hellman(&one_time_public).as_bytes());
    }
    finalize_pqxdh_root_key_ref(
        session_id,
        sender_client_id,
        receiver_client_id,
        receiver_signed_prekey_id,
        receiver_one_time_prekey_id,
        receiver_pq_prekey_present,
        &ikm,
    )
}

fn derive_inbound_pqxdh_root_key_ref(
    session_id: &str,
    sender_client_id: &str,
    receiver_client_id: &str,
    local_identity_private_key_b64: &str,
    local_signed_prekey_private_key_b64: &str,
    sender_encryption_identity_key_b64: &str,
    _receiver_encryption_identity_key_b64: &str,
    _receiver_signed_prekey_public_key_b64: &str,
    receiver_one_time_private_key_b64: Option<&str>,
    receiver_signed_prekey_id: u32,
    receiver_one_time_prekey_id: Option<u32>,
    receiver_pq_prekey_present: bool,
) -> Result<String> {
    let sender_public = decode_x25519_public(sender_encryption_identity_key_b64)?;
    let local_identity_secret = decode_x25519_secret(local_identity_private_key_b64)?;
    let local_signed_secret = decode_x25519_secret(local_signed_prekey_private_key_b64)?;

    let mut ikm = Vec::new();
    ikm.extend_from_slice(local_signed_secret.diffie_hellman(&sender_public).as_bytes());
    ikm.extend_from_slice(local_identity_secret.diffie_hellman(&sender_public).as_bytes());
    if let Some(one_time_private_b64) = receiver_one_time_private_key_b64 {
        let one_time_secret = decode_x25519_secret(one_time_private_b64)?;
        ikm.extend_from_slice(one_time_secret.diffie_hellman(&sender_public).as_bytes());
    }

    finalize_pqxdh_root_key_ref(
        session_id,
        sender_client_id,
        receiver_client_id,
        receiver_signed_prekey_id,
        receiver_one_time_prekey_id,
        receiver_pq_prekey_present,
        &ikm,
    )
}

fn finalize_pqxdh_root_key_ref(
    session_id: &str,
    sender_client_id: &str,
    receiver_client_id: &str,
    receiver_signed_prekey_id: u32,
    receiver_one_time_prekey_id: Option<u32>,
    receiver_pq_prekey_present: bool,
    ikm: &[u8],
) -> Result<String> {
    let salt = format!(
        "secure-chat::pqxdh::{}::{}::{}::{}::{}",
        session_id,
        sender_client_id,
        receiver_client_id,
        receiver_signed_prekey_id,
        receiver_one_time_prekey_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm);
    let mut okm = [0u8; 32];
    hk.expand(
        if receiver_pq_prekey_present {
            b"secure-chat::pqxdh-root::with-pq"
        } else {
            b"secure-chat::pqxdh-root::no-pq"
        },
        &mut okm,
    )
    .map_err(|_| ClientCoreError::State("failed to derive PQXDH root key reference".to_string()))?;

    Ok(format!(
        "rk::pqxdh::{}",
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

fn validate_pqxdh_init<S>(
    store: &S,
    bootstrap: &SessionBootstrap,
    payload: &PqxdhInitPayload,
) -> Result<()>
where
    S: SecretStore,
{
    payload.validate()?;

    if payload.sender_client_id != bootstrap.peer_client_id {
        return Err(ClientCoreError::State(
            "PQXDH init sender does not match peer client id".to_string(),
        ));
    }

    if payload.receiver_client_id != bootstrap.local_client_id {
        return Err(ClientCoreError::State(
            "PQXDH init receiver does not match local client id".to_string(),
        ));
    }

    let identity = store.load_direct_identity_profile().ok_or_else(|| {
        ClientCoreError::State(
            "cannot validate PQXDH init without a local direct identity profile".to_string(),
        )
    })?;
    if identity.client_id != bootstrap.local_client_id {
        return Err(ClientCoreError::State(
            "local direct identity profile does not match bootstrap receiver".to_string(),
        ));
    }

    Ok(())
}

fn validate_pqxdh_init_ack(
    bootstrap: &SessionBootstrap,
    payload: &PqxdhInitAckPayload,
) -> Result<()> {
    payload.validate()?;

    if payload.sender_client_id != bootstrap.peer_client_id {
        return Err(ClientCoreError::State(
            "PQXDH init ack sender does not match peer client id".to_string(),
        ));
    }

    if payload.receiver_client_id != bootstrap.local_client_id {
        return Err(ClientCoreError::State(
            "PQXDH init ack receiver does not match local client id".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::engine::{
        PortableInboundBootstrapEvent, PortableInboundDirectEvent, PortableOutboundDirectEvent,
        PortableSessionSnapshot,
    };
    use crate::protocols::{
        DirectBootstrapMessage, DirectEnvelope, DirectIdentityProfile, DirectMessageMode,
        DirectPeerAnnouncement, DirectSessionHeader, DirectTransportFrame, LocalBootstrapMaterial,
        LocalOneTimePrekey, LocalSignedPrekey, OneTimePrekey, PeerPrekeyBundle,
        PqxdhInitAckPayload, PqxdhInitPayload, SignedPrekey,
    };
    use crate::storage::{MemorySecretStore, SecretStore};

    use super::{DirectEngine, PqxdhSessionDriver, SignedStaticSessionDriver};

    fn peer(client_id: &str) -> DirectPeerAnnouncement {
        DirectPeerAnnouncement {
            client_id: client_id.to_string(),
            username: "alice".to_string(),
            room_id: "lobby".to_string(),
            encryption_key_b64: "enc".to_string(),
            signing_key_b64: "sig".to_string(),
            signature_b64: "signed".to_string(),
        }
    }

    fn bootstrap_ready_store() -> MemorySecretStore {
        let mut store = MemorySecretStore::default();
        let local_identity_private = [1u8; 32];
        let local_identity_public = PublicKey::from(&StaticSecret::from(local_identity_private));
        let local_signed_private = [2u8; 32];
        let local_signed_public = PublicKey::from(&StaticSecret::from(local_signed_private));
        let local_otp_private = [3u8; 32];
        let local_otp_public = PublicKey::from(&StaticSecret::from(local_otp_private));
        let peer_identity_private = [4u8; 32];
        let peer_identity_public = PublicKey::from(&StaticSecret::from(peer_identity_private));
        let peer_signed_private = [5u8; 32];
        let peer_signed_public = PublicKey::from(&StaticSecret::from(peer_signed_private));
        let peer_otp_private = [6u8; 32];
        let peer_otp_public = PublicKey::from(&StaticSecret::from(peer_otp_private));

        let local_identity_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(local_identity_public.as_bytes());
        let local_signed_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(local_signed_public.as_bytes());
        let local_otp_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(local_otp_public.as_bytes());
        let peer_identity_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(peer_identity_public.as_bytes());
        let peer_signed_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(peer_signed_public.as_bytes());
        let peer_otp_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(peer_otp_public.as_bytes());

        store.save_direct_identity_profile(DirectIdentityProfile {
            client_id: "peer-a".to_string(),
            encryption_identity_key_b64: local_identity_public_b64.clone(),
            signing_identity_key_b64: "sig-id".to_string(),
            created_at: "2026-03-25T00:00:00Z".to_string(),
        });
        store.save_local_bootstrap_material(LocalBootstrapMaterial {
            profile: DirectIdentityProfile {
                client_id: "peer-a".to_string(),
                encryption_identity_key_b64: local_identity_public_b64,
                signing_identity_key_b64: "sig-id".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
            },
            encryption_identity_private_key_b64: base64::engine::general_purpose::STANDARD
                .encode(local_identity_private),
            signing_identity_private_key_b64: "sig-id-private".to_string(),
            signed_prekey: LocalSignedPrekey {
                key_id: 18,
                public_key_b64: local_signed_public_b64,
                private_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(local_signed_private),
                signature_b64: "local-spk-sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![LocalOneTimePrekey {
                key_id: 19,
                public_key_b64: local_otp_public_b64,
                private_key_b64: base64::engine::general_purpose::STANDARD.encode(local_otp_private),
                created_at: "2026-03-25T00:00:00Z".to_string(),
            }],
            pq_prekey_public_b64: Some("local-pq".to_string()),
            pq_prekey_private_b64: Some("local-pq-private".to_string()),
            bundle_signature_b64: "local-bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        });
        store.save_peer_prekey_bundle(PeerPrekeyBundle {
            client_id: "peer-b".to_string(),
            signing_identity_key_b64: "peer-sign".to_string(),
            encryption_identity_key_b64: peer_identity_public_b64,
            signed_prekey: SignedPrekey {
                key_id: 8,
                public_key_b64: peer_signed_public_b64,
                signature_b64: "spk-sig".to_string(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                expires_at: "2026-04-25T00:00:00Z".to_string(),
            },
            one_time_prekeys: vec![OneTimePrekey {
                key_id: 9,
                public_key_b64: peer_otp_public_b64,
                created_at: "2026-03-25T00:00:00Z".to_string(),
            }],
            pq_prekey_b64: Some("pq".to_string()),
            bundle_signature_b64: "bundle-sig".to_string(),
            published_at: "2026-03-25T00:00:00Z".to_string(),
        });
        store
    }

    #[test]
    fn default_engine_uses_signed_static_session_mode() {
        let engine = DirectEngine::new(MemorySecretStore::default());
        assert_eq!(engine.mode(), DirectMessageMode::SignedStaticSession);
    }

    #[test]
    fn outbound_sequence_increments() {
        let store = MemorySecretStore::default();
        let mut engine = DirectEngine::with_driver(store, SignedStaticSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let first = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("first outbound should succeed");
        let second = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("second outbound should succeed");

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert!(first.bootstrap.is_none());
        assert!(second.bootstrap.is_none());
        assert!(first.bootstrap_message.is_none());
        assert!(second.bootstrap_message.is_none());
        assert!(first.ratchet_generation.is_none());
        assert!(second.ratchet_generation.is_none());
        assert!(first.ratchet_message_number.is_none());
        assert!(second.ratchet_message_number.is_none());
        assert!(first.message_key_ref.is_none());
        assert!(second.message_key_ref.is_none());
        assert!(first.ratchet_public_key_b64.is_none());
        assert!(second.ratchet_public_key_b64.is_none());
    }

    #[test]
    fn inbound_replay_is_rejected() {
        let store = MemorySecretStore::default();
        let mut engine = DirectEngine::new(store);

        let envelope = DirectEnvelope {
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
        };

        assert!(engine.accept_inbound("peer-b", &envelope).is_ok());
        assert!(engine.accept_inbound("peer-b", &envelope).is_err());
    }

    #[test]
    fn pqxdh_driver_emits_bootstrap_once_for_new_session() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let first = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("first outbound should succeed");
        let second = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("second outbound should succeed");

        assert_eq!(first.mode, DirectMessageMode::PqxdhDoubleRatchet);
        assert!(first.bootstrap.is_some());
        assert!(first.bootstrap_message.is_some());
        assert!(second.bootstrap.is_none());
        assert!(second.bootstrap_message.is_none());
        assert_eq!(first.ratchet_generation, Some(1));
        assert_eq!(second.ratchet_generation, Some(2));
        assert_eq!(first.ratchet_message_number, Some(1));
        assert_eq!(second.ratchet_message_number, Some(2));
        assert!(first.ratchet_public_key_b64.is_some());
        assert!(second.ratchet_public_key_b64.is_some());
        assert!(first
            .message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-send::1::")));
        assert!(second
            .message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-send::2::")));
        assert_eq!(first.session_id, second.session_id);
    }

    #[test]
    fn pqxdh_driver_requires_bootstrap_material() {
        let store = MemorySecretStore::default();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        assert!(engine.prepare_outbound("peer-b", "lobby", "peer-a").is_err());
    }

    #[test]
    fn pqxdh_snapshot_reports_bootstrap_ready() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let snapshot = engine
            .ensure_session("peer-b", "lobby", "peer-a")
            .expect("session should initialize");

        assert!(snapshot.bootstrap_ready);
        assert!(snapshot.ratchet_initialized);
        assert_eq!(snapshot.dh_ratchet_turn, 0);
        assert!(snapshot.local_ratchet_public_key_b64.is_some());
        assert!(snapshot.remote_ratchet_public_key_b64.is_none());
        assert_eq!(snapshot.send_chain_generation, 0);
        assert_eq!(snapshot.receive_chain_generation, 0);
        assert!(snapshot
            .send_chain_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ck-send::0::")));
        assert!(snapshot
            .receive_chain_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ck-recv::0::")));
        assert_eq!(snapshot.skipped_message_keys, 0);
        assert!(snapshot
            .session_id
            .starts_with("pqxdh::lobby::peer-a::peer-b"));
        assert_eq!(snapshot.last_send_message_number, None);
        assert_eq!(snapshot.last_receive_message_number, None);
        assert_eq!(snapshot.mode, DirectMessageMode::PqxdhDoubleRatchet);
    }

    #[test]
    fn pqxdh_driver_accepts_init_and_emits_ack() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let event = engine
            .accept_bootstrap_message(
                "peer-b",
                "lobby",
                "peer-a",
                &DirectBootstrapMessage::PqxdhInit(PqxdhInitPayload {
                    protocol: "PQXDH/1".to_string(),
                    sender_client_id: "peer-b".to_string(),
                    receiver_client_id: "peer-a".to_string(),
                    sender_encryption_identity_key_b64: base64::engine::general_purpose::STANDARD
                        .encode(PublicKey::from(&StaticSecret::from([4u8; 32])).as_bytes()),
                    sender_signing_identity_key_b64: "peer-sign".to_string(),
                    receiver_signed_prekey_id: 8,
                    receiver_one_time_prekey_id: Some(9),
                    receiver_pq_prekey_present: true,
                }),
            )
            .expect("init should be accepted");

        assert_eq!(event.mode, DirectMessageMode::PqxdhDoubleRatchet);
        assert_eq!(event.session_id, "pqxdh::lobby::peer-a::peer-b");
        assert!(matches!(
            event.response,
            Some(DirectBootstrapMessage::PqxdhInitAck(_))
        ));

        let snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist after init");
        assert!(snapshot.ratchet_initialized);
    }

    #[test]
    fn pqxdh_driver_accepts_ack_for_existing_session() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let event = engine
            .accept_bootstrap_message(
                "peer-b",
                "lobby",
                "peer-a",
                &DirectBootstrapMessage::PqxdhInitAck(PqxdhInitAckPayload {
                    protocol: "PQXDH/1".to_string(),
                    sender_client_id: "peer-b".to_string(),
                    receiver_client_id: "peer-a".to_string(),
                    session_id: outbound.session_id.clone(),
                }),
            )
            .expect("ack should be accepted");

        assert_eq!(event.session_id, outbound.session_id);
        assert!(event.response.is_none());
    }

    #[test]
    fn pqxdh_inbound_messages_advance_receive_chain_generation() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");
        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let envelope = DirectEnvelope {
            version: 1,
            algorithm: "pqxdh-bridge+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id.clone(),
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

        let inbound = engine
            .accept_inbound("peer-b", &envelope)
            .expect("inbound message should succeed");
        assert_eq!(inbound.ratchet_generation, Some(1));
        assert!(!inbound.used_skipped_message_key);
        assert_eq!(inbound.ratchet_message_number, Some(1));
        assert!(inbound.ratchet_public_key_b64.is_some());
        assert!(inbound
            .message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-recv::1::")));

        let snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist");
        assert_eq!(snapshot.send_chain_generation, 1);
        assert_eq!(snapshot.receive_chain_generation, 1);
        assert!(snapshot
            .send_chain_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ck-send::1::")));
        assert!(snapshot
            .receive_chain_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("ck-recv::1::")));
        assert_eq!(snapshot.last_send_message_number, Some(1));
        assert_eq!(snapshot.last_receive_message_number, Some(1));
        assert!(snapshot
            .last_send_message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-send::1::")));
        assert!(snapshot
            .last_receive_message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-recv::1::")));
    }

    #[test]
    fn pqxdh_out_of_order_receive_uses_skipped_message_key_cache() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");
        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let later_envelope = DirectEnvelope {
            version: 1,
            algorithm: "pqxdh-bridge+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id.clone(),
                sequence: 3,
            },
            sender_key_b64: "enc".to_string(),
            sender_ratchet_key_b64: None,
            sender_signing_key_b64: "sig".to_string(),
            salt_b64: "salt".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "cipher".to_string(),
            signature_b64: "signed".to_string(),
        };

        let later = engine
            .accept_inbound("peer-b", &later_envelope)
            .expect("later inbound should succeed");
        assert_eq!(later.ratchet_generation, Some(3));
        assert!(!later.used_skipped_message_key);
        assert_eq!(later.ratchet_message_number, Some(3));
        assert!(later
            .message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-recv::3::")));

        let skipped_snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist");
        assert_eq!(skipped_snapshot.skipped_message_keys, 2);

        let skipped_envelope = DirectEnvelope {
            version: 1,
            algorithm: "pqxdh-bridge+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id,
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

        let skipped = engine
            .accept_inbound("peer-b", &skipped_envelope)
            .expect("skipped inbound should succeed");
        assert_eq!(skipped.ratchet_generation, Some(1));
        assert!(skipped.used_skipped_message_key);
        assert_eq!(skipped.ratchet_message_number, Some(1));
        assert!(skipped
            .message_key_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mk-skipped::1::")));

        let final_snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist");
        assert_eq!(final_snapshot.skipped_message_keys, 1);
    }

    #[test]
    fn pqxdh_inbound_new_ratchet_key_applies_dh_turn() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");
        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let remote_ratchet_public =
            PublicKey::from(&StaticSecret::from([10u8; 32]));
        let remote_ratchet_public_b64 =
            base64::engine::general_purpose::STANDARD.encode(remote_ratchet_public.as_bytes());

        let envelope = DirectEnvelope {
            version: 1,
            algorithm: "pqxdh-placeholder".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id,
                sequence: 1,
            },
            sender_key_b64: "enc".to_string(),
            sender_ratchet_key_b64: Some(remote_ratchet_public_b64.clone()),
            sender_signing_key_b64: "sig".to_string(),
            salt_b64: "salt".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "cipher".to_string(),
            signature_b64: "signed".to_string(),
        };

        let inbound = engine
            .accept_inbound("peer-b", &envelope)
            .expect("inbound message with new remote ratchet key should succeed");
        let snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist");

        assert_eq!(snapshot.dh_ratchet_turn, 1);
        assert_eq!(
            snapshot.remote_ratchet_public_key_b64.as_deref(),
            Some(remote_ratchet_public_b64.as_str())
        );
        assert!(snapshot.local_ratchet_public_key_b64.is_some());
        assert!(inbound.ratchet_public_key_b64.is_some());
        assert_eq!(inbound.ratchet_generation, None);
    }

    #[test]
    fn pqxdh_static_bridge_message_does_not_advance_receive_chain() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");
        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let envelope = DirectEnvelope {
            version: 1,
            algorithm: "x25519+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id,
                sequence: 1,
            },
            sender_key_b64: "enc".to_string(),
            sender_ratchet_key_b64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(PublicKey::from(&StaticSecret::from([11u8; 32])).as_bytes()),
            ),
            sender_signing_key_b64: "sig".to_string(),
            salt_b64: "salt".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "cipher".to_string(),
            signature_b64: "signed".to_string(),
        };

        let inbound = engine
            .accept_inbound("peer-b", &envelope)
            .expect("static bridge inbound should succeed");
        let snapshot = engine
            .session_snapshot("peer-b")
            .expect("snapshot should exist");

        assert_eq!(inbound.ratchet_generation, None);
        assert_eq!(inbound.ratchet_message_number, None);
        assert_eq!(snapshot.receive_chain_generation, 0);
        assert_eq!(snapshot.last_receive_message_number, None);
    }

    #[test]
    fn prepare_outbound_application_attaches_application_transport() {
        let store = MemorySecretStore::default();
        let mut engine = DirectEngine::with_driver(store, SignedStaticSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let event = engine
            .prepare_outbound_application(
                "peer-b",
                "lobby",
                "peer-a",
                DirectEnvelope {
                    version: 1,
                    algorithm: "test".to_string(),
                header: DirectSessionHeader {
                    session_id: "dm::lobby::peer-a::peer-b".to_string(),
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
            )
            .expect("application transport should be attached");

        assert!(matches!(
            event.transport,
            Some(DirectTransportFrame::Application(_))
        ));
    }

    #[test]
    fn outbound_bootstrap_event_builds_control_transport() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let event = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("bootstrap outbound should succeed");

        let transport = event
            .bootstrap_transport()
            .expect("bootstrap transport should validate");
        assert!(matches!(transport, Some(DirectTransportFrame::Control(_))));
    }

    #[test]
    fn inbound_bootstrap_response_builds_control_transport() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let event = engine
            .accept_bootstrap_message(
                "peer-b",
                "lobby",
                "peer-a",
                &DirectBootstrapMessage::PqxdhInit(PqxdhInitPayload {
                    protocol: "PQXDH/1".to_string(),
                    sender_client_id: "peer-b".to_string(),
                    receiver_client_id: "peer-a".to_string(),
                    sender_encryption_identity_key_b64: base64::engine::general_purpose::STANDARD
                        .encode(PublicKey::from(&StaticSecret::from([4u8; 32])).as_bytes()),
                    sender_signing_identity_key_b64: "peer-sign".to_string(),
                    receiver_signed_prekey_id: 8,
                    receiver_one_time_prekey_id: Some(9),
                    receiver_pq_prekey_present: true,
                }),
            )
            .expect("init should be accepted");

        let transport = event
            .response_transport()
            .expect("response transport should validate");
        assert!(matches!(transport, Some(DirectTransportFrame::Control(_))));
    }

    #[test]
    fn portable_inbound_bootstrap_event_uses_python_compatible_fields() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let event = engine
            .accept_bootstrap_message(
                "peer-b",
                "lobby",
                "peer-a",
                &DirectBootstrapMessage::PqxdhInit(PqxdhInitPayload {
                    protocol: "PQXDH/1".to_string(),
                    sender_client_id: "peer-b".to_string(),
                    receiver_client_id: "peer-a".to_string(),
                    sender_encryption_identity_key_b64: base64::engine::general_purpose::STANDARD
                        .encode(PublicKey::from(&StaticSecret::from([4u8; 32])).as_bytes()),
                    sender_signing_identity_key_b64: "peer-sign".to_string(),
                    receiver_signed_prekey_id: 8,
                    receiver_one_time_prekey_id: Some(9),
                    receiver_pq_prekey_present: true,
                }),
            )
            .expect("init should be accepted");

        let portable = PortableInboundBootstrapEvent::from(event);
        assert_eq!(portable.peer_client_id, "peer-b");
        assert_eq!(portable.session_id, "pqxdh::lobby::peer-a::peer-b");
        assert_eq!(portable.mode, "pqxdh-bridge-session");
        assert_eq!(portable.received_type, "PqxdhInit");
        assert!(portable.has_response);
        assert_eq!(portable.response_type.as_deref(), Some("PqxdhInitAck"));
        assert_eq!(portable.response_sequence, None);
    }

    #[test]
    fn portable_snapshot_uses_python_compatible_mode_labels() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let snapshot = engine
            .ensure_session("peer-b", "lobby", "peer-a")
            .expect("session should initialize");
        let portable = PortableSessionSnapshot::from(snapshot);

        assert_eq!(portable.mode, "pqxdh-bridge-session");
        assert!(portable.bootstrap_ready);
        assert_eq!(portable.peer_client_id, "peer-b");
        assert!(portable.send_chain_key_ref.is_some());
    }

    #[test]
    fn portable_direct_events_use_python_compatible_field_values() {
        let store = bootstrap_ready_store();
        let mut engine = DirectEngine::with_driver(store, PqxdhSessionDriver);
        engine.upsert_peer(peer("peer-b")).expect("peer should upsert");

        let outbound = engine
            .prepare_outbound("peer-b", "lobby", "peer-a")
            .expect("outbound should succeed");
        let portable_outbound = PortableOutboundDirectEvent::from(outbound.clone());
        assert_eq!(portable_outbound.peer_client_id, "peer-b");
        assert_eq!(portable_outbound.mode, "pqxdh-bridge-session");
        assert_eq!(portable_outbound.ratchet_message_number, Some(1));
        assert!(portable_outbound.has_bootstrap_message);

        let envelope = DirectEnvelope {
            version: 1,
            algorithm: "x25519+hkdf+aes-256-gcm+ed25519".to_string(),
            header: DirectSessionHeader {
                session_id: outbound.session_id,
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
        let inbound = engine
            .accept_inbound("peer-b", &envelope)
            .expect("inbound should succeed");
        let portable_inbound = PortableInboundDirectEvent::from(inbound);
        assert_eq!(portable_inbound.peer_client_id, "peer-b");
        assert_eq!(portable_inbound.mode, "pqxdh-bridge-session");
        assert_eq!(portable_inbound.used_skipped_message_key, false);
    }
}
