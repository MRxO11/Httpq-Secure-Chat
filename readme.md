# HTTPq Secure Chat

![Platform](https://img.shields.io/badge/platform-terminal-blue)
![Mode](https://img.shields.io/badge/chat-DM--first-green)
![Security](https://img.shields.io/badge/security-HTTPq%20%2B%20ratchet-orange)

Anonymous terminal chat for people who want secure 1-to-1 messaging without accounts, profiles, or server-side chat history.

This project uses its own `HTTPq` trust protocol so the client verifies the relay before any conversation starts.  
That helps protect against fake-relay and man-in-the-middle style server attacks instead of trusting the network blindly.

For direct messages, the app uses a ratchet-style secure session.  
In simple terms, the encryption keys keep changing as messages are exchanged, instead of reusing one permanent key for the whole conversation.  
That makes leaked old keys much less useful and helps keep direct messages safer over time.

Rooms are mainly for discovery and presence.  
The real secure conversation path is direct 1-to-1 messaging.

No accounts, no chat history, and no built-in identity database means even the server owner is designed to know as little as possible about who is using the chat.

---

<img width="1726" height="938" alt="Screenshot 2026-03-27 011644" src="https://github.com/user-attachments/assets/5e35dd4a-317a-4a38-b054-446d24b024b5" />

<img width="1730" height="933" alt="Screenshot 2026-03-27 011844" src="https://github.com/user-attachments/assets/de128de4-6be8-46b4-9b81-f2f8e5fc68a7" />


---

## Features

### Anonymous by Design
- No accounts
- No usernames tied to real identity
- No server-side chat history
- Join, discover, DM, leave

### Secure Direct Messaging
- Secure 1-to-1 direct messages as the main path
- Ratchet-style session with changing message keys
- Replay protection for duplicate packets
- Safety-number check with `/verify`
- Trust reset with `/trust-reset`

### Strong Relay Trust
- Custom `HTTPq` relay-authentication protocol
- Key Transparency for relay key discovery
- Witness-backed verification
- Protection against fake-relay / MITM-style relay attacks

### Privacy-Focused Runtime
- Reduced metadata exposure
- Padded traffic
- Route-token based routing
- Privacy-aware relay behavior
- Terminal-first workflow

---

## Why Not Normal Chat-App Trust?

Most chat apps ask users to trust the server first and hope the server is the real one.

This project takes a different approach:

- the client verifies the relay before trusting it
- direct-message security does not depend on one static chat key
- the relay is designed to stay dumb about message contents
- users do not need accounts or persistent server profiles

So instead of:
- trust server first
- then chat

this project aims for:
- verify server first
- then chat securely

---

## How It Works

1. A user joins anonymously.
2. The client verifies the relay with `HTTPq`.
3. Users discover peers in the room.
4. Secure conversation happens through direct messages.
5. Session keys keep evolving as the conversation continues.
6. Other users in the room should not be able to read that DM plaintext.

---

## Architecture

```text
client-tui  ->  relay  ->  peer
     |            |
     |            +-- HTTPq relay identity
     |            +-- Key Transparency lookup
     |            +-- Witness-backed verification
     |
     +-- direct session bootstrap
     +-- ratchet-style key updates
     +-- local trust / safety number checks

```
---

## Core Parts

- `client-tui/` - terminal client
- `client-core/` - Rust trust, storage, and crypto core
- `relay/` - WebSocket relay
- `kt-log/` - Key Transparency log
- `witness/` - split-view detection helper
- `admin-tools/` - local stack and smoke-test scripts

---

## Quick Start

### Make sure these are installed on your system:

- `Python 3.11+`
- `Rust` and `Cargo`
- `Go 1.22+`
- `PowerShell`

### Start the local stack

```
.\admin-tools\scripts\start-local-stack.ps1
```

### Open Alice

```
cd .\client-tui
.\.venv\Scripts\Activate.ps1
$env:CHAT_NAME="alice"
python .\app\main.py
```

### Open Bob

```
cd .\client-tui
.\.venv\Scripts\Activate.ps1
$env:CHAT_NAME="bob"
python .\app\main.py
```

### Discover peers

```
/peers
```

### Verify peer identity

```
/verify bob
```

### Send a secure direct message

```
/dm bob hello
```

### Useful Commands

```
/peers
/verify HANDLE
/trust-reset HANDLE
/dm HANDLE MESSAGE
/name NEW_NAME
/help
```

---

## Why It Matters

- The client verifies the relay before trusting it.
- Direct messages use changing session keys instead of one fixed key.
- Replay and duplicate direct packets are rejected.
- Other users in the same room should not be able to read someone else’s direct-message plaintext.
- No accounts, no chat history, and no built-in identity database means even the server owner is designed to know as little as possible about who is using the chat.

---

## Project Status

- DM-first secure messaging is the main supported path.
- The project is not externally audited yet.
- Group messaging is not the main finished security story.


  I will continously work on this to make it more secure !!
