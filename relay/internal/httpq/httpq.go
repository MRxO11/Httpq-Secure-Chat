package httpq

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr   string
	Realm        string
	IdentityFile string
	RelayID      string
	KTLogURL     string
	WitnessURL   string
	MaxFrameBytes      int64
	MaxPayloadBytes    int
	MaxRoomIDBytes     int
	MaxUsernameBytes   int
	MaxClientNonceBytes int
	MaxDirectKeyBytes  int
	MaxTargetIDBytes   int
	MaxConnections     int
	MaxMessagesPerWindow int
	RateLimitWindowSeconds int
	DirectBatchWindowMillis int
	PrivacyLogRedaction bool
}

type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

type identityFile struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type Transcript struct {
	Realm       string
	ClientID    string
	ClientNonce []byte
	ServerNonce []byte
	PublicKey   []byte
}

type ServerHello struct {
	Type            string `json:"type"`
	Realm           string `json:"realm"`
	ProtocolVersion string `json:"protocolVersion"`
	RelayID         string `json:"relayId"`
	KTLogURL        string `json:"ktLogUrl"`
	WitnessURL      string `json:"witnessUrl"`
	ServerNonce     string `json:"serverNonce"`
	RelayPublicKey  string `json:"relayPublicKey"`
}

type ServerProof struct {
	Type           string `json:"type"`
	Realm          string `json:"realm"`
	RelayID        string `json:"relayId"`
	ClientID       string `json:"clientId"`
	ServerNonce    string `json:"serverNonce"`
	ClientNonce    string `json:"clientNonce"`
	RelayPublicKey string `json:"relayPublicKey"`
	Signature      string `json:"signature"`
}

func DefaultConfig() Config {
	listenAddr := os.Getenv("RELAY_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	realm := os.Getenv("HTTPQ_REALM")
	if realm == "" {
		realm = "secure-chat"
	}

	identityFile := os.Getenv("RELAY_IDENTITY_FILE")
	if identityFile == "" {
		identityFile = filepath.Join(".", "relay-identity.json")
	}

	return Config{
		ListenAddr:   listenAddr,
		Realm:        realm,
		IdentityFile: identityFile,
		RelayID:      envOrDefault("RELAY_ID", "relay-local"),
		KTLogURL:     envOrDefault("KT_LOG_URL", "http://127.0.0.1:8081"),
		WitnessURL:   envOrDefault("WITNESS_URL", "http://127.0.0.1:8082"),
		MaxFrameBytes:      int64(envIntOrDefault("RELAY_MAX_FRAME_BYTES", 64*1024)),
		MaxPayloadBytes:    envIntOrDefault("RELAY_MAX_PAYLOAD_BYTES", 16*1024),
		MaxRoomIDBytes:     envIntOrDefault("RELAY_MAX_ROOM_ID_BYTES", 128),
		MaxUsernameBytes:   envIntOrDefault("RELAY_MAX_USERNAME_BYTES", 128),
		MaxClientNonceBytes: envIntOrDefault("RELAY_MAX_CLIENT_NONCE_BYTES", 128),
		MaxDirectKeyBytes:  envIntOrDefault("RELAY_MAX_DIRECT_KEY_BYTES", 2048),
		MaxTargetIDBytes:   envIntOrDefault("RELAY_MAX_TARGET_ID_BYTES", 128),
		MaxConnections:     envIntOrDefault("RELAY_MAX_CONNECTIONS", 256),
		MaxMessagesPerWindow: envIntOrDefault("RELAY_MAX_MESSAGES_PER_WINDOW", 64),
		RateLimitWindowSeconds: envIntOrDefault("RELAY_RATE_LIMIT_WINDOW_SECONDS", 10),
		DirectBatchWindowMillis: envIntOrDefault("RELAY_DIRECT_BATCH_WINDOW_MS", 150),
		PrivacyLogRedaction: envBoolOrDefault("RELAY_PRIVACY_LOG_REDACTION", true),
	}
}

func LoadOrCreateIdentity(path string) (Identity, bool, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		var disk identityFile
		if err := json.Unmarshal(raw, &disk); err != nil {
			return Identity{}, false, fmt.Errorf("parse relay identity: %w", err)
		}

		privateKey, err := base64.StdEncoding.DecodeString(disk.PrivateKey)
		if err != nil {
			return Identity{}, false, fmt.Errorf("decode private key: %w", err)
		}

		publicKey, err := base64.StdEncoding.DecodeString(disk.PublicKey)
		if err != nil {
			return Identity{}, false, fmt.Errorf("decode public key: %w", err)
		}

		return Identity{
			PrivateKey: ed25519.PrivateKey(privateKey),
			PublicKey:  ed25519.PublicKey(publicKey),
		}, false, nil
	}

	if !os.IsNotExist(err) {
		return Identity{}, false, fmt.Errorf("read relay identity: %w", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, false, fmt.Errorf("generate relay identity: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Identity{}, false, fmt.Errorf("prepare identity directory: %w", err)
	}

	encoded, err := json.MarshalIndent(identityFile{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}, "", "  ")
	if err != nil {
		return Identity{}, false, fmt.Errorf("encode relay identity: %w", err)
	}

	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return Identity{}, false, fmt.Errorf("write relay identity: %w", err)
	}

	return Identity{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, true, nil
}

func RandomNonce() ([]byte, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	return buf, err
}

func DefaultHello(cfg Config, identity Identity, serverNonce []byte) ServerHello {
	return ServerHello{
		Type:            "auth/hello",
		Realm:           cfg.Realm,
		ProtocolVersion: "httpq-phase1",
		RelayID:         cfg.RelayID,
		KTLogURL:        cfg.KTLogURL,
		WitnessURL:      cfg.WitnessURL,
		ServerNonce:     base64.StdEncoding.EncodeToString(serverNonce),
		RelayPublicKey:  base64.StdEncoding.EncodeToString(identity.PublicKey),
	}
}

func BuildProof(cfg Config, identity Identity, clientID string, clientNonce, serverNonce []byte) ServerProof {
	signature := ed25519.Sign(identity.PrivateKey, TranscriptBytes(Transcript{
		Realm:       cfg.Realm,
		ClientID:    clientID,
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
		PublicKey:   identity.PublicKey,
	}))

	return ServerProof{
		Type:           "auth/proof",
		Realm:          cfg.Realm,
		RelayID:        cfg.RelayID,
		ClientID:       clientID,
		ServerNonce:    base64.StdEncoding.EncodeToString(serverNonce),
		ClientNonce:    base64.StdEncoding.EncodeToString(clientNonce),
		RelayPublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey),
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}
}

func TranscriptBytes(t Transcript) []byte {
	parts := []string{
		"HTTPq/1",
		t.Realm,
		t.ClientID,
		base64.StdEncoding.EncodeToString(t.ClientNonce),
		base64.StdEncoding.EncodeToString(t.ServerNonce),
		base64.StdEncoding.EncodeToString(t.PublicKey),
	}

	return []byte(strings.Join(parts, "\n"))
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envIntOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func envBoolOrDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
