package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type checkpoint struct {
	LogID            string `json:"logId"`
	TreeSize         int    `json:"treeSize"`
	RootHash         string `json:"rootHash"`
	SigningPublicKey string `json:"signingPublicKey"`
	WitnessPublicKey string `json:"witnessPublicKey,omitempty"`
	WitnessSignature string `json:"witnessSignature,omitempty"`
}

type diskState struct {
	Checkpoints map[string]checkpoint `json:"checkpoints"`
}

type witnessState struct {
	mu          sync.RWMutex
	checkpoints map[string]checkpoint
	dataFile    string
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
}

type config struct {
	ListenAddr    string
	DataFile      string
	KeyFile       string
	MaxBodyBytes  int64
	MaxLogIDBytes int
	MaxHashBytes  int
	MaxKeyBytes   int
}

func main() {
	cfg := loadConfig()

	privateKey, publicKey, createdKey, err := loadOrCreateSigningKey(cfg.KeyFile)
	if err != nil {
		log.Fatal(err)
	}

	state, err := loadState(cfg.DataFile, privateKey, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", state.handleHealth)
	mux.HandleFunc("/v1/checkpoints", state.handleCheckpointUpsert)
	mux.HandleFunc("/v1/checkpoints/", state.handleCheckpointGet)

	log.Printf("witness starting on %s with %d known checkpoints", cfg.ListenAddr, len(state.checkpoints))
	if createdKey {
		log.Printf("generated new witness signing key at %s", cfg.KeyFile)
	} else {
		log.Printf("loaded witness signing key from %s", cfg.KeyFile)
	}
	if err := http.ListenAndServe(cfg.ListenAddr, withLimits(cfg, mux)); err != nil {
		log.Fatal(err)
	}
}

func (s *witnessState) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"service":          "witness",
		"checkpoints":      len(s.checkpoints),
		"witnessPublicKey": base64.StdEncoding.EncodeToString(s.publicKey),
	})
}

func (s *witnessState) handleCheckpointGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	logID := strings.TrimPrefix(r.URL.Path, "/v1/checkpoints/")
	logID = strings.Trim(logID, "/")
	if logID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cp, ok := s.checkpoints[logID]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "checkpoint not found"})
		return
	}

	writeJSON(w, http.StatusOK, s.signedCheckpoint(cp))
}

func (s *witnessState) handleCheckpointUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, loadConfig().MaxBodyBytes)
	var cp checkpoint
	if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if err := validateCheckpoint(loadConfig(), cp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cp.LogID = strings.TrimSpace(cp.LogID)
	cp.RootHash = strings.TrimSpace(cp.RootHash)
	cp.SigningPublicKey = strings.TrimSpace(cp.SigningPublicKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.checkpoints[cp.LogID]
	if ok {
		if cp.TreeSize < existing.TreeSize {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "checkpoint is older than witness view"})
			return
		}

		if cp.TreeSize == existing.TreeSize && cp.RootHash != existing.RootHash {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "split-view detected for same tree size"})
			return
		}

		if existing.SigningPublicKey != cp.SigningPublicKey {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "witness observed different KT signing key"})
			return
		}
	}

	cp.WitnessPublicKey = ""
	cp.WitnessSignature = ""
	s.checkpoints[cp.LogID] = cp
	if err := s.saveLocked(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, s.signedCheckpoint(cp))
}

func (s *witnessState) saveLocked() error {
	directory := filepath.Dir(s.dataFile)
	if directory != "" && directory != "." {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}

	encoded, err := json.MarshalIndent(diskState{Checkpoints: s.checkpoints}, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.dataFile, encoded, 0o600)
}

func loadState(path string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (*witnessState, error) {
	state := &witnessState{
		checkpoints: make(map[string]checkpoint),
		dataFile:    path,
		privateKey:  privateKey,
		publicKey:   publicKey,
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}

	var disk diskState
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, err
	}
	if disk.Checkpoints != nil {
		state.checkpoints = disk.Checkpoints
	}

	return state, nil
}

func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		var disk struct {
			PrivateKey string `json:"privateKey"`
			PublicKey  string `json:"publicKey"`
		}
		if err := json.Unmarshal(raw, &disk); err != nil {
			return nil, nil, false, err
		}

		privateKey, err := base64.StdEncoding.DecodeString(disk.PrivateKey)
		if err != nil {
			return nil, nil, false, err
		}
		publicKey, err := base64.StdEncoding.DecodeString(disk.PublicKey)
		if err != nil {
			return nil, nil, false, err
		}

		return ed25519.PrivateKey(privateKey), ed25519.PublicKey(publicKey), false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, false, err
	}

	encoded, err := json.MarshalIndent(map[string]string{
		"privateKey": base64.StdEncoding.EncodeToString(privateKey),
		"publicKey":  base64.StdEncoding.EncodeToString(publicKey),
	}, "", "  ")
	if err != nil {
		return nil, nil, false, err
	}

	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, nil, false, err
	}

	return privateKey, publicKey, true, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
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

func loadConfig() config {
	return config{
		ListenAddr:    envOrDefault("WITNESS_LISTEN_ADDR", ":8082"),
		DataFile:      envOrDefault("WITNESS_DATA_FILE", filepath.Join(".", "witness-data.json")),
		KeyFile:       envOrDefault("WITNESS_SIGNING_KEY_FILE", filepath.Join(".", "witness-signing-key.json")),
		MaxBodyBytes:  int64(envIntOrDefault("WITNESS_MAX_BODY_BYTES", 16*1024)),
		MaxLogIDBytes: envIntOrDefault("WITNESS_MAX_LOG_ID_BYTES", 128),
		MaxHashBytes:  envIntOrDefault("WITNESS_MAX_HASH_BYTES", 1024),
		MaxKeyBytes:   envIntOrDefault("WITNESS_MAX_KEY_BYTES", 4096),
	}
}

func validateCheckpoint(cfg config, cp checkpoint) error {
	logID := strings.TrimSpace(cp.LogID)
	rootHash := strings.TrimSpace(cp.RootHash)
	signingKey := strings.TrimSpace(cp.SigningPublicKey)

	if logID == "" || cp.TreeSize <= 0 || rootHash == "" || signingKey == "" {
		return errors.New("logId, treeSize, rootHash, and signingPublicKey are required")
	}
	if len(logID) > cfg.MaxLogIDBytes {
		return errors.New("logId exceeds witness limit")
	}
	if len(rootHash) > cfg.MaxHashBytes {
		return errors.New("rootHash exceeds witness limit")
	}
	if len(signingKey) > cfg.MaxKeyBytes {
		return errors.New("signingPublicKey exceeds witness limit")
	}
	return nil
}

func (s *witnessState) signedCheckpoint(cp checkpoint) checkpoint {
	signed := cp
	signed.WitnessPublicKey = base64.StdEncoding.EncodeToString(s.publicKey)
	signed.WitnessSignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(s.privateKey, checkpointMessage(cp)),
	)
	return signed
}

func checkpointMessage(cp checkpoint) []byte {
	return []byte(strings.Join([]string{
		"WITNESS/1",
		cp.LogID,
		strconv.Itoa(cp.TreeSize),
		cp.RootHash,
		cp.SigningPublicKey,
	}, "\n"))
}

func withLimits(cfg config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/checkpoints" && r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
