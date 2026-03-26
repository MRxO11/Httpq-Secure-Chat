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
	"time"

	"secure-chat/kt-log/internal/merkle"
)

type logRecord struct {
	RelayID    string `json:"relayId"`
	PublicKey  string `json:"publicKey"`
	Algorithm  string `json:"algorithm"`
	CreatedAt  string `json:"createdAt"`
}

type signedTreeHead struct {
	TreeSize  int    `json:"treeSize"`
	RootHash  string `json:"rootHash"`
	Signature string `json:"signature"`
}

type logState struct {
	mu         sync.RWMutex
	tree       *merkle.Tree
	records    []logRecord
	indexByID  map[string]int
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type diskState struct {
	Records []logRecord `json:"records"`
}

type diskKey struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type config struct {
	ListenAddr      string
	DataFile        string
	KeyFile         string
	MaxBodyBytes    int64
	MaxRelayIDBytes int
	MaxKeyBytes     int
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
	mux.HandleFunc("/v1/sth", state.handleSTH)
	mux.HandleFunc("/v1/consistency", state.handleConsistency)
	mux.HandleFunc("/v1/entries", state.handleEntries)
	mux.HandleFunc("/v1/entries/", state.handleEntryProof)

	log.Printf("kt-log starting on %s with tree size %d", cfg.ListenAddr, state.tree.Size())
	if createdKey {
		log.Printf("generated new KT signing key at %s", cfg.KeyFile)
	} else {
		log.Printf("loaded KT signing key from %s", cfg.KeyFile)
	}
	if err := http.ListenAndServe(cfg.ListenAddr, withLimits(cfg, mux)); err != nil {
		log.Fatal(err)
	}
}

func (s *logState) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"service":  "kt-log",
		"treeSize": s.tree.Size(),
	})
}

func (s *logState) handleSTH(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"sth":              s.currentSTHLocked(),
		"signingPublicKey": base64.StdEncoding.EncodeToString(s.publicKey),
	})
}

func (s *logState) handleEntries(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": s.records,
			"sth":     s.currentSTHLocked(),
		})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, loadConfig().MaxBodyBytes)
		var record logRecord
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		if err := validateRecord(loadConfig(), record); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		record.Algorithm = strings.TrimSpace(record.Algorithm)
		if record.Algorithm == "" {
			record.Algorithm = "Ed25519"
		}
		if strings.TrimSpace(record.CreatedAt) == "" {
			record.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if _, exists := s.indexByID[record.RelayID]; exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "relayId already exists"})
			return
		}

		leaf, err := json.Marshal(record)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode record"})
			return
		}

		index := s.tree.Append(leaf)
		s.records = append(s.records, record)
		s.indexByID[record.RelayID] = index

		if err := s.saveLocked(loadConfig().DataFile); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		proof, err := s.tree.InclusionProof(index)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"record":           record,
			"index":            index,
			"sth":              s.currentSTHLocked(),
			"proof":            encodeProof(proof),
			"signingPublicKey": base64.StdEncoding.EncodeToString(s.publicKey),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *logState) handleConsistency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	fromSize, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("from")))
	if err != nil || fromSize <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid from tree size"})
		return
	}
	toSize, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("to")))
	if err != nil || toSize <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid to tree size"})
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	proof, err := s.tree.ConsistencyProof(fromSize, toSize)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	oldRoot := treeRootForRecords(s.records[:fromSize])
	newRoot := treeRootForRecords(s.records[:toSize])
	writeJSON(w, http.StatusOK, map[string]any{
		"fromTreeSize":     fromSize,
		"toTreeSize":       toSize,
		"proof":            encodeProof(proof),
		"oldRootHash":      base64.StdEncoding.EncodeToString(oldRoot),
		"newRootHash":      base64.StdEncoding.EncodeToString(newRoot),
		"signingPublicKey": base64.StdEncoding.EncodeToString(s.publicKey),
	})
}

func (s *logState) handleEntryProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	relayID := strings.TrimPrefix(r.URL.Path, "/v1/entries/")
	relayID = strings.TrimSuffix(relayID, "/proof")
	relayID = strings.Trim(relayID, "/")
	if relayID == "" || !strings.HasSuffix(r.URL.Path, "/proof") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	index, ok := s.indexByID[relayID]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relayId not found"})
		return
	}

	proof, err := s.tree.InclusionProof(index)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"record":           s.records[index],
		"index":            index,
		"proof":            encodeProof(proof),
		"sth":              s.currentSTHLocked(),
		"signingPublicKey": base64.StdEncoding.EncodeToString(s.publicKey),
	})
}

func (s *logState) currentSTHLocked() signedTreeHead {
	root := s.tree.Root()
	treeSize := s.tree.Size()
	message := []byte(sthMessage(treeSize, root))
	signature := ed25519.Sign(s.privateKey, message)

	return signedTreeHead{
		TreeSize:  treeSize,
		RootHash:  base64.StdEncoding.EncodeToString(root),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
}

func (s *logState) saveLocked(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(diskState{Records: s.records}, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, encoded, 0o600)
}

func loadState(path string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (*logState, error) {
	state := &logState{
		tree:       merkle.NewTree(),
		records:    make([]logRecord, 0),
		indexByID:  make(map[string]int),
		privateKey: privateKey,
		publicKey:  publicKey,
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

	for _, record := range disk.Records {
		leaf, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}

		index := state.tree.Append(leaf)
		state.records = append(state.records, record)
		state.indexByID[record.RelayID] = index
	}

	return state, nil
}

func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		var disk diskKey
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

	encoded, err := json.MarshalIndent(diskKey{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}, "", "  ")
	if err != nil {
		return nil, nil, false, err
	}

	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, nil, false, err
	}

	return privateKey, publicKey, true, nil
}

func encodeProof(proof [][]byte) []string {
	out := make([]string, 0, len(proof))
	for _, node := range proof {
		out = append(out, base64.StdEncoding.EncodeToString(node))
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func sthMessage(treeSize int, root []byte) string {
	return strings.Join([]string{
		"KT-LOG/1",
		strconv.Itoa(treeSize),
		base64.StdEncoding.EncodeToString(root),
	}, "\n")
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
		ListenAddr:      envOrDefault("KT_LOG_LISTEN_ADDR", ":8081"),
		DataFile:        envOrDefault("KT_LOG_DATA_FILE", filepath.Join(".", "kt-log-data.json")),
		KeyFile:         envOrDefault("KT_LOG_SIGNING_KEY_FILE", filepath.Join(".", "kt-log-signing-key.json")),
		MaxBodyBytes:    int64(envIntOrDefault("KT_LOG_MAX_BODY_BYTES", 32*1024)),
		MaxRelayIDBytes: envIntOrDefault("KT_LOG_MAX_RELAY_ID_BYTES", 128),
		MaxKeyBytes:     envIntOrDefault("KT_LOG_MAX_KEY_BYTES", 4096),
	}
}

func validateRecord(cfg config, record logRecord) error {
	record.RelayID = strings.TrimSpace(record.RelayID)
	record.PublicKey = strings.TrimSpace(record.PublicKey)
	record.Algorithm = strings.TrimSpace(record.Algorithm)

	if record.RelayID == "" || record.PublicKey == "" {
		return errors.New("relayId and publicKey are required")
	}
	if len(record.RelayID) > cfg.MaxRelayIDBytes {
		return errors.New("relayId exceeds KT log limit")
	}
	if len(record.PublicKey) > cfg.MaxKeyBytes {
		return errors.New("publicKey exceeds KT log limit")
	}
	if record.Algorithm != "" && len(record.Algorithm) > 32 {
		return errors.New("algorithm exceeds KT log limit")
	}
	return nil
}

func treeRootForRecords(records []logRecord) []byte {
	tree := merkle.NewTree()
	for _, record := range records {
		leaf, err := json.Marshal(record)
		if err != nil {
			return nil
		}
		tree.Append(leaf)
	}
	return tree.Root()
}

func withLimits(cfg config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/entries" && r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
