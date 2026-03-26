package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"secure-chat/relay/internal/httpq"
	"secure-chat/relay/internal/rooms"
)

type client struct {
	id         string
	username   string
	roomID     string
	directKey  string
	directRouteToken string
	directSigningKey string
	directSignature  string
	authed     bool
	serverNonce []byte
	rateWindowStartedAt time.Time
	rateWindowCount int
	conn       *websocket.Conn
	send       chan []byte
}

type relayServer struct {
	cfg      httpq.Config
	identity httpq.Identity
	hub      *rooms.Hub
	upgrader websocket.Upgrader

	mu      sync.RWMutex
	clients map[string]*client

	directBatchMu sync.Mutex
	pendingDirect []directDelivery
}

func (s *relayServer) clientLogLabel(c *client) string {
	if c == nil {
		return "client"
	}
	if !s.cfg.PrivacyLogRedaction {
		return c.id
	}
	if c.roomID != "" {
		return "session@" + c.roomID
	}
	return "session"
}

type directDelivery struct {
	target  *client
	payload []byte
}

type incomingMessage struct {
	Type           string `json:"type"`
	RoomID         string `json:"roomId"`
	Username       string `json:"username"`
	Payload        string `json:"payload"`
	ClientNonce    string `json:"clientNonce"`
	DirectKey      string `json:"directKey"`
	DirectSigningKey string `json:"directSigningKey"`
	DirectSignature  string `json:"directSignature"`
	TargetClientID string `json:"targetClientId"`
	TargetRouteToken string `json:"targetRouteToken"`
}

type protocolError struct {
	Message string
}

func (e *protocolError) Error() string {
	return e.Message
}

var clientSeq atomic.Uint64

func main() {
	cfg := httpq.DefaultConfig()
	identity, created, err := httpq.LoadOrCreateIdentity(cfg.IdentityFile)
	if err != nil {
		log.Fatal(err)
	}

	server := &relayServer{
		cfg:      cfg,
		identity: identity,
		hub:      rooms.NewHub(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients: make(map[string]*client),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/ws", server.handleWebSocket)

	log.Printf("relay starting on %s with httpq realm %q", cfg.ListenAddr, cfg.Realm)
	log.Printf("relay id %q using KT log %q", cfg.RelayID, cfg.KTLogURL)
	if created {
		log.Printf("generated new relay identity at %s", cfg.IdentityFile)
	} else {
		log.Printf("loaded relay identity from %s", cfg.IdentityFile)
	}
	if err := registerRelayKey(cfg, identity); err != nil {
		log.Printf("kt-log registration warning: %v", err)
	}
	if cfg.DirectBatchWindowMillis > 0 {
		go server.directBatchLoop()
	}
	if cfg.PrivacyLogRedaction {
		log.Println("relay privacy log redaction is enabled")
	}
	log.Println("phase1 relay stores membership only in memory and never persists chat payloads")
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *relayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"service":     "relay",
		"realm":       s.cfg.Realm,
		"activeRooms": s.hub.ActiveRooms(),
	})
}

func (s *relayServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.clientCount() >= s.cfg.MaxConnections {
		http.Error(w, "relay is at connection capacity", http.StatusServiceUnavailable)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}

	c := &client{
		id:         nextClientID(),
		conn:       conn,
		send:       make(chan []byte, 16),
	}
	c.conn.SetReadLimit(s.cfg.MaxFrameBytes)

	serverNonce, err := httpq.RandomNonce()
	if err != nil {
		log.Printf("nonce generation failed for %s: %v", s.clientLogLabel(c), err)
		_ = conn.Close()
		return
	}
	c.serverNonce = serverNonce

	s.mu.Lock()
	s.clients[c.id] = c
	s.mu.Unlock()

	log.Printf("client connected: %s", s.clientLogLabel(c))

	go s.writeLoop(c)
	s.sendJSON(c, httpq.DefaultHello(s.cfg, s.identity, c.serverNonce))
	s.readLoop(c)
}

func (s *relayServer) readLoop(c *client) {
	defer s.disconnect(c)

	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	for {
		var msg incomingMessage
		if err := c.conn.ReadJSON(&msg); err != nil {
			log.Printf("read failed for %s: %v", s.clientLogLabel(c), err)
			return
		}

		if err := s.handleMessage(c, msg); err != nil {
			s.sendJSON(c, map[string]any{
				"type":  "sys/error",
				"error": err.Error(),
				"at":    time.Now().UTC(),
			})
		}
	}
}

func (s *relayServer) writeLoop(c *client) {
	ticker := time.NewTicker(20 * time.Second)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()

	for {
		select {
		case payload, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *relayServer) handleMessage(c *client, msg incomingMessage) error {
	if !s.allowClientMessage(c, time.Now().UTC()) {
		return &protocolError{Message: "rate limit exceeded"}
	}

	if err := s.validateMessage(msg); err != nil {
		return err
	}

	switch msg.Type {
	case "auth/client-hello":
		clientNonce, err := decodeBase64Field(msg.ClientNonce, "client nonce")
		if err != nil {
			return err
		}

		c.authed = true
		s.sendJSON(c, httpq.BuildProof(s.cfg, s.identity, c.id, clientNonce, c.serverNonce))
		return nil
	case "room/join":
		if !c.authed {
			return &protocolError{Message: "authentication required before joining a room"}
		}

		roomID := normalizeRoomID(msg.RoomID)
		username := normalizeUsername(msg.Username, c.id)
		c.directKey = strings.TrimSpace(msg.DirectKey)
		c.directRouteToken = nextDirectRouteToken()
		c.directSigningKey = strings.TrimSpace(msg.DirectSigningKey)
		c.directSignature = strings.TrimSpace(msg.DirectSignature)

		if c.roomID != "" && c.roomID != roomID {
			previousRoomID := c.roomID
			if event, ok := s.hub.Leave(previousRoomID, c.id); ok {
				s.broadcastRoom(previousRoomID, event)
			}
			s.broadcastRoom(previousRoomID, peerEvent("peer/left", previousRoomID, c))
		}

		c.roomID = roomID
		c.username = username

		event, err := s.hub.Join(roomID, rooms.Presence{
			ClientID: c.id,
			Username: username,
		})
		if err != nil {
			return err
		}

		s.broadcastRoom(roomID, event)
		s.sendJSON(c, s.hub.Snapshot(roomID))
		s.sendJSON(c, s.peerSnapshot(roomID))
		s.broadcastRoom(roomID, peerEvent("peer/upsert", roomID, c))
		return nil
	case "room/leave":
		if !c.authed {
			return &protocolError{Message: "authentication required before leaving a room"}
		}

		if c.roomID == "" {
			return nil
		}

		roomID := c.roomID
		c.roomID = ""
		if event, ok := s.hub.Leave(roomID, c.id); ok {
			s.broadcastRoom(roomID, event)
		}
		s.broadcastRoom(roomID, peerEvent("peer/left", roomID, c))
		return nil
	case "msg/send":
		if !c.authed {
			return &protocolError{Message: "authentication required before sending messages"}
		}

		if c.roomID == "" {
			return rooms.ErrRoomRequired
		}

		s.broadcastRoom(c.roomID, rooms.Event{
			Type:     "msg/opaque",
			RoomID:   c.roomID,
			ClientID: c.id,
			Username: c.username,
			Payload:  msg.Payload,
			At:       time.Now().UTC(),
		})
		return nil
	case "msg/direct":
		if !c.authed {
			return &protocolError{Message: "authentication required before sending messages"}
		}
		if c.roomID == "" {
			return rooms.ErrRoomRequired
		}
		if strings.TrimSpace(msg.TargetClientID) == "" && strings.TrimSpace(msg.TargetRouteToken) == "" {
			return &protocolError{Message: "target route token or client id is required"}
		}
		target := s.resolveDirectTarget(c.roomID, msg.TargetClientID, msg.TargetRouteToken)
		if target == nil || target.roomID != c.roomID {
			return &protocolError{Message: "target client is not available in the current room"}
		}
		s.queueDirectJSON(target, map[string]any{
			"type":            "msg/direct",
			"roomId":          c.roomID,
			"senderRouteToken": c.directRouteToken,
			"payload":         msg.Payload,
			"at":              time.Now().UTC(),
		})
		return nil
	case "msg/direct-control":
		if !c.authed {
			return &protocolError{Message: "authentication required before sending messages"}
		}
		if c.roomID == "" {
			return rooms.ErrRoomRequired
		}
		if strings.TrimSpace(msg.TargetClientID) == "" && strings.TrimSpace(msg.TargetRouteToken) == "" {
			return &protocolError{Message: "target route token or client id is required"}
		}
		target := s.resolveDirectTarget(c.roomID, msg.TargetClientID, msg.TargetRouteToken)
		if target == nil || target.roomID != c.roomID {
			return &protocolError{Message: "target client is not available in the current room"}
		}
		s.queueDirectJSON(target, map[string]any{
			"type":            "msg/direct-control",
			"roomId":          c.roomID,
			"senderRouteToken": c.directRouteToken,
			"payload":         msg.Payload,
			"at":              time.Now().UTC(),
		})
		return nil
	case "msg/room-control":
		if !c.authed {
			return &protocolError{Message: "authentication required before sending messages"}
		}
		if c.roomID == "" {
			return rooms.ErrRoomRequired
		}
		s.broadcastRoom(c.roomID, map[string]any{
			"type":     "msg/room-control",
			"roomId":   c.roomID,
			"clientId": c.id,
			"username": c.username,
			"payload":  msg.Payload,
			"at":       time.Now().UTC(),
		})
		return nil
	case "msg/cover":
		if !c.authed {
			return &protocolError{Message: "authentication required before sending messages"}
		}
		if c.roomID == "" {
			return rooms.ErrRoomRequired
		}
		return nil
	default:
		return &protocolError{Message: "unsupported message type"}
	}
}

func (s *relayServer) validateMessage(msg incomingMessage) error {
	if strings.TrimSpace(msg.Type) == "" {
		return &protocolError{Message: "message type is required"}
	}

	switch msg.Type {
	case "auth/client-hello":
		if len(strings.TrimSpace(msg.ClientNonce)) > s.cfg.MaxClientNonceBytes {
			return &protocolError{Message: "client nonce exceeds relay limit"}
		}
	case "room/join":
		if len(strings.TrimSpace(msg.RoomID)) > s.cfg.MaxRoomIDBytes {
			return &protocolError{Message: "room id exceeds relay limit"}
		}
		if len(strings.TrimSpace(msg.Username)) > s.cfg.MaxUsernameBytes {
			return &protocolError{Message: "username exceeds relay limit"}
		}
		if len(strings.TrimSpace(msg.DirectKey)) > s.cfg.MaxDirectKeyBytes {
			return &protocolError{Message: "direct key exceeds relay limit"}
		}
		if len(strings.TrimSpace(msg.DirectSigningKey)) > s.cfg.MaxDirectKeyBytes {
			return &protocolError{Message: "direct signing key exceeds relay limit"}
		}
		if len(strings.TrimSpace(msg.DirectSignature)) > s.cfg.MaxDirectKeyBytes {
			return &protocolError{Message: "direct signature exceeds relay limit"}
		}
	case "room/leave":
		return nil
	case "msg/send", "msg/direct", "msg/direct-control", "msg/room-control", "msg/cover":
		if len(msg.Payload) > s.cfg.MaxPayloadBytes {
			return &protocolError{Message: "payload exceeds relay limit"}
		}
		if msg.Type != "msg/send" && msg.Type != "msg/room-control" && len(strings.TrimSpace(msg.TargetClientID)) > s.cfg.MaxTargetIDBytes {
			return &protocolError{Message: "target client id exceeds relay limit"}
		}
		if msg.Type != "msg/send" && msg.Type != "msg/room-control" && len(strings.TrimSpace(msg.TargetRouteToken)) > s.cfg.MaxTargetIDBytes {
			return &protocolError{Message: "target route token exceeds relay limit"}
		}
	default:
		return nil
	}

	return nil
}

func (s *relayServer) allowClientMessage(c *client, now time.Time) bool {
	window := time.Duration(s.cfg.RateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = 10 * time.Second
	}

	if c.rateWindowStartedAt.IsZero() || now.Sub(c.rateWindowStartedAt) >= window {
		c.rateWindowStartedAt = now
		c.rateWindowCount = 0
	}

	if c.rateWindowCount >= s.cfg.MaxMessagesPerWindow {
		return false
	}

	c.rateWindowCount++
	return true
}

func (s *relayServer) disconnect(c *client) {
	if c.roomID != "" {
		roomID := c.roomID
		c.roomID = ""
		if event, ok := s.hub.Leave(roomID, c.id); ok {
			s.broadcastRoom(roomID, event)
		}
		s.broadcastRoom(roomID, peerEvent("peer/left", roomID, c))
	}

	s.mu.Lock()
	delete(s.clients, c.id)
	s.mu.Unlock()

	close(c.send)
	log.Printf("client disconnected: %s", s.clientLogLabel(c))
}

func (s *relayServer) broadcastRoom(roomID string, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal failed for room %s: %v", roomID, err)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clients {
		if c.roomID != roomID {
			continue
		}
		s.enqueueClientBytes(c, encoded)
	}
}

func (s *relayServer) sendJSON(c *client, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal failed for client %s: %v", c.id, err)
		return
	}

	s.enqueueClientBytes(c, encoded)
}

func (s *relayServer) queueDirectJSON(c *client, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal failed for client %s: %v", c.id, err)
		return
	}

	if s.cfg.DirectBatchWindowMillis <= 0 {
		s.enqueueClientBytes(c, encoded)
		return
	}

	s.directBatchMu.Lock()
	s.pendingDirect = append(s.pendingDirect, directDelivery{
		target:  c,
		payload: encoded,
	})
	s.directBatchMu.Unlock()
}

func (s *relayServer) directBatchLoop() {
	window := time.Duration(s.cfg.DirectBatchWindowMillis) * time.Millisecond
	if window <= 0 {
		return
	}

	ticker := time.NewTicker(window)
	defer ticker.Stop()

	for range ticker.C {
		s.flushDirectBatch()
	}
}

func (s *relayServer) flushDirectBatch() {
	s.directBatchMu.Lock()
	pending := s.pendingDirect
	s.pendingDirect = nil
	s.directBatchMu.Unlock()

	for _, delivery := range pending {
		s.enqueueClientBytes(delivery.target, delivery.payload)
	}
}

func (s *relayServer) enqueueClientBytes(c *client, encoded []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("dropping message for closed %s", s.clientLogLabel(c))
		}
	}()

	select {
	case c.send <- encoded:
	default:
		log.Printf("dropping message for slow %s", s.clientLogLabel(c))
	}
}

func (s *relayServer) peerSnapshot(roomID string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]map[string]string, 0)
	for _, c := range s.clients {
		if c.roomID != roomID {
			continue
		}
		peers = append(peers, peerInfo(c))
	}

	return map[string]any{
		"type":  "peer/snapshot",
		"roomId": roomID,
		"peers": peers,
		"at":    time.Now().UTC(),
	}
}

func peerEvent(eventType, roomID string, c *client) map[string]any {
	return map[string]any{
		"type":  eventType,
		"roomId": roomID,
		"peer":  peerInfo(c),
		"at":    time.Now().UTC(),
	}
}

func peerInfo(c *client) map[string]string {
	return map[string]string{
		"clientId":         c.id,
		"username":         c.username,
		"directKey":        c.directKey,
		"directRouteToken": c.directRouteToken,
		"directSigningKey": c.directSigningKey,
		"directSignature":  c.directSignature,
	}
}

func (s *relayServer) findClient(clientID string) *client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

func (s *relayServer) resolveDirectTarget(roomID, clientID, routeToken string) *client {
	if strings.TrimSpace(routeToken) != "" {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, c := range s.clients {
			if c.roomID == roomID && c.directRouteToken == routeToken {
				return c
			}
		}
		return nil
	}
	return s.findClient(clientID)
}

func nextDirectRouteToken() string {
	nonce, err := httpq.RandomNonce()
	if err != nil {
		return nextClientID()
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:18])
}

func (s *relayServer) clientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

func nextClientID() string {
	return "anon-" + strings.ToLower(base36(clientSeq.Add(1)))
}

func normalizeRoomID(roomID string) string {
	roomID = strings.TrimSpace(roomID)
	if roomID == "" {
		return "lobby"
	}

	return roomID
}

func normalizeUsername(username, clientID string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return clientID
	}

	return username
}

func base36(n uint64) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}

	var out [16]byte
	i := len(out)
	for n > 0 {
		i--
		out[i] = alphabet[n%36]
		n /= 36
	}

	return string(out[i:])
}

func decodeBase64Field(value, field string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, &protocolError{Message: "invalid " + field}
	}

	return out, nil
}

func registerRelayKey(cfg httpq.Config, identity httpq.Identity) error {
	record := map[string]string{
		"relayId":   cfg.RelayID,
		"publicKey": base64.StdEncoding.EncodeToString(identity.PublicKey),
		"algorithm": "Ed25519",
	}

	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	resp, err := http.Post(cfg.KTLogURL+"/v1/entries", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}

	return &protocolError{Message: "unexpected KT log response: " + resp.Status}
}
