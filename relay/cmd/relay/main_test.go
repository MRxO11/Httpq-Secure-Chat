package main

import (
	"strings"
	"testing"
	"time"

	"secure-chat/relay/internal/httpq"
)

func testServer() *relayServer {
	return &relayServer{
		cfg: httpq.Config{
			MaxPayloadBytes:     16,
			MaxRoomIDBytes:      8,
			MaxUsernameBytes:    8,
			MaxClientNonceBytes: 8,
			MaxDirectKeyBytes:   12,
			MaxTargetIDBytes:    8,
			MaxConnections:      2,
			MaxMessagesPerWindow: 2,
			RateLimitWindowSeconds: 10,
			DirectBatchWindowMillis: 150,
		},
	}
}

func TestValidateMessageRejectsOversizedPayload(t *testing.T) {
	server := testServer()
	err := server.validateMessage(incomingMessage{
		Type:    "msg/send",
		Payload: strings.Repeat("a", 17),
	})
	if err == nil || err.Error() != "payload exceeds relay limit" {
		t.Fatalf("expected payload limit error, got %v", err)
	}
}

func TestValidateMessageRejectsOversizedJoinFields(t *testing.T) {
	server := testServer()
	err := server.validateMessage(incomingMessage{
		Type:     "room/join",
		RoomID:   "room-room",
		Username: "alice",
	})
	if err == nil || err.Error() != "room id exceeds relay limit" {
		t.Fatalf("expected room id limit error, got %v", err)
	}
}

func TestValidateMessageAllowsBoundedDirectControl(t *testing.T) {
	server := testServer()
	err := server.validateMessage(incomingMessage{
		Type:           "msg/direct-control",
		TargetClientID: "anon-1",
		Payload:        "{\"t\":1}",
	})
	if err != nil {
		t.Fatalf("expected direct-control payload to pass validation, got %v", err)
	}
}

func TestValidateMessageAllowsBoundedRoomControl(t *testing.T) {
	server := testServer()
	err := server.validateMessage(incomingMessage{
		Type:    "msg/room-control",
		Payload: "{\"t\":1}",
	})
	if err != nil {
		t.Fatalf("expected room-control payload to pass validation, got %v", err)
	}
}

func TestValidateMessageAllowsBoundedCoverTraffic(t *testing.T) {
	server := testServer()
	err := server.validateMessage(incomingMessage{
		Type:    "msg/cover",
		Payload: "{\"x\":1}",
	})
	if err != nil {
		t.Fatalf("expected cover payload to pass validation, got %v", err)
	}
}

func TestAllowClientMessageRejectsBurstBeyondLimit(t *testing.T) {
	server := testServer()
	client := &client{}
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)

	if !server.allowClientMessage(client, now) {
		t.Fatal("expected first message to be allowed")
	}
	if !server.allowClientMessage(client, now.Add(2*time.Second)) {
		t.Fatal("expected second message to be allowed")
	}
	if server.allowClientMessage(client, now.Add(3*time.Second)) {
		t.Fatal("expected third message in same window to be rejected")
	}
}

func TestAllowClientMessageResetsAfterWindow(t *testing.T) {
	server := testServer()
	client := &client{}
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)

	server.allowClientMessage(client, now)
	server.allowClientMessage(client, now.Add(1*time.Second))
	if !server.allowClientMessage(client, now.Add(11*time.Second)) {
		t.Fatal("expected rate limiter to reset after the configured window")
	}
}

func TestClientCountReturnsCurrentConnectedClients(t *testing.T) {
	server := testServer()
	server.clients = map[string]*client{
		"a": {},
		"b": {},
	}

	if got := server.clientCount(); got != 2 {
		t.Fatalf("expected client count 2, got %d", got)
	}
}

func TestQueueDirectJSONBatchesUntilFlush(t *testing.T) {
	server := testServer()
	target := &client{
		id:   "anon-1",
		send: make(chan []byte, 2),
	}

	server.queueDirectJSON(target, map[string]any{
		"type": "msg/direct",
	})

	select {
	case <-target.send:
		t.Fatal("expected direct message to wait for batch flush")
	default:
	}

	server.flushDirectBatch()

	select {
	case payload := <-target.send:
		if !strings.Contains(string(payload), "\"type\":\"msg/direct\"") {
			t.Fatalf("expected flushed payload to be delivered, got %s", string(payload))
		}
	default:
		t.Fatal("expected direct message to be delivered after flush")
	}
}

func TestQueueDirectJSONSendsImmediatelyWhenBatchingDisabled(t *testing.T) {
	server := testServer()
	server.cfg.DirectBatchWindowMillis = 0
	target := &client{
		id:   "anon-1",
		send: make(chan []byte, 1),
	}

	server.queueDirectJSON(target, map[string]any{
		"type": "msg/direct-control",
	})

	select {
	case payload := <-target.send:
		if !strings.Contains(string(payload), "\"type\":\"msg/direct-control\"") {
			t.Fatalf("expected immediate payload delivery, got %s", string(payload))
		}
	default:
		t.Fatal("expected direct control message to send immediately when batching is disabled")
	}
}
