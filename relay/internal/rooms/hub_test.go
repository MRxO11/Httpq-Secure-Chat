package rooms

import "testing"

func TestJoinLeaveLifecycle(t *testing.T) {
	hub := NewHub()

	joined, err := hub.Join("alpha", Presence{
		ClientID: "anon-1",
		Username: "alice",
	})
	if err != nil {
		t.Fatalf("join returned error: %v", err)
	}

	if joined.Type != "room/joined" {
		t.Fatalf("unexpected event type: %s", joined.Type)
	}

	if got := hub.ActiveRooms(); got != 1 {
		t.Fatalf("expected 1 active room, got %d", got)
	}

	snapshot := hub.Snapshot("alpha")
	if len(snapshot.MemberIDs) != 1 {
		t.Fatalf("expected 1 member in snapshot, got %d", len(snapshot.MemberIDs))
	}

	left, ok := hub.Leave("alpha", "anon-1")
	if !ok {
		t.Fatal("expected leave to succeed")
	}

	if left.Type != "room/left" {
		t.Fatalf("unexpected leave event type: %s", left.Type)
	}

	if got := hub.ActiveRooms(); got != 0 {
		t.Fatalf("expected room cleanup after last member leaves, got %d rooms", got)
	}
}

func TestJoinRequiresRoomID(t *testing.T) {
	hub := NewHub()

	if _, err := hub.Join("", Presence{ClientID: "anon-1"}); err == nil {
		t.Fatal("expected join to fail for empty room id")
	}
}
