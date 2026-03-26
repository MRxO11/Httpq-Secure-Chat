package rooms

import (
	"errors"
	"sync"
	"time"
)

var ErrRoomRequired = errors.New("room id is required")

type Event struct {
	Type      string    `json:"type"`
	RoomID    string    `json:"roomId"`
	ClientID  string    `json:"clientId,omitempty"`
	Username  string    `json:"username,omitempty"`
	Payload   string    `json:"payload,omitempty"`
	MemberIDs []string  `json:"memberIds,omitempty"`
	At        time.Time `json:"at"`
}

type Presence struct {
	ClientID string
	Username string
}

type Hub struct {
	mu    sync.RWMutex
	rooms map[string]map[string]Presence
}

func NewHub() *Hub {
	return &Hub{
		rooms: make(map[string]map[string]Presence),
	}
}

func (h *Hub) ActiveRooms() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.rooms)
}

func (h *Hub) Join(roomID string, who Presence) (Event, error) {
	if roomID == "" {
		return Event{}, ErrRoomRequired
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	room := h.rooms[roomID]
	if room == nil {
		room = make(map[string]Presence)
		h.rooms[roomID] = room
	}

	room[who.ClientID] = who

	return Event{
		Type:      "room/joined",
		RoomID:    roomID,
		ClientID:  who.ClientID,
		Username:  who.Username,
		MemberIDs: memberIDs(room),
		At:        time.Now().UTC(),
	}, nil
}

func (h *Hub) Leave(roomID, clientID string) (Event, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	room := h.rooms[roomID]
	if room == nil {
		return Event{}, false
	}

	member, ok := room[clientID]
	if !ok {
		return Event{}, false
	}

	delete(room, clientID)
	if len(room) == 0 {
		delete(h.rooms, roomID)
	}

	return Event{
		Type:      "room/left",
		RoomID:    roomID,
		ClientID:  clientID,
		Username:  member.Username,
		MemberIDs: memberIDs(room),
		At:        time.Now().UTC(),
	}, true
}

func (h *Hub) Snapshot(roomID string) Event {
	h.mu.RLock()
	defer h.mu.RUnlock()

	room := h.rooms[roomID]
	return Event{
		Type:      "room/snapshot",
		RoomID:    roomID,
		MemberIDs: memberIDs(room),
		At:        time.Now().UTC(),
	}
}

func memberIDs(room map[string]Presence) []string {
	if len(room) == 0 {
		return nil
	}

	ids := make([]string, 0, len(room))
	for id := range room {
		ids = append(ids, id)
	}

	return ids
}
