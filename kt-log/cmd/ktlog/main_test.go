package main

import "testing"

func testConfig() config {
	return config{
		MaxBodyBytes:    1024,
		MaxRelayIDBytes: 8,
		MaxKeyBytes:     16,
	}
}

func TestValidateRecordRejectsOversizedRelayID(t *testing.T) {
	err := validateRecord(testConfig(), logRecord{
		RelayID:   "relay-too-long",
		PublicKey: "abcd",
	})
	if err == nil || err.Error() != "relayId exceeds KT log limit" {
		t.Fatalf("expected relayId limit error, got %v", err)
	}
}

func TestValidateRecordRejectsMissingPublicKey(t *testing.T) {
	err := validateRecord(testConfig(), logRecord{
		RelayID: "relay-a",
	})
	if err == nil || err.Error() != "relayId and publicKey are required" {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestValidateRecordAllowsBoundedEntry(t *testing.T) {
	err := validateRecord(testConfig(), logRecord{
		RelayID:   "relay-a",
		PublicKey: "abcd",
		Algorithm: "Ed25519",
	})
	if err != nil {
		t.Fatalf("expected bounded record to be valid, got %v", err)
	}
}
