package main

import "testing"

func testWitnessConfig() config {
	return config{
		MaxBodyBytes:  1024,
		MaxLogIDBytes: 8,
		MaxHashBytes:  16,
		MaxKeyBytes:   16,
	}
}

func TestValidateCheckpointRejectsOversizedLogID(t *testing.T) {
	err := validateCheckpoint(testWitnessConfig(), checkpoint{
		LogID:            "log-too-long",
		TreeSize:         1,
		RootHash:         "abcd",
		SigningPublicKey: "efgh",
	})
	if err == nil || err.Error() != "logId exceeds witness limit" {
		t.Fatalf("expected logId limit error, got %v", err)
	}
}

func TestValidateCheckpointRejectsMissingFields(t *testing.T) {
	err := validateCheckpoint(testWitnessConfig(), checkpoint{})
	if err == nil || err.Error() != "logId, treeSize, rootHash, and signingPublicKey are required" {
		t.Fatalf("expected missing field error, got %v", err)
	}
}

func TestValidateCheckpointAllowsBoundedCheckpoint(t *testing.T) {
	err := validateCheckpoint(testWitnessConfig(), checkpoint{
		LogID:            "kt-log",
		TreeSize:         1,
		RootHash:         "abcd",
		SigningPublicKey: "efgh",
	})
	if err != nil {
		t.Fatalf("expected bounded checkpoint to be valid, got %v", err)
	}
}
