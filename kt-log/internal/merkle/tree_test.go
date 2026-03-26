package merkle

import "testing"

func TestRootAndInclusionProof(t *testing.T) {
	tree := NewTree()
	tree.Append([]byte("alpha"))
	tree.Append([]byte("beta"))
	tree.Append([]byte("gamma"))

	root := tree.Root()
	if len(root) == 0 {
		t.Fatal("expected non-empty Merkle root")
	}

	proof, err := tree.InclusionProof(1)
	if err != nil {
		t.Fatalf("expected proof for index 1, got error: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("expected non-empty inclusion proof")
	}
}
