package merkle

import (
	"crypto/sha256"
	"errors"
)

var ErrLeafIndexOutOfRange = errors.New("leaf index out of range")
var ErrConsistencyRangeInvalid = errors.New("invalid consistency proof range")

type Tree struct {
	leaves [][]byte
}

func NewTree() *Tree {
	return &Tree{
		leaves: make([][]byte, 0),
	}
}

func (t *Tree) Size() int {
	return len(t.leaves)
}

func (t *Tree) Append(leaf []byte) int {
	cloned := append([]byte(nil), leaf...)
	t.leaves = append(t.leaves, cloned)
	return len(t.leaves) - 1
}

func (t *Tree) Root() []byte {
	if len(t.leaves) == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}

	nodes := make([][]byte, 0, len(t.leaves))
	for _, leaf := range t.leaves {
		nodes = append(nodes, hashLeaf(leaf))
	}

	for len(nodes) > 1 {
		nodes = nextLevel(nodes)
	}

	return nodes[0]
}

func (t *Tree) InclusionProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, ErrLeafIndexOutOfRange
	}

	nodes := make([][]byte, 0, len(t.leaves))
	for _, leaf := range t.leaves {
		nodes = append(nodes, hashLeaf(leaf))
	}

	pos := index
	proof := make([][]byte, 0)
	for len(nodes) > 1 {
		if pos%2 == 0 {
			if pos+1 < len(nodes) {
				proof = append(proof, nodes[pos+1])
			}
		} else {
			proof = append(proof, nodes[pos-1])
		}

		nodes = nextLevel(nodes)
		pos /= 2
	}

	return proof, nil
}

func (t *Tree) ConsistencyProof(oldSize, newSize int) ([][]byte, error) {
	if oldSize <= 0 || newSize <= 0 || oldSize > newSize || newSize > len(t.leaves) {
		return nil, ErrConsistencyRangeInvalid
	}
	if oldSize == newSize {
		return [][]byte{}, nil
	}

	nodes := t.hashedLeaves()[:newSize]
	return subproof(nodes, oldSize, true), nil
}

func (t *Tree) hashedLeaves() [][]byte {
	nodes := make([][]byte, 0, len(t.leaves))
	for _, leaf := range t.leaves {
		nodes = append(nodes, hashLeaf(leaf))
	}
	return nodes
}

func subtreeRoot(nodes [][]byte) []byte {
	if len(nodes) == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	level := make([][]byte, len(nodes))
	copy(level, nodes)
	for len(level) > 1 {
		level = nextLevel(level)
	}
	return level[0]
}

func subproof(nodes [][]byte, m int, includeSelf bool) [][]byte {
	n := len(nodes)
	if m == n {
		if includeSelf {
			return [][]byte{}
		}
		return [][]byte{subtreeRoot(nodes)}
	}

	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		proof := subproof(nodes[:k], m, includeSelf)
		return append(proof, subtreeRoot(nodes[k:]))
	}

	proof := subproof(nodes[k:], m-k, false)
	return append(proof, subtreeRoot(nodes[:k]))
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func hashLeaf(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func nextLevel(nodes [][]byte) [][]byte {
	next := make([][]byte, 0, (len(nodes)+1)/2)
	for i := 0; i < len(nodes); i += 2 {
		if i+1 >= len(nodes) {
			next = append(next, nodes[i])
			continue
		}

		next = append(next, hashNode(nodes[i], nodes[i+1]))
	}

	return next
}
