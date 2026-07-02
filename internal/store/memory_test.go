package store

import "testing"

func TestMemoryContract(t *testing.T) {
	RunContract(t, func() Store { return NewMemory() })
}
