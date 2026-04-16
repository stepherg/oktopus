package testcases

import (
	"sort"
	"strconv"
	"strings"
)

// Registry holds all registered TP-469 test cases.
type Registry struct {
	cases []TestCase
}

// NewRegistry returns an empty registry. Register test cases via Register().
func NewRegistry() *Registry {
	return &Registry{}
}

// Register appends test cases to the registry.
func (r *Registry) Register(cases ...TestCase) {
	r.cases = append(r.cases, cases...)
}

// All returns every registered test case.
func (r *Registry) All() []TestCase { return r.cases }

// Filter returns the subset of test cases matching the requested IDs and/or
// sections. When both slices are empty, all non-disabled cases are returned.
// Disabled tests are always included when explicitly requested by ID.
func (r *Registry) Filter(ids []string, sections []int) []TestCase {
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	secSet := make(map[int]bool, len(sections))
	for _, s := range sections {
		secSet[s] = true
	}

	var out []TestCase
	for _, tc := range r.cases {
		explicitByID := idSet[tc.ID]
		if len(ids) == 0 && len(sections) == 0 {
			// Run all: skip disabled unless explicitly requested (can't be here).
			if tc.Disabled {
				continue
			}
			out = append(out, tc)
		} else if explicitByID || secSet[tc.Section] {
			// Explicit selection: include disabled tests only when requested by ID.
			if tc.Disabled && !explicitByID {
				continue
			}
			out = append(out, tc)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].Section, out[j].Section
		if si != sj {
			return si < sj
		}
		return TestIDKey(out[i].ID) < TestIDKey(out[j].ID)
	})
	return out
}

// TestIDKey returns a sortable integer for a test ID like "1.84".
// Falls back to 0 for malformed IDs.
func TestIDKey(id string) int {
	if i := strings.LastIndex(id, "."); i >= 0 {
		n, _ := strconv.Atoi(id[i+1:])
		return n
	}
	return 0
}
