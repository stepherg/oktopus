package testcases

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
// sections. When both slices are empty, all cases are returned.
func (r *Registry) Filter(ids []string, sections []int) []TestCase {
	if len(ids) == 0 && len(sections) == 0 {
		return r.cases
	}

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
		if idSet[tc.ID] || secSet[tc.Section] {
			out = append(out, tc)
		}
	}
	return out
}
