package filter

// Decision is the outcome of the cookie filter for one Set-Cookie name.
type Decision int

const (
	// Drop is the implicit default: unlisted cookies are neither forwarded
	// nor stored. There is no configuration for Drop.
	Drop Decision = iota
	Forward
	Store
)

// Filter decides, deny-by-default, what happens to a backend Set-Cookie.
type Filter struct {
	forward map[string]struct{}
	store   map[string]struct{}
}

// New builds a filter from the configured forward and store name lists.
func New(forward, store []string) *Filter {
	f := &Filter{forward: toSet(forward), store: toSet(store)}
	return f
}

func toSet(names []string) map[string]struct{} {
	s := make(map[string]struct{}, len(names))
	for _, n := range names {
		s[n] = struct{}{}
	}
	return s
}

// Decide returns Store if the name is in the store list (store wins over
// forward, so a misconfigured overlap never leaks to the client), Forward if
// only in the forward list, otherwise Drop.
func (f *Filter) Decide(name string) Decision {
	if _, ok := f.store[name]; ok {
		return Store
	}
	if _, ok := f.forward[name]; ok {
		return Forward
	}
	return Drop
}
