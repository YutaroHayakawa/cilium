package routeexporter

type prefixSet struct {
	prefixes map[string]interface{}
}

func newPrefixSet() *prefixSet {
	return &prefixSet{
		prefixes: make(map[string]interface{}),
	}
}

func (ps *prefixSet) add(prefix string) {
	ps.prefixes[prefix] = 0
}

func (ps *prefixSet) del(prefix string) {
	delete(ps.prefixes, prefix)
}

func (ps *prefixSet) exists(prefix string) bool {
	_, ok := ps.prefixes[prefix]
	return ok
}

func (src *prefixSet) dup() *prefixSet {
	dst := newPrefixSet()
	for prefix := range src.prefixes {
		dst.add(prefix)
	}
	return dst
}

func (desired *prefixSet) distance(current *prefixSet) (*prefixSet, *prefixSet) {
	addSet := desired.dup()
	deleteSet := newPrefixSet()

	for prefix := range current.prefixes {
		if desired.exists(prefix) {
			addSet.del(prefix)
		} else {
			deleteSet.add(prefix)
		}
	}

	return addSet, deleteSet
}
