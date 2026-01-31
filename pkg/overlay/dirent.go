package overlay

import (
	"sort"

	"fuss/pkg/vfs"
)

type DirMerger struct {
	entries   map[string]vfs.DirEntry
	whiteouts map[string]bool
}

func NewDirMerger() *DirMerger {
	return &DirMerger{
		entries:   make(map[string]vfs.DirEntry),
		whiteouts: make(map[string]bool),
	}
}

func (m *DirMerger) Add(entry vfs.DirEntry) {
	if m.whiteouts[entry.Name] {
		return
	}
	if _, exists := m.entries[entry.Name]; exists {
		return
	}
	m.entries[entry.Name] = entry
}

func (m *DirMerger) AddWhiteout(name string) {
	m.whiteouts[name] = true
	delete(m.entries, name)
}

func (m *DirMerger) Entries() []vfs.DirEntry {
	result := make([]vfs.DirEntry, 0, len(m.entries))
	for _, e := range m.entries {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}
