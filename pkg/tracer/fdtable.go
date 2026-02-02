package tracer

import (
	"sync"
)

type DirInfo struct {
	path   string
	pos    int
}

type FDTable struct {
	mu   sync.RWMutex
	dirs map[int]*DirInfo
}

func NewFDTable() *FDTable {
	return &FDTable{
		dirs: make(map[int]*DirInfo),
	}
}

func (t *FDTable) TrackDir(fd int, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dirs[fd] = &DirInfo{path: path, pos: 0}
}

func (t *FDTable) GetDir(fd int) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if d, ok := t.dirs[fd]; ok {
		return d.path, true
	}
	return "", false
}

func (t *FDTable) IsTrackedDir(fd int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.dirs[fd]
	return ok
}

func (t *FDTable) GetDirPos(fd int) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if d, ok := t.dirs[fd]; ok {
		return d.pos
	}
	return 0
}

func (t *FDTable) SetDirPos(fd int, pos int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d, ok := t.dirs[fd]; ok {
		d.pos = pos
	}
}

func (t *FDTable) Close(fd int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.dirs, fd)
}

func (t *FDTable) Dup(oldfd, newfd int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d, ok := t.dirs[oldfd]; ok {
		t.dirs[newfd] = &DirInfo{path: d.path, pos: d.pos}
	}
}

func (t *FDTable) CloseAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dirs = make(map[int]*DirInfo)
}
