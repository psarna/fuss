package tracer

import (
	"sync"

	"fuss/pkg/vfs"
)

const VirtualFDBase = 1000000

type FDTable struct {
	mu      sync.RWMutex
	handles map[int]vfs.FileHandle
	nextFD  int
	dirPos  map[int]int
}

func NewFDTable() *FDTable {
	return &FDTable{
		handles: make(map[int]vfs.FileHandle),
		nextFD:  VirtualFDBase,
		dirPos:  make(map[int]int),
	}
}

func (t *FDTable) Allocate(h vfs.FileHandle) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	fd := t.nextFD
	t.nextFD++
	t.handles[fd] = h
	return fd
}

func (t *FDTable) Get(fd int) (vfs.FileHandle, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	h, ok := t.handles[fd]
	return h, ok
}

func (t *FDTable) Close(fd int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	h, ok := t.handles[fd]
	if !ok {
		return nil
	}

	delete(t.handles, fd)
	delete(t.dirPos, fd)
	return h.Close()
}

func (t *FDTable) IsVirtual(fd int) bool {
	return fd >= VirtualFDBase
}

func (t *FDTable) Dup(oldfd int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	h, ok := t.handles[oldfd]
	if !ok {
		return -1, nil
	}

	newfd := t.nextFD
	t.nextFD++
	t.handles[newfd] = h
	return newfd, nil
}

func (t *FDTable) Dup2(oldfd, newfd int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	h, ok := t.handles[oldfd]
	if !ok {
		return nil
	}

	if existing, ok := t.handles[newfd]; ok {
		existing.Close()
	}

	t.handles[newfd] = h
	return nil
}

func (t *FDTable) GetDirPos(fd int) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dirPos[fd]
}

func (t *FDTable) SetDirPos(fd int, pos int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dirPos[fd] = pos
}

func (t *FDTable) CloseAll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, h := range t.handles {
		h.Close()
	}
	t.handles = make(map[int]vfs.FileHandle)
	t.dirPos = make(map[int]int)
}
