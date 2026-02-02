package passthrough

import (
	"os"
	"path/filepath"
	"syscall"

	"fuss/pkg/vfs"

	"golang.org/x/sys/unix"
)

type PassthroughFS struct {
	root string
}

func New(root string) *PassthroughFS {
	return &PassthroughFS{root: root}
}

func (fs *PassthroughFS) realPath(path string) string {
	return filepath.Join(fs.root, path)
}

func (fs *PassthroughFS) ResolveForOpen(path string, flags vfs.OpenFlags, mode uint32) (string, error) {
	return fs.realPath(path), nil
}

func (fs *PassthroughFS) ResolveForStat(path string, followSymlinks bool) (string, error) {
	return fs.realPath(path), nil
}

func (fs *PassthroughFS) ResolvePath(path string) (string, error) {
	return fs.realPath(path), nil
}

func (fs *PassthroughFS) PrepareCreate(path string) (string, error) {
	return fs.realPath(path), nil
}

func (fs *PassthroughFS) PrepareWrite(path string) (string, error) {
	return fs.realPath(path), nil
}

func (fs *PassthroughFS) PrepareUnlink(path string) error {
	return syscall.Unlink(fs.realPath(path))
}

func (fs *PassthroughFS) PrepareRmdir(path string) error {
	return syscall.Rmdir(fs.realPath(path))
}

func (fs *PassthroughFS) PrepareRename(oldpath, newpath string) (string, string, error) {
	return fs.realPath(oldpath), fs.realPath(newpath), nil
}

func (fs *PassthroughFS) PrepareLink(oldpath, newpath string) (string, string, error) {
	return fs.realPath(oldpath), fs.realPath(newpath), nil
}

func (fs *PassthroughFS) PrepareSymlink(linkpath string) (string, error) {
	return fs.realPath(linkpath), nil
}

func (fs *PassthroughFS) ReadDir(path string) ([]vfs.DirEntry, error) {
	realPath := fs.realPath(path)
	entries, err := os.ReadDir(realPath)
	if err != nil {
		return nil, err
	}

	result := make([]vfs.DirEntry, 0, len(entries))
	for i, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		st := info.Sys().(*syscall.Stat_t)
		result = append(result, vfs.DirEntry{
			Name:   e.Name(),
			Type:   uint8(st.Mode >> 12),
			Ino:    st.Ino,
			Offset: int64(i + 1),
		})
	}
	return result, nil
}

func splitXattrList(data []byte) []string {
	var result []string
	start := 0
	for i, b := range data {
		if b == 0 {
			if i > start {
				result = append(result, string(data[start:i]))
			}
			start = i + 1
		}
	}
	return result
}

var _ vfs.VFS = (*PassthroughFS)(nil)

func (fs *PassthroughFS) Access(path string, mode uint32) error {
	return unix.Access(fs.realPath(path), mode)
}
