package passthrough

import (
	"io"
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

func (fs *PassthroughFS) Open(path string, flags vfs.OpenFlags, mode uint32) (vfs.FileHandle, error) {
	realPath := fs.realPath(path)
	f, err := os.OpenFile(realPath, int(flags), os.FileMode(mode))
	if err != nil {
		return nil, err
	}
	return &passthroughHandle{f: f}, nil
}

func (fs *PassthroughFS) Stat(path string) (*vfs.FileInfo, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(fs.realPath(path), &st); err != nil {
		return nil, err
	}
	return vfs.FileInfoFromStat(filepath.Base(path), &st), nil
}

func (fs *PassthroughFS) Lstat(path string) (*vfs.FileInfo, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(fs.realPath(path), &st); err != nil {
		return nil, err
	}
	return vfs.FileInfoFromStat(filepath.Base(path), &st), nil
}

func (fs *PassthroughFS) Readlink(path string) (string, error) {
	return os.Readlink(fs.realPath(path))
}

func (fs *PassthroughFS) Access(path string, mode uint32) error {
	return unix.Access(fs.realPath(path), mode)
}

func (fs *PassthroughFS) Mkdir(path string, mode uint32) error {
	return os.Mkdir(fs.realPath(path), os.FileMode(mode))
}

func (fs *PassthroughFS) Rmdir(path string) error {
	return syscall.Rmdir(fs.realPath(path))
}

func (fs *PassthroughFS) Unlink(path string) error {
	return syscall.Unlink(fs.realPath(path))
}

func (fs *PassthroughFS) Rename(oldpath, newpath string, flags uint) error {
	return os.Rename(fs.realPath(oldpath), fs.realPath(newpath))
}

func (fs *PassthroughFS) Link(oldpath, newpath string) error {
	return os.Link(fs.realPath(oldpath), fs.realPath(newpath))
}

func (fs *PassthroughFS) Symlink(target, linkpath string) error {
	return os.Symlink(target, fs.realPath(linkpath))
}

func (fs *PassthroughFS) Chmod(path string, mode uint32) error {
	return os.Chmod(fs.realPath(path), os.FileMode(mode))
}

func (fs *PassthroughFS) Chown(path string, uid, gid int) error {
	return os.Chown(fs.realPath(path), uid, gid)
}

func (fs *PassthroughFS) Lchown(path string, uid, gid int) error {
	return os.Lchown(fs.realPath(path), uid, gid)
}

func (fs *PassthroughFS) Truncate(path string, size int64) error {
	return os.Truncate(fs.realPath(path), size)
}

func (fs *PassthroughFS) Utimes(path string, atime, mtime int64) error {
	return unix.Utimes(fs.realPath(path), []unix.Timeval{
		{Sec: atime},
		{Sec: mtime},
	})
}

func (fs *PassthroughFS) Getxattr(path, name string) ([]byte, error) {
	dest := make([]byte, 256)
	n, err := unix.Getxattr(fs.realPath(path), name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:n], nil
}

func (fs *PassthroughFS) Setxattr(path, name string, value []byte, flags int) error {
	return unix.Setxattr(fs.realPath(path), name, value, flags)
}

func (fs *PassthroughFS) Listxattr(path string) ([]string, error) {
	dest := make([]byte, 4096)
	n, err := unix.Listxattr(fs.realPath(path), dest)
	if err != nil {
		return nil, err
	}
	return splitXattrList(dest[:n]), nil
}

func (fs *PassthroughFS) Removexattr(path, name string) error {
	return unix.Removexattr(fs.realPath(path), name)
}

func (fs *PassthroughFS) Lgetxattr(path, name string) ([]byte, error) {
	dest := make([]byte, 256)
	n, err := unix.Lgetxattr(fs.realPath(path), name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:n], nil
}

func (fs *PassthroughFS) Lsetxattr(path, name string, value []byte, flags int) error {
	return unix.Lsetxattr(fs.realPath(path), name, value, flags)
}

func (fs *PassthroughFS) Llistxattr(path string) ([]string, error) {
	dest := make([]byte, 4096)
	n, err := unix.Llistxattr(fs.realPath(path), dest)
	if err != nil {
		return nil, err
	}
	return splitXattrList(dest[:n]), nil
}

func (fs *PassthroughFS) Lremovexattr(path, name string) error {
	return unix.Lremovexattr(fs.realPath(path), name)
}

func (fs *PassthroughFS) Statfs(path string) (*vfs.StatfsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(fs.realPath(path), &st); err != nil {
		return nil, err
	}
	return &vfs.StatfsInfo{
		Type:    st.Type,
		Bsize:   st.Bsize,
		Blocks:  st.Blocks,
		Bfree:   st.Bfree,
		Bavail:  st.Bavail,
		Files:   st.Files,
		Ffree:   st.Ffree,
		Fsid:    st.Fsid.X__val,
		Namelen: st.Namelen,
		Frsize:  st.Frsize,
		Flags:   st.Flags,
	}, nil
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

type passthroughHandle struct {
	f *os.File
}

func (h *passthroughHandle) Read(p []byte) (int, error) {
	return h.f.Read(p)
}

func (h *passthroughHandle) Write(p []byte) (int, error) {
	return h.f.Write(p)
}

func (h *passthroughHandle) Seek(offset int64, whence int) (int64, error) {
	return h.f.Seek(offset, whence)
}

func (h *passthroughHandle) Close() error {
	return h.f.Close()
}

func (h *passthroughHandle) Stat() (*vfs.FileInfo, error) {
	fi, err := h.f.Stat()
	if err != nil {
		return nil, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return vfs.FileInfoFromStat(fi.Name(), st), nil
}

func (h *passthroughHandle) ReadDir(n int) ([]vfs.DirEntry, error) {
	entries, err := h.f.ReadDir(n)
	if err != nil && err != io.EOF {
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

func (h *passthroughHandle) Sync() error {
	return h.f.Sync()
}

func (h *passthroughHandle) Truncate(size int64) error {
	return h.f.Truncate(size)
}
