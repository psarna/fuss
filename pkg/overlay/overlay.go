package overlay

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"fuss/pkg/vfs"

	"golang.org/x/sys/unix"
)

type OverlayFS struct {
	lowerDirs     []string
	upperDir      string
	whiteoutStyle WhiteoutStyle
}

type Config struct {
	LowerDirs     []string
	UpperDir      string
	WhiteoutStyle WhiteoutStyle
}

func New(cfg Config) *OverlayFS {
	return &OverlayFS{
		lowerDirs:     cfg.LowerDirs,
		upperDir:      cfg.UpperDir,
		whiteoutStyle: cfg.WhiteoutStyle,
	}
}

func (fs *OverlayFS) resolve(path string) (realPath string, inUpper bool, err error) {
	upperPath := filepath.Join(fs.upperDir, path)

	if isWhiteout(upperPath) {
		return "", false, syscall.ENOENT
	}

	if _, err := os.Lstat(upperPath); err == nil {
		return upperPath, true, nil
	}

	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, path)

		dir := filepath.Dir(path)
		if dir != "." && dir != "/" {
			upperDir := filepath.Join(fs.upperDir, dir)
			if isOpaqueDir(upperDir) {
				continue
			}
		}

		whiteoutPath := filepath.Join(fs.upperDir, filepath.Dir(path), whiteoutName(filepath.Base(path)))
		if isWhiteout(whiteoutPath) {
			continue
		}

		if _, err := os.Lstat(lowerPath); err == nil {
			return lowerPath, false, nil
		}
	}

	return "", false, syscall.ENOENT
}

func (fs *OverlayFS) Open(path string, flags vfs.OpenFlags, mode uint32) (vfs.FileHandle, error) {
	if flags.IsCreate() {
		if err := fs.copyUpParents(path); err != nil {
			return nil, err
		}

		upperPath := filepath.Join(fs.upperDir, path)
		removeWhiteout(upperPath, fs.whiteoutStyle)

		f, err := os.OpenFile(upperPath, int(flags), os.FileMode(mode))
		if err != nil {
			return nil, err
		}
		return &overlayHandle{f: f, path: path, fs: fs}, nil
	}

	realPath, inUpper, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}

	if flags.IsWrite() || flags.IsTrunc() {
		if !inUpper {
			if err := fs.copyUp(path); err != nil {
				return nil, err
			}
			realPath = filepath.Join(fs.upperDir, path)
		}
	}

	f, err := os.OpenFile(realPath, int(flags), os.FileMode(mode))
	if err != nil {
		return nil, err
	}

	return &overlayHandle{f: f, path: path, fs: fs}, nil
}

func (fs *OverlayFS) Stat(path string) (*vfs.FileInfo, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}

	var st syscall.Stat_t
	if err := syscall.Stat(realPath, &st); err != nil {
		return nil, err
	}
	return vfs.FileInfoFromStat(filepath.Base(path), &st), nil
}

func (fs *OverlayFS) Lstat(path string) (*vfs.FileInfo, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(realPath, &st); err != nil {
		return nil, err
	}
	return vfs.FileInfoFromStat(filepath.Base(path), &st), nil
}

func (fs *OverlayFS) Readlink(path string) (string, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return "", err
	}
	return os.Readlink(realPath)
}

func (fs *OverlayFS) Access(path string, mode uint32) error {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return err
	}
	return unix.Access(realPath, mode)
}

func (fs *OverlayFS) Mkdir(path string, mode uint32) error {
	if err := fs.copyUpParents(path); err != nil {
		return err
	}

	upperPath := filepath.Join(fs.upperDir, path)
	removeWhiteout(upperPath, fs.whiteoutStyle)

	return os.Mkdir(upperPath, os.FileMode(mode))
}

func (fs *OverlayFS) Rmdir(path string) error {
	realPath, inUpper, err := fs.resolve(path)
	if err != nil {
		return err
	}

	existsInLower := false
	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, path)
		if _, err := os.Lstat(lowerPath); err == nil {
			existsInLower = true
			break
		}
	}

	if inUpper {
		if err := syscall.Rmdir(realPath); err != nil {
			return err
		}
	}

	if existsInLower {
		return fs.createWhiteout(path)
	}

	return nil
}

func (fs *OverlayFS) Unlink(path string) error {
	realPath, inUpper, err := fs.resolve(path)
	if err != nil {
		return err
	}

	existsInLower := false
	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, path)
		if _, err := os.Lstat(lowerPath); err == nil {
			existsInLower = true
			break
		}
	}

	if inUpper {
		if err := syscall.Unlink(realPath); err != nil {
			return err
		}
	}

	if existsInLower {
		return fs.createWhiteout(path)
	}

	return nil
}

func (fs *OverlayFS) Rename(oldpath, newpath string, flags uint) error {
	if err := fs.copyUp(oldpath); err != nil {
		return err
	}
	if err := fs.copyUpParents(newpath); err != nil {
		return err
	}

	oldUpper := filepath.Join(fs.upperDir, oldpath)
	newUpper := filepath.Join(fs.upperDir, newpath)

	removeWhiteout(newUpper, fs.whiteoutStyle)

	if err := os.Rename(oldUpper, newUpper); err != nil {
		return err
	}

	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, oldpath)
		if _, err := os.Lstat(lowerPath); err == nil {
			return fs.createWhiteout(oldpath)
		}
	}

	return nil
}

func (fs *OverlayFS) Link(oldpath, newpath string) error {
	if err := fs.copyUp(oldpath); err != nil {
		return err
	}
	if err := fs.copyUpParents(newpath); err != nil {
		return err
	}

	oldUpper := filepath.Join(fs.upperDir, oldpath)
	newUpper := filepath.Join(fs.upperDir, newpath)

	removeWhiteout(newUpper, fs.whiteoutStyle)

	return os.Link(oldUpper, newUpper)
}

func (fs *OverlayFS) Symlink(target, linkpath string) error {
	if err := fs.copyUpParents(linkpath); err != nil {
		return err
	}

	upperPath := filepath.Join(fs.upperDir, linkpath)
	removeWhiteout(upperPath, fs.whiteoutStyle)

	return os.Symlink(target, upperPath)
}

func (fs *OverlayFS) Chmod(path string, mode uint32) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(fs.upperDir, path), os.FileMode(mode))
}

func (fs *OverlayFS) Chown(path string, uid, gid int) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return os.Chown(filepath.Join(fs.upperDir, path), uid, gid)
}

func (fs *OverlayFS) Lchown(path string, uid, gid int) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return os.Lchown(filepath.Join(fs.upperDir, path), uid, gid)
}

func (fs *OverlayFS) Truncate(path string, size int64) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return os.Truncate(filepath.Join(fs.upperDir, path), size)
}

func (fs *OverlayFS) Utimes(path string, atime, mtime int64) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return unix.Utimes(filepath.Join(fs.upperDir, path), []unix.Timeval{
		{Sec: atime},
		{Sec: mtime},
	})
}

func (fs *OverlayFS) Getxattr(path, name string) ([]byte, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 256)
	n, err := unix.Getxattr(realPath, name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:n], nil
}

func (fs *OverlayFS) Setxattr(path, name string, value []byte, flags int) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return unix.Setxattr(filepath.Join(fs.upperDir, path), name, value, flags)
}

func (fs *OverlayFS) Listxattr(path string) ([]string, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 4096)
	n, err := unix.Listxattr(realPath, dest)
	if err != nil {
		return nil, err
	}
	return splitXattrList(dest[:n]), nil
}

func (fs *OverlayFS) Removexattr(path, name string) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return unix.Removexattr(filepath.Join(fs.upperDir, path), name)
}

func (fs *OverlayFS) Lgetxattr(path, name string) ([]byte, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 256)
	n, err := unix.Lgetxattr(realPath, name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:n], nil
}

func (fs *OverlayFS) Lsetxattr(path, name string, value []byte, flags int) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return unix.Lsetxattr(filepath.Join(fs.upperDir, path), name, value, flags)
}

func (fs *OverlayFS) Llistxattr(path string) ([]string, error) {
	realPath, _, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 4096)
	n, err := unix.Llistxattr(realPath, dest)
	if err != nil {
		return nil, err
	}
	return splitXattrList(dest[:n]), nil
}

func (fs *OverlayFS) Lremovexattr(path, name string) error {
	if err := fs.copyUp(path); err != nil {
		return err
	}
	return unix.Lremovexattr(filepath.Join(fs.upperDir, path), name)
}

func (fs *OverlayFS) Statfs(path string) (*vfs.StatfsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(fs.upperDir, &st); err != nil {
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

func (fs *OverlayFS) createWhiteout(path string) error {
	if err := fs.copyUpParents(path); err != nil {
		return err
	}
	return createWhiteout(filepath.Join(fs.upperDir, path), fs.whiteoutStyle)
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

type overlayHandle struct {
	f    *os.File
	path string
	fs   *OverlayFS
}

func (h *overlayHandle) Read(p []byte) (int, error) {
	return h.f.Read(p)
}

func (h *overlayHandle) Write(p []byte) (int, error) {
	return h.f.Write(p)
}

func (h *overlayHandle) Seek(offset int64, whence int) (int64, error) {
	return h.f.Seek(offset, whence)
}

func (h *overlayHandle) Close() error {
	return h.f.Close()
}

func (h *overlayHandle) Stat() (*vfs.FileInfo, error) {
	fi, err := h.f.Stat()
	if err != nil {
		return nil, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return vfs.FileInfoFromStat(fi.Name(), st), nil
}

func (h *overlayHandle) ReadDir(n int) ([]vfs.DirEntry, error) {
	return h.fs.readDir(h.path)
}

func (h *overlayHandle) Sync() error {
	return h.f.Sync()
}

func (h *overlayHandle) Truncate(size int64) error {
	return h.f.Truncate(size)
}

func (fs *OverlayFS) readDir(path string) ([]vfs.DirEntry, error) {
	merger := NewDirMerger()

	upperPath := filepath.Join(fs.upperDir, path)
	if entries, err := os.ReadDir(upperPath); err == nil {
		for _, e := range entries {
			name := e.Name()
			if isWhiteoutName(name) {
				merger.AddWhiteout(whiteoutTarget(name))
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			st := info.Sys().(*syscall.Stat_t)
			merger.Add(vfs.DirEntry{
				Name: name,
				Type: uint8(st.Mode >> 12),
				Ino:  st.Ino,
			})
		}
	}

	if isOpaqueDir(upperPath) {
		return merger.Entries(), nil
	}

	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, path)
		entries, err := os.ReadDir(lowerPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if isWhiteoutName(name) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			st := info.Sys().(*syscall.Stat_t)
			merger.Add(vfs.DirEntry{
				Name: name,
				Type: uint8(st.Mode >> 12),
				Ino:  st.Ino,
			})
		}
	}

	result := merger.Entries()
	for i := range result {
		result[i].Offset = int64(i + 1)
	}
	return result, nil
}

func (fs *OverlayFS) copyUp(path string) error {
	realPath, inUpper, err := fs.resolve(path)
	if err != nil {
		return err
	}

	if inUpper {
		return nil
	}

	return copyUp(realPath, filepath.Join(fs.upperDir, path))
}

func (fs *OverlayFS) copyUpParents(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return nil
	}

	parts := splitPath(dir)
	current := ""

	for _, part := range parts {
		current = filepath.Join(current, part)
		upperPath := filepath.Join(fs.upperDir, current)

		if _, err := os.Stat(upperPath); err == nil {
			continue
		}

		realPath, _, err := fs.resolve(current)
		if err != nil {
			if err := os.MkdirAll(upperPath, 0755); err != nil {
				return err
			}
			continue
		}

		if err := copyUp(realPath, upperPath); err != nil {
			return err
		}
	}

	return nil
}

func splitPath(path string) []string {
	var parts []string
	for path != "" && path != "/" && path != "." {
		dir, file := filepath.Split(path)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		path = filepath.Clean(dir)
		if path == "." {
			break
		}
	}
	return parts
}

func copyUp(src, dst string) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	st := srcInfo.Sys().(*syscall.Stat_t)

	switch srcInfo.Mode() & os.ModeType {
	case os.ModeDir:
		if err := os.Mkdir(dst, srcInfo.Mode().Perm()); err != nil && !os.IsExist(err) {
			return err
		}
	case os.ModeSymlink:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, dst); err != nil {
			return err
		}
	default:
		srcFile, err := os.Open(src)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode().Perm())
		if err != nil {
			return err
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return err
		}
	}

	os.Lchown(dst, int(st.Uid), int(st.Gid))
	if srcInfo.Mode()&os.ModeSymlink == 0 {
		os.Chmod(dst, srcInfo.Mode().Perm())
	}

	copyXattrs(src, dst)

	return nil
}

func copyXattrs(src, dst string) {
	list := make([]byte, 4096)
	n, err := unix.Llistxattr(src, list)
	if err != nil || n == 0 {
		return
	}

	names := splitXattrList(list[:n])
	for _, name := range names {
		val := make([]byte, 4096)
		vn, err := unix.Lgetxattr(src, name, val)
		if err != nil {
			continue
		}
		unix.Lsetxattr(dst, name, val[:vn], 0)
	}
}
