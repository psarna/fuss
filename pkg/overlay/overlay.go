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

	dir := filepath.Dir(path)
	if dir != "." && dir != "/" {
		upperDir := filepath.Join(fs.upperDir, dir)
		if isOpaqueDir(upperDir) {
			return "", false, syscall.ENOENT
		}
	}

	for i, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, path)

		if isWhiteout(lowerPath) {
			return "", false, syscall.ENOENT
		}

		for j := 0; j < i; j++ {
			higherLowerPath := filepath.Join(fs.lowerDirs[j], path)
			if isWhiteout(higherLowerPath) {
				return "", false, syscall.ENOENT
			}
		}

		if _, err := os.Lstat(lowerPath); err == nil {
			return lowerPath, false, nil
		}
	}

	return "", false, syscall.ENOENT
}

func (fs *OverlayFS) ResolveForOpen(path string, flags vfs.OpenFlags, mode uint32) (string, error) {
	realPath, inUpper, err := fs.resolve(path)

	if flags.IsCreate() && err != nil {
		if err := fs.copyUpParents(path); err != nil {
			return "", err
		}
		upperPath := filepath.Join(fs.upperDir, path)
		removeWhiteout(upperPath, fs.whiteoutStyle)
		return upperPath, nil
	}

	if err != nil {
		return "", err
	}

	if flags.IsWrite() || flags.IsTrunc() {
		if !inUpper {
			if err := fs.copyUp(path); err != nil {
				return "", err
			}
			return filepath.Join(fs.upperDir, path), nil
		}
	}

	return realPath, nil
}

func (fs *OverlayFS) ResolveForStat(path string, followSymlinks bool) (string, error) {
	realPath, _, err := fs.resolve(path)
	return realPath, err
}

func (fs *OverlayFS) ResolvePath(path string) (string, error) {
	realPath, _, err := fs.resolve(path)
	return realPath, err
}

func (fs *OverlayFS) PrepareCreate(path string) (string, error) {
	if err := fs.copyUpParents(path); err != nil {
		return "", err
	}
	upperPath := filepath.Join(fs.upperDir, path)
	removeWhiteout(upperPath, fs.whiteoutStyle)
	return upperPath, nil
}

func (fs *OverlayFS) PrepareWrite(path string) (string, error) {
	if err := fs.copyUp(path); err != nil {
		return "", err
	}
	return filepath.Join(fs.upperDir, path), nil
}

func (fs *OverlayFS) PrepareUnlink(path string) error {
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

func (fs *OverlayFS) PrepareRmdir(path string) error {
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

func (fs *OverlayFS) PrepareRename(oldpath, newpath string) (string, string, error) {
	if err := fs.copyUp(oldpath); err != nil {
		return "", "", err
	}
	if err := fs.copyUpParents(newpath); err != nil {
		return "", "", err
	}

	oldUpper := filepath.Join(fs.upperDir, oldpath)
	newUpper := filepath.Join(fs.upperDir, newpath)

	removeWhiteout(newUpper, fs.whiteoutStyle)

	for _, lower := range fs.lowerDirs {
		lowerPath := filepath.Join(lower, oldpath)
		if _, err := os.Lstat(lowerPath); err == nil {
			if err := fs.createWhiteout(oldpath); err != nil {
				return "", "", err
			}
			break
		}
	}

	return oldUpper, newUpper, nil
}

func (fs *OverlayFS) PrepareLink(oldpath, newpath string) (string, string, error) {
	if err := fs.copyUp(oldpath); err != nil {
		return "", "", err
	}
	if err := fs.copyUpParents(newpath); err != nil {
		return "", "", err
	}

	oldUpper := filepath.Join(fs.upperDir, oldpath)
	newUpper := filepath.Join(fs.upperDir, newpath)

	removeWhiteout(newUpper, fs.whiteoutStyle)

	return oldUpper, newUpper, nil
}

func (fs *OverlayFS) PrepareSymlink(linkpath string) (string, error) {
	if err := fs.copyUpParents(linkpath); err != nil {
		return "", err
	}

	upperPath := filepath.Join(fs.upperDir, linkpath)
	removeWhiteout(upperPath, fs.whiteoutStyle)

	return upperPath, nil
}

func (fs *OverlayFS) ReadDir(path string) ([]vfs.DirEntry, error) {
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

	result := merger.Entries()
	for i := range result {
		result[i].Offset = int64(i + 1)
	}
	return result, nil
}

func (fs *OverlayFS) createWhiteout(path string) error {
	if err := fs.copyUpParents(path); err != nil {
		return err
	}
	return createWhiteout(filepath.Join(fs.upperDir, path), fs.whiteoutStyle)
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
