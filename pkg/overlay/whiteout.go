package overlay

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type WhiteoutStyle int

const (
	WhiteoutFilePrefix WhiteoutStyle = iota
	WhiteoutCharDevice
)

const (
	whiteoutPrefix   = ".wh."
	opaqueMarkerFile = ".wh..wh..opq"
	opaqueXattrName  = "trusted.overlay.opaque"
)

func whiteoutName(name string) string {
	return whiteoutPrefix + name
}

func whiteoutTarget(whName string) string {
	return strings.TrimPrefix(whName, whiteoutPrefix)
}

func isWhiteoutName(name string) bool {
	return strings.HasPrefix(name, whiteoutPrefix)
}

func isWhiteout(path string) bool {
	if isWhiteoutFile(path) {
		return true
	}
	if isWhiteoutCharDev(path) {
		return true
	}
	return false
}

func isWhiteoutFile(path string) bool {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	whPath := filepath.Join(dir, whiteoutPrefix+name)

	info, err := os.Lstat(whPath)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func isWhiteoutCharDev(path string) bool {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return false
	}

	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return false
	}

	return st.Rdev == 0
}

func isOpaqueDir(path string) bool {
	if isOpaqueByXattr(path) {
		return true
	}
	if isOpaqueByFile(path) {
		return true
	}
	return false
}

func isOpaqueByXattr(path string) bool {
	val := make([]byte, 16)
	n, err := unix.Getxattr(path, opaqueXattrName, val)
	if err != nil || n == 0 {
		return false
	}
	return string(val[:n]) == "y"
}

func isOpaqueByFile(path string) bool {
	opqPath := filepath.Join(path, opaqueMarkerFile)
	_, err := os.Lstat(opqPath)
	return err == nil
}

func createWhiteout(path string, style WhiteoutStyle) error {
	dir := filepath.Dir(path)
	name := filepath.Base(path)

	switch style {
	case WhiteoutCharDevice:
		return unix.Mknod(path, syscall.S_IFCHR|0666, 0)
	case WhiteoutFilePrefix:
		fallthrough
	default:
		whPath := filepath.Join(dir, whiteoutPrefix+name)
		f, err := os.Create(whPath)
		if err != nil {
			return err
		}
		return f.Close()
	}
}

func removeWhiteout(path string, style WhiteoutStyle) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)

	whPath := filepath.Join(dir, whiteoutPrefix+name)
	os.Remove(whPath)

	if isWhiteoutCharDev(path) {
		os.Remove(path)
	}
}

func setOpaqueDir(path string, style WhiteoutStyle) error {
	switch style {
	case WhiteoutCharDevice:
		return unix.Setxattr(path, opaqueXattrName, []byte("y"), 0)
	case WhiteoutFilePrefix:
		fallthrough
	default:
		opqPath := filepath.Join(path, opaqueMarkerFile)
		f, err := os.Create(opqPath)
		if err != nil {
			return err
		}
		return f.Close()
	}
}
