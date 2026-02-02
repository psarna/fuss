package vfs

type VFS interface {
	ResolveForOpen(path string, flags OpenFlags, mode uint32) (realPath string, err error)
	ResolveForStat(path string, followSymlinks bool) (realPath string, err error)
	ResolvePath(path string) (realPath string, err error)

	PrepareCreate(path string) (realPath string, err error)
	PrepareWrite(path string) (realPath string, err error)
	PrepareUnlink(path string) error
	PrepareRmdir(path string) error
	PrepareRename(oldpath, newpath string) (oldReal, newReal string, err error)
	PrepareLink(oldpath, newpath string) (oldReal, newReal string, err error)
	PrepareSymlink(linkpath string) (realPath string, err error)

	ReadDir(path string) ([]DirEntry, error)
}
