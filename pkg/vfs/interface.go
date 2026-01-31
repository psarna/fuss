package vfs

type VFS interface {
	Open(path string, flags OpenFlags, mode uint32) (FileHandle, error)
	Stat(path string) (*FileInfo, error)
	Lstat(path string) (*FileInfo, error)
	Readlink(path string) (string, error)
	Access(path string, mode uint32) error

	Mkdir(path string, mode uint32) error
	Rmdir(path string) error
	Unlink(path string) error
	Rename(oldpath, newpath string, flags uint) error
	Link(oldpath, newpath string) error
	Symlink(target, linkpath string) error

	Chmod(path string, mode uint32) error
	Chown(path string, uid, gid int) error
	Lchown(path string, uid, gid int) error
	Truncate(path string, size int64) error
	Utimes(path string, atime, mtime int64) error

	Getxattr(path, name string) ([]byte, error)
	Setxattr(path, name string, value []byte, flags int) error
	Listxattr(path string) ([]string, error)
	Removexattr(path, name string) error
	Lgetxattr(path, name string) ([]byte, error)
	Lsetxattr(path, name string, value []byte, flags int) error
	Llistxattr(path string) ([]string, error)
	Lremovexattr(path, name string) error

	Statfs(path string) (*StatfsInfo, error)
}
