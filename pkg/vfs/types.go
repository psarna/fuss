package vfs

import (
	"syscall"
	"time"
)

type FileInfo struct {
	Name    string
	Size    int64
	Mode    uint32
	ModTime time.Time
	IsDir   bool
	Nlink   uint64
	Uid     uint32
	Gid     uint32
	Rdev    uint64
	Ino     uint64
	Blksize int64
	Blocks  int64
	Atime   time.Time
	Ctime   time.Time
}

func (fi *FileInfo) ToStat() syscall.Stat_t {
	return syscall.Stat_t{
		Dev:     0,
		Ino:     fi.Ino,
		Nlink:   fi.Nlink,
		Mode:    fi.Mode,
		Uid:     fi.Uid,
		Gid:     fi.Gid,
		Rdev:    fi.Rdev,
		Size:    fi.Size,
		Blksize: fi.Blksize,
		Blocks:  fi.Blocks,
		Atim:    syscall.Timespec{Sec: fi.Atime.Unix(), Nsec: int64(fi.Atime.Nanosecond())},
		Mtim:    syscall.Timespec{Sec: fi.ModTime.Unix(), Nsec: int64(fi.ModTime.Nanosecond())},
		Ctim:    syscall.Timespec{Sec: fi.Ctime.Unix(), Nsec: int64(fi.Ctime.Nanosecond())},
	}
}

func FileInfoFromStat(name string, st *syscall.Stat_t) *FileInfo {
	return &FileInfo{
		Name:    name,
		Size:    st.Size,
		Mode:    st.Mode,
		ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
		IsDir:   st.Mode&syscall.S_IFDIR != 0,
		Nlink:   st.Nlink,
		Uid:     st.Uid,
		Gid:     st.Gid,
		Rdev:    st.Rdev,
		Ino:     st.Ino,
		Blksize: st.Blksize,
		Blocks:  st.Blocks,
		Atime:   time.Unix(st.Atim.Sec, st.Atim.Nsec),
		Ctime:   time.Unix(st.Ctim.Sec, st.Ctim.Nsec),
	}
}

type DirEntry struct {
	Name   string
	Type   uint8
	Ino    uint64
	Offset int64
}

type OpenFlags int

const (
	O_RDONLY OpenFlags = syscall.O_RDONLY
	O_WRONLY OpenFlags = syscall.O_WRONLY
	O_RDWR   OpenFlags = syscall.O_RDWR
	O_APPEND OpenFlags = syscall.O_APPEND
	O_CREAT  OpenFlags = syscall.O_CREAT
	O_EXCL   OpenFlags = syscall.O_EXCL
	O_TRUNC  OpenFlags = syscall.O_TRUNC
)

func (f OpenFlags) IsWrite() bool {
	return f&O_WRONLY != 0 || f&O_RDWR != 0
}

func (f OpenFlags) IsCreate() bool {
	return f&O_CREAT != 0
}

func (f OpenFlags) IsTrunc() bool {
	return f&O_TRUNC != 0
}

type StatfsInfo struct {
	Type    int64
	Bsize   int64
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Fsid    [2]int32
	Namelen int64
	Frsize  int64
	Flags   int64
}

func (si *StatfsInfo) ToStatfs() syscall.Statfs_t {
	return syscall.Statfs_t{
		Type:    si.Type,
		Bsize:   si.Bsize,
		Blocks:  si.Blocks,
		Bfree:   si.Bfree,
		Bavail:  si.Bavail,
		Files:   si.Files,
		Ffree:   si.Ffree,
		Fsid:    syscall.Fsid{X__val: si.Fsid},
		Namelen: si.Namelen,
		Frsize:  si.Frsize,
		Flags:   si.Flags,
	}
}
