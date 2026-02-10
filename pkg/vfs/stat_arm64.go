package vfs

import "syscall"

func statSetNlink(st *syscall.Stat_t, nlink uint64) {
	st.Nlink = uint32(nlink)
}

func statSetBlksize(st *syscall.Stat_t, blksize int64) {
	st.Blksize = int32(blksize)
}
