package vfs

import "syscall"

func statSetNlink(st *syscall.Stat_t, nlink uint64) {
	st.Nlink = nlink
}

func statSetBlksize(st *syscall.Stat_t, blksize int64) {
	st.Blksize = blksize
}
