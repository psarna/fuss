package tracer

import "syscall"

const (
	SYS_GETXATTR   = 8
	SYS_LGETXATTR  = 9
	SYS_LISTXATTR  = 11
	SYS_LLISTXATTR = 12
	SYS_DUP        = 23
	SYS_DUP3       = 24
	SYS_MKDIRAT    = 34
	SYS_UNLINKAT   = 35
	SYS_SYMLINKAT  = 36
	SYS_LINKAT     = 37
	SYS_RENAMEAT2  = 276
	SYS_STATFS     = 43
	SYS_CHDIR      = 49
	SYS_FCHDIR     = 50
	SYS_FCHMODAT   = 53
	SYS_FCHOWNAT   = 54
	SYS_OPENAT     = 56
	SYS_CLOSE      = 57
	SYS_GETDENTS64 = 61
	SYS_READLINKAT = 78
	SYS_NEWFSTATAT = 79
	SYS_FSTAT      = 80
	SYS_GETPID     = 172
	SYS_EXECVE     = 221
	SYS_EXECVEAT   = 281
	SYS_STATX      = 291
	SYS_FACCESSAT2 = 439

	SYS_OPEN     = 0xFFFF
	SYS_STAT     = 0xFFFF - 1
	SYS_LSTAT    = 0xFFFF - 2
	SYS_DUP2     = 0xFFFF - 3
	SYS_RMDIR    = 0xFFFF - 4
	SYS_UNLINK   = 0xFFFF - 5
	SYS_READLINK = 0xFFFF - 6
	SYS_RENAMEAT = 0xFFFF - 7
)

func sysno(regs *syscall.PtraceRegs) uint64       { return regs.Regs[8] }
func setSysno(regs *syscall.PtraceRegs, v uint64)  { regs.Regs[8] = v }
func retval(regs *syscall.PtraceRegs) uint64       { return regs.Regs[0] }
func setRetval(regs *syscall.PtraceRegs, v uint64) { regs.Regs[0] = v }
func arg0(regs *syscall.PtraceRegs) uint64         { return regs.Regs[0] }
func setArg0(regs *syscall.PtraceRegs, v uint64)   { regs.Regs[0] = v }
func arg1(regs *syscall.PtraceRegs) uint64         { return regs.Regs[1] }
func setArg1(regs *syscall.PtraceRegs, v uint64)   { regs.Regs[1] = v }
func arg2(regs *syscall.PtraceRegs) uint64         { return regs.Regs[2] }
func setArg2(regs *syscall.PtraceRegs, v uint64)   { regs.Regs[2] = v }
func arg3(regs *syscall.PtraceRegs) uint64         { return regs.Regs[3] }
func setArg3(regs *syscall.PtraceRegs, v uint64)   { regs.Regs[3] = v }
func sp(regs *syscall.PtraceRegs) uint64           { return regs.Sp }
