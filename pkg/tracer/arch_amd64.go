package tracer

import "syscall"

const (
	SYS_OPEN       = 2
	SYS_CLOSE      = 3
	SYS_STAT       = 4
	SYS_FSTAT      = 5
	SYS_LSTAT      = 6
	SYS_DUP        = 32
	SYS_DUP2       = 33
	SYS_GETPID     = 39
	SYS_EXECVE     = 59
	SYS_CHDIR      = 80
	SYS_FCHDIR     = 81
	SYS_RMDIR      = 84
	SYS_UNLINK     = 87
	SYS_READLINK   = 89
	SYS_STATFS     = 137
	SYS_GETXATTR   = 191
	SYS_LGETXATTR  = 192
	SYS_LISTXATTR  = 194
	SYS_LLISTXATTR = 195
	SYS_GETDENTS64 = 217
	SYS_OPENAT     = 257
	SYS_MKDIRAT    = 258
	SYS_FCHOWNAT   = 260
	SYS_NEWFSTATAT = 262
	SYS_UNLINKAT   = 263
	SYS_RENAMEAT   = 264
	SYS_LINKAT     = 265
	SYS_SYMLINKAT  = 266
	SYS_READLINKAT = 267
	SYS_FCHMODAT   = 268
	SYS_DUP3       = 292
	SYS_RENAMEAT2  = 316
	SYS_EXECVEAT   = 322
	SYS_STATX      = 332
	SYS_FACCESSAT2 = 439
)

func sysno(regs *syscall.PtraceRegs) uint64  { return regs.Orig_rax }
func setSysno(regs *syscall.PtraceRegs, v uint64) { regs.Orig_rax = v }
func retval(regs *syscall.PtraceRegs) uint64  { return regs.Rax }
func setRetval(regs *syscall.PtraceRegs, v uint64) { regs.Rax = v }
func arg0(regs *syscall.PtraceRegs) uint64    { return regs.Rdi }
func setArg0(regs *syscall.PtraceRegs, v uint64)  { regs.Rdi = v }
func arg1(regs *syscall.PtraceRegs) uint64    { return regs.Rsi }
func setArg1(regs *syscall.PtraceRegs, v uint64)  { regs.Rsi = v }
func arg2(regs *syscall.PtraceRegs) uint64    { return regs.Rdx }
func setArg2(regs *syscall.PtraceRegs, v uint64)  { regs.Rdx = v }
func arg3(regs *syscall.PtraceRegs) uint64    { return regs.R10 }
func setArg3(regs *syscall.PtraceRegs, v uint64)  { regs.R10 = v }
func sp(regs *syscall.PtraceRegs) uint64      { return regs.Rsp }
