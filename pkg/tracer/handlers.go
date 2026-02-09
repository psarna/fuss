package tracer

import (
	"encoding/binary"
	"syscall"

	"fuss/pkg/vfs"
)

const (
	SYS_OPEN       = 2
	SYS_CLOSE      = 3
	SYS_STAT       = 4
	SYS_FSTAT      = 5
	SYS_LSTAT      = 6
	SYS_EXECVE     = 59
	SYS_CHDIR      = 80
	SYS_FCHDIR     = 81
	SYS_DUP        = 32
	SYS_DUP2       = 33
	SYS_RMDIR      = 84
	SYS_UNLINK     = 87
	SYS_READLINK   = 89
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

	AT_FDCWD            = -100
	AT_SYMLINK_NOFOLLOW = 0x100
	AT_REMOVEDIR        = 0x200

	O_DIRECTORY = 0200000
)

const AT_FDCWD_U64 = 0xffffffffffffff9c

type SyscallHandler struct {
	tracer    *Tracer
	proc      *ProcessState
	regs      *syscall.PtraceRegs
	origPath  uintptr
	newPath   uintptr
	isDir     bool
	vfsPath   string
}

func (h *SyscallHandler) HandleEntry() {
	sysno := h.regs.Orig_rax
	debugf("syscall entry: %d rdi=%x rsi=%x rdx=%x r10=%x", sysno, h.regs.Rdi, h.regs.Rsi, h.regs.Rdx, h.regs.R10)

	switch sysno {
	case SYS_OPEN:
		h.handleOpenEntry()
	case SYS_OPENAT:
		h.handleOpenatEntry()
	case SYS_EXECVE:
		h.handleExecveEntry()
	case SYS_EXECVEAT:
		h.handleExecveatEntry()
	case SYS_CLOSE:
		h.handleCloseEntry()
	case SYS_STAT:
		h.handleStatEntry()
	case SYS_LSTAT:
		h.handleLstatEntry()
	case SYS_NEWFSTATAT:
		h.handleNewfstatatEntry()
	case SYS_GETDENTS64:
		h.handleGetdents64Entry()
	case SYS_MKDIRAT:
		h.handleMkdiratEntry()
	case SYS_UNLINK:
		h.handleUnlinkEntry()
	case SYS_RMDIR:
		h.handleRmdirEntry()
	case SYS_UNLINKAT:
		h.handleUnlinkatEntry()
	case SYS_RENAMEAT, SYS_RENAMEAT2:
		h.handleRenameatEntry()
	case SYS_LINKAT:
		h.handleLinkatEntry()
	case SYS_SYMLINKAT:
		h.handleSymlinkatEntry()
	case SYS_READLINK:
		h.handleReadlinkEntry()
	case SYS_READLINKAT:
		h.handleReadlinkatEntry()
	case SYS_FCHMODAT:
		h.handleFchmodatEntry()
	case SYS_FCHOWNAT:
		h.handleFchownatEntry()
	case SYS_FACCESSAT2:
		h.handleFaccessat2Entry()
	case SYS_STATX:
		h.handleStatxEntry()
	case SYS_DUP:
		h.handleDupEntry()
	case SYS_DUP2, SYS_DUP3:
		h.handleDup2Entry()
	case SYS_CHDIR:
		h.handleChdirEntry()
	case SYS_FCHDIR:
		h.handleFchdirEntry()
	}
}

func (h *SyscallHandler) HandleExit() {
	sysno := h.regs.Orig_rax

	switch sysno {
	case SYS_OPEN:
		h.handleOpenatExit()
	case SYS_OPENAT:
		h.handleOpenatExit()
	case SYS_DUP:
		h.handleDupExit()
	case SYS_DUP2, SYS_DUP3:
		h.handleDup2Exit()
	case SYS_CHDIR:
		h.handleChdirExit()
	case SYS_FCHDIR:
		h.handleFchdirExit()
	}
}

func (h *SyscallHandler) skipSyscall(result int64) {
	h.regs.Orig_rax = ^uint64(0)
	h.regs.Rax = uint64(result)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) readPathAt(dirfd int, pathAddr uintptr) (string, bool) {
	path, err := ReadString(h.proc.pid, pathAddr, 4096)
	if err != nil {
		debugf("readPathAt: ReadString failed: pid=%d addr=%x err=%v", h.proc.pid, pathAddr, err)
		return "", false
	}
	if path == "" {
		debugf("readPathAt: empty path (pid=%d addr=%x)", h.proc.pid, pathAddr)
		return "", false
	}

	resolved := h.tracer.resolver.ResolveAt(dirfd, path, h.proc.cwd, h.proc.fdPaths)
	shouldIntercept := h.tracer.resolver.ShouldIntercept(resolved)
	debugf("readPathAt: path=%q resolved=%q shouldIntercept=%v", path, resolved, shouldIntercept)
	if !shouldIntercept {
		return "", false
	}

	vfsPath := h.tracer.resolver.TranslatePath(resolved)
	logIntercept(h.regs.Orig_rax, path, resolved, vfsPath)
	return vfsPath, true
}

func (h *SyscallHandler) rewritePath(pathAddr uintptr, newPath string) (uintptr, error) {
	stackAddr := uintptr(h.regs.Rsp) - 4096
	if err := WriteString(h.proc.pid, stackAddr, newPath); err != nil {
		debugf("rewritePath: WriteString failed: %v (addr=%x path=%q)", err, stackAddr, newPath)
		return 0, err
	}
	return stackAddr, nil
}

func (h *SyscallHandler) handleOpenatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	flags := int(h.regs.Rdx)
	mode := uint32(h.regs.R10)

	rawPath, _ := ReadString(h.proc.pid, pathAddr, 4096)
	debugf("openat: dirfd=%d path=%q flags=0x%x mode=0%o", dirfd, rawPath, flags, mode)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		debugf("openat: not intercepting %q", rawPath)
		return
	}

	debugf("openat: intercepting %q -> vfs %q", rawPath, vfsPath)

	realPath, err := h.tracer.vfs.ResolveForOpen(vfsPath, vfs.OpenFlags(flags), mode)
	if err != nil {
		debugf("openat: ResolveForOpen failed: %v", err)
		h.skipSyscall(errnoFromError(err))
		return
	}

	debugf("openat: resolved to real path %q", realPath)

	h.origPath = pathAddr
	newPath, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.newPath = newPath
	h.regs.Rsi = uint64(h.newPath)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)

	h.isDir = flags&O_DIRECTORY != 0
	h.vfsPath = vfsPath

	resolved := h.tracer.resolver.ResolveAt(dirfd, rawPath, h.proc.cwd, h.proc.fdPaths)
	h.proc.pendingOpen = &pendingOpen{
		path:  resolved,
		isDir: h.isDir,
		vfsPath: vfsPath,
	}
}

func (h *SyscallHandler) handleOpenEntry() {
	pathAddr := uintptr(h.regs.Rdi)
	flags := int(h.regs.Rsi)
	mode := uint32(h.regs.Rdx)

	rawPath, _ := ReadString(h.proc.pid, pathAddr, 4096)
	debugf("open: path=%q flags=0x%x mode=0%o", rawPath, flags, mode)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		debugf("open: not intercepting %q", rawPath)
		return
	}

	debugf("open: intercepting %q -> vfs %q", rawPath, vfsPath)

	realPath, err := h.tracer.vfs.ResolveForOpen(vfsPath, vfs.OpenFlags(flags), mode)
	if err != nil {
		debugf("open: ResolveForOpen failed: %v", err)
		h.skipSyscall(errnoFromError(err))
		return
	}

	debugf("open: resolved to real path %q", realPath)

	h.origPath = pathAddr
	newPath, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.newPath = newPath
	h.regs.Rdi = uint64(h.newPath)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)

	h.isDir = flags&O_DIRECTORY != 0
	h.vfsPath = vfsPath

	resolved := h.tracer.resolver.ResolveAt(AT_FDCWD, rawPath, h.proc.cwd, h.proc.fdPaths)
	h.proc.pendingOpen = &pendingOpen{
		path:    resolved,
		isDir:   h.isDir,
		vfsPath: vfsPath,
	}
}

func (h *SyscallHandler) handleOpenatExit() {
	if h.proc.pendingOpen == nil {
		return
	}

	pending := h.proc.pendingOpen
	h.proc.pendingOpen = nil

	fd := int(int64(h.regs.Rax))
	if fd < 0 {
		debugf("openat exit: failed with %d", fd)
		return
	}

	debugf("openat exit: fd=%d path=%q isDir=%v", fd, pending.path, pending.isDir)

	h.proc.fdPaths[fd] = pending.path

	if pending.isDir {
		h.tracer.fdTable.TrackDir(fd, pending.vfsPath)
	}
}

func (h *SyscallHandler) handleCloseEntry() {
	fd := int(h.regs.Rdi)
	debugf("close: fd=%d", fd)

	h.tracer.fdTable.Close(fd)
	delete(h.proc.fdPaths, fd)
}

func (h *SyscallHandler) handleStatEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.ResolveForStat(vfsPath, true)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rdi = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleLstatEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.ResolveForStat(vfsPath, false)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rdi = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleNewfstatatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	flags := int(h.regs.R10)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	followSymlinks := flags&AT_SYMLINK_NOFOLLOW == 0
	realPath, err := h.tracer.vfs.ResolveForStat(vfsPath, followSymlinks)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleGetdents64Entry() {
	fd := int(h.regs.Rdi)
	bufAddr := uintptr(h.regs.Rsi)
	count := int(h.regs.Rdx)

	vfsPath, ok := h.tracer.fdTable.GetDir(fd)
	if !ok {
		return
	}

	debugf("getdents64: fd=%d path=%q", fd, vfsPath)

	entries, err := h.tracer.vfs.ReadDir(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	pos := h.tracer.fdTable.GetDirPos(fd)
	if pos >= len(entries) {
		h.skipSyscall(0)
		return
	}

	buf := make([]byte, count)
	offset := 0
	entriesRead := 0

	for i := pos; i < len(entries) && offset < count; i++ {
		entry := &entries[i]
		reclen := (19 + len(entry.Name) + 1 + 7) & ^7

		if offset+reclen > count {
			break
		}

		binary.LittleEndian.PutUint64(buf[offset:], entry.Ino)
		binary.LittleEndian.PutUint64(buf[offset+8:], uint64(entry.Offset))
		binary.LittleEndian.PutUint16(buf[offset+16:], uint16(reclen))
		buf[offset+18] = entry.Type
		copy(buf[offset+19:], entry.Name)
		buf[offset+19+len(entry.Name)] = 0

		offset += reclen
		entriesRead++
	}

	if offset > 0 {
		WriteBytes(h.proc.pid, bufAddr, buf[:offset])
	}

	h.tracer.fdTable.SetDirPos(fd, pos+entriesRead)
	h.skipSyscall(int64(offset))
}

func (h *SyscallHandler) handleMkdiratEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.PrepareCreate(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleUnlinkEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.PrepareUnlink(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleRmdirEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.PrepareRmdir(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleUnlinkatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	flags := int(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	var err error
	if flags&AT_REMOVEDIR != 0 {
		err = h.tracer.vfs.PrepareRmdir(vfsPath)
	} else {
		err = h.tracer.vfs.PrepareUnlink(vfsPath)
	}

	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleRenameatEntry() {
	oldDirfd := int(int32(h.regs.Rdi))
	oldPathAddr := uintptr(h.regs.Rsi)
	newDirfd := int(int32(h.regs.Rdx))
	newPathAddr := uintptr(h.regs.R10)

	oldVfsPath, oldIntercept := h.readPathAt(oldDirfd, oldPathAddr)
	newVfsPath, newIntercept := h.readPathAt(newDirfd, newPathAddr)

	if !oldIntercept && !newIntercept {
		return
	}

	if oldIntercept != newIntercept {
		h.skipSyscall(negErrno(syscall.EXDEV))
		return
	}

	oldReal, newReal, err := h.tracer.vfs.PrepareRename(oldVfsPath, newVfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	oldAddr, err := h.rewritePath(oldPathAddr, oldReal)
	if err != nil {
		return
	}
	newAddr := uintptr(h.regs.Rsp) - 8192
	if err := WriteString(h.proc.pid, newAddr, newReal); err != nil {
		return
	}

	h.regs.Rdi = AT_FDCWD_U64
	h.regs.Rsi = uint64(oldAddr)
	h.regs.Rdx = AT_FDCWD_U64
	h.regs.R10 = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleLinkatEntry() {
	oldDirfd := int(int32(h.regs.Rdi))
	oldPathAddr := uintptr(h.regs.Rsi)
	newDirfd := int(int32(h.regs.Rdx))
	newPathAddr := uintptr(h.regs.R10)

	oldVfsPath, oldIntercept := h.readPathAt(oldDirfd, oldPathAddr)
	newVfsPath, newIntercept := h.readPathAt(newDirfd, newPathAddr)

	if !oldIntercept && !newIntercept {
		return
	}

	if oldIntercept != newIntercept {
		h.skipSyscall(negErrno(syscall.EXDEV))
		return
	}

	oldReal, newReal, err := h.tracer.vfs.PrepareLink(oldVfsPath, newVfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	oldAddr, err := h.rewritePath(oldPathAddr, oldReal)
	if err != nil {
		return
	}
	newAddr := uintptr(h.regs.Rsp) - 8192
	if err := WriteString(h.proc.pid, newAddr, newReal); err != nil {
		return
	}

	h.regs.Rdi = AT_FDCWD_U64
	h.regs.Rsi = uint64(oldAddr)
	h.regs.Rdx = AT_FDCWD_U64
	h.regs.R10 = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleSymlinkatEntry() {
	targetAddr := uintptr(h.regs.Rdi)
	newDirfd := int(int32(h.regs.Rsi))
	linkpathAddr := uintptr(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(newDirfd, linkpathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.PrepareSymlink(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(linkpathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = AT_FDCWD_U64
	h.regs.Rdx = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
	_ = targetAddr
}

func (h *SyscallHandler) handleExecveEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		rawPath, err := ReadString(h.proc.pid, pathAddr, 4096)
		if err != nil {
			debugf("execve: ReadString failed: pid=%d addr=%x err=%v", h.proc.pid, pathAddr, err)
		} else {
			debugf("execve: not intercepting path %q", rawPath)
		}
		return
	}

	debugf("execve: intercepting vfs path %q", vfsPath)

	realPath, err := h.tracer.vfs.ResolvePath(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	debugf("execve: resolved to real path %q", realPath)

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rdi = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleExecveatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	debugf("execveat: intercepting vfs path %q", vfsPath)

	realPath, err := h.tracer.vfs.ResolvePath(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	debugf("execveat: resolved to real path %q", realPath)

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleReadlinkatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.ResolvePath(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleReadlinkEntry() {
	pathAddr := uintptr(h.regs.Rdi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.ResolvePath(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rdi = uint64(newAddr)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleFchmodatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.PrepareWrite(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleFchownatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.PrepareWrite(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleFaccessat2Entry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	realPath, err := h.tracer.vfs.ResolvePath(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleStatxEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	flags := int(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	followSymlinks := flags&AT_SYMLINK_NOFOLLOW == 0
	realPath, err := h.tracer.vfs.ResolveForStat(vfsPath, followSymlinks)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	newAddr, err := h.rewritePath(pathAddr, realPath)
	if err != nil {
		return
	}
	h.regs.Rsi = uint64(newAddr)
	h.regs.Rdi = AT_FDCWD_U64
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) handleDupEntry() {
	h.proc.pendingDup = &pendingDup{
		oldfd: int(h.regs.Rdi),
		newfd: -1,
	}
}

func (h *SyscallHandler) handleDupExit() {
	if h.proc.pendingDup == nil {
		return
	}

	pending := h.proc.pendingDup
	h.proc.pendingDup = nil

	newfd := int(int64(h.regs.Rax))
	if newfd < 0 {
		return
	}

	h.tracer.fdTable.Dup(pending.oldfd, newfd)
	if path, ok := h.proc.fdPaths[pending.oldfd]; ok {
		h.proc.fdPaths[newfd] = path
	}
}

func (h *SyscallHandler) handleDup2Entry() {
	h.proc.pendingDup = &pendingDup{
		oldfd: int(h.regs.Rdi),
		newfd: int(h.regs.Rsi),
	}
}

func (h *SyscallHandler) handleDup2Exit() {
	if h.proc.pendingDup == nil {
		return
	}

	pending := h.proc.pendingDup
	h.proc.pendingDup = nil

	result := int(int64(h.regs.Rax))
	if result < 0 {
		return
	}

	h.tracer.fdTable.Close(pending.newfd)
	h.tracer.fdTable.Dup(pending.oldfd, pending.newfd)
	if path, ok := h.proc.fdPaths[pending.oldfd]; ok {
		h.proc.fdPaths[pending.newfd] = path
	}
}

func (h *SyscallHandler) handleChdirEntry() {
	pathAddr := uintptr(h.regs.Rdi)
	path, err := ReadString(h.proc.pid, pathAddr, 4096)
	if err != nil {
		return
	}

	resolved := h.tracer.resolver.ResolvePath(h.proc.cwd, path)
	h.proc.pendingChdir = &pendingChdir{path: resolved}
}

func (h *SyscallHandler) handleChdirExit() {
	if h.proc.pendingChdir == nil {
		return
	}

	pending := h.proc.pendingChdir
	h.proc.pendingChdir = nil

	result := int(int64(h.regs.Rax))
	if result != 0 {
		return
	}

	h.proc.cwd = pending.path
	debugf("chdir: cwd now %q", h.proc.cwd)
}

func (h *SyscallHandler) handleFchdirEntry() {
	fd := int(h.regs.Rdi)
	h.proc.pendingChdir = &pendingChdir{fd: fd}
}

func (h *SyscallHandler) handleFchdirExit() {
	if h.proc.pendingChdir == nil {
		return
	}

	pending := h.proc.pendingChdir
	h.proc.pendingChdir = nil

	result := int(int64(h.regs.Rax))
	if result != 0 {
		return
	}

	if path, ok := h.proc.fdPaths[pending.fd]; ok {
		h.proc.cwd = path
		debugf("fchdir: cwd now %q", h.proc.cwd)
	}
}

func errnoFromError(err error) int64 {
	if err == nil {
		return 0
	}
	if errno, ok := err.(syscall.Errno); ok {
		return -int64(errno)
	}
	return -int64(syscall.EIO)
}

func negErrno(e syscall.Errno) int64 {
	return -int64(e)
}
