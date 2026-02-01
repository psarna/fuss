package tracer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	"fuss/pkg/vfs"
)

var debug = os.Getenv("FUSS_DEBUG") != ""

func debugf(format string, args ...interface{}) {
	if debug {
		fmt.Fprintf(os.Stderr, "[FUSS] "+format+"\n", args...)
	}
}

const (
	SYS_READ       = 0
	SYS_WRITE      = 1
	SYS_OPEN       = 2
	SYS_CLOSE      = 3
	SYS_STAT       = 4
	SYS_FSTAT      = 5
	SYS_LSTAT      = 6
	SYS_LSEEK      = 8
	SYS_DUP        = 32
	SYS_DUP2       = 33
	SYS_FCNTL      = 72
	SYS_FTRUNCATE  = 77
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
	SYS_FACCESSAT2 = 439

	AT_FDCWD            = -100
	AT_SYMLINK_NOFOLLOW = 0x100
	AT_REMOVEDIR        = 0x200
)

type SyscallHandler struct {
	tracer    *Tracer
	proc      *ProcessState
	regs      *syscall.PtraceRegs
	savedRegs *syscall.PtraceRegs
	handled   bool
	result    int64
}

func (h *SyscallHandler) HandleEntry() {
	sysno := h.regs.Orig_rax
	debugf("syscall entry: %d rdi=%x rsi=%x rdx=%x r10=%x", sysno, h.regs.Rdi, h.regs.Rsi, h.regs.Rdx, h.regs.R10)

	switch sysno {
	case SYS_OPENAT:
		h.handleOpenatEntry()
	case SYS_OPEN:
		h.handleOpenEntry()
	case SYS_CLOSE:
		h.handleCloseEntry()
	case SYS_READ:
		h.handleReadEntry()
	case SYS_WRITE:
		h.handleWriteEntry()
	case SYS_FSTAT:
		h.handleFstatEntry()
	case SYS_STAT:
		h.handleStatEntry()
	case SYS_LSTAT:
		h.handleLstatEntry()
	case SYS_NEWFSTATAT:
		h.handleNewfstatatEntry()
	case SYS_LSEEK:
		h.handleLseekEntry()
	case SYS_GETDENTS64:
		h.handleGetdents64Entry()
	case SYS_MKDIRAT:
		h.handleMkdiratEntry()
	case SYS_UNLINKAT:
		h.handleUnlinkatEntry()
	case SYS_RENAMEAT, SYS_RENAMEAT2:
		h.handleRenameatEntry()
	case SYS_LINKAT:
		h.handleLinkatEntry()
	case SYS_SYMLINKAT:
		h.handleSymlinkatEntry()
	case SYS_READLINKAT:
		h.handleReadlinkatEntry()
	case SYS_FCHMODAT:
		h.handleFchmodatEntry()
	case SYS_FCHOWNAT:
		h.handleFchownatEntry()
	case SYS_FACCESSAT2:
		h.handleFaccessat2Entry()
	case SYS_FTRUNCATE:
		h.handleFtruncateEntry()
	case SYS_DUP:
		h.handleDupEntry()
	case SYS_DUP2:
		h.handleDup2Entry()
	case SYS_DUP3:
		h.handleDup3Entry()
	case SYS_FCNTL:
		h.handleFcntlEntry()
	}
}

func (h *SyscallHandler) HandleExit() {
}

func (h *SyscallHandler) skipSyscall(result int64) {
	h.regs.Orig_rax = ^uint64(0)
	h.regs.Rax = uint64(result)
	syscall.PtraceSetRegs(h.proc.pid, h.regs)
}

func (h *SyscallHandler) readPathAt(dirfd int, pathAddr uintptr) (string, bool) {
	path, err := ReadString(h.proc.pid, pathAddr, 4096)
	if err != nil {
		return "", false
	}

	resolved := h.tracer.resolver.ResolveAt(dirfd, path, h.proc.cwd, h.proc.fdPaths)
	shouldIntercept := h.tracer.resolver.ShouldIntercept(resolved)
	debugf("readPathAt: path=%q resolved=%q shouldIntercept=%v", path, resolved, shouldIntercept)
	if !shouldIntercept {
		return "", false
	}

	return h.tracer.resolver.TranslatePath(resolved), true
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

	fh, err := h.tracer.vfs.Open(vfsPath, vfs.OpenFlags(flags), mode)
	if err != nil {
		debugf("openat: vfs.Open failed: %v", err)
		h.skipSyscall(errnoFromError(err))
		return
	}

	fd := h.tracer.fdTable.Allocate(fh)

	resolved := h.tracer.resolver.ResolveAt(dirfd, rawPath, h.proc.cwd, h.proc.fdPaths)
	h.proc.fdPaths[fd] = resolved

	debugf("openat: success, returning fd=%d", fd)
	h.skipSyscall(int64(fd))
}

func (h *SyscallHandler) handleOpenEntry() {
	pathAddr := uintptr(h.regs.Rdi)
	flags := int(h.regs.Rsi)
	mode := uint32(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	fh, err := h.tracer.vfs.Open(vfsPath, vfs.OpenFlags(flags), mode)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	fd := h.tracer.fdTable.Allocate(fh)

	rawPath, _ := ReadString(h.proc.pid, pathAddr, 4096)
	resolved := h.tracer.resolver.ResolvePath(h.proc.cwd, rawPath)
	h.proc.fdPaths[fd] = resolved

	h.skipSyscall(int64(fd))
}

func (h *SyscallHandler) handleCloseEntry() {
	fd := int(h.regs.Rdi)
	debugf("close: fd=%d isVirtual=%v", fd, h.tracer.fdTable.IsVirtual(fd))

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	h.tracer.fdTable.Close(fd)
	delete(h.proc.fdPaths, fd)
	debugf("close: fd=%d success", fd)
	h.skipSyscall(0)
}

func (h *SyscallHandler) handleReadEntry() {
	fd := int(h.regs.Rdi)
	bufAddr := uintptr(h.regs.Rsi)
	count := int(h.regs.Rdx)
	debugf("read: fd=%d count=%d isVirtual=%v", fd, count, h.tracer.fdTable.IsVirtual(fd))

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	buf := make([]byte, count)
	n, err := fh.Read(buf)
	debugf("read: fd=%d result n=%d err=%v", fd, n, err)
	if n == 0 && err != nil {
		if err == io.EOF {
			h.skipSyscall(0)
			return
		}
		h.skipSyscall(errnoFromError(err))
		return
	}

	if n > 0 {
		WriteBytes(h.proc.pid, bufAddr, buf[:n])
	}

	h.skipSyscall(int64(n))
}

func (h *SyscallHandler) handleWriteEntry() {
	fd := int(h.regs.Rdi)
	bufAddr := uintptr(h.regs.Rsi)
	count := int(h.regs.Rdx)

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	buf := make([]byte, count)
	ReadBytes(h.proc.pid, bufAddr, buf)

	n, err := fh.Write(buf)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(int64(n))
}

func (h *SyscallHandler) handleFstatEntry() {
	fd := int(h.regs.Rdi)
	statAddr := uintptr(h.regs.Rsi)
	debugf("fstat: fd=%d isVirtual=%v", fd, h.tracer.fdTable.IsVirtual(fd))

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	info, err := fh.Stat()
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	st := info.ToStat()
	h.writeStat(statAddr, &st)
	h.skipSyscall(0)
}

func (h *SyscallHandler) handleStatEntry() {
	pathAddr := uintptr(h.regs.Rdi)
	statAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	info, err := h.tracer.vfs.Stat(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	st := info.ToStat()
	h.writeStat(statAddr, &st)
	h.skipSyscall(0)
}

func (h *SyscallHandler) handleLstatEntry() {
	pathAddr := uintptr(h.regs.Rdi)
	statAddr := uintptr(h.regs.Rsi)

	vfsPath, intercept := h.readPathAt(AT_FDCWD, pathAddr)
	if !intercept {
		return
	}

	info, err := h.tracer.vfs.Lstat(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	st := info.ToStat()
	h.writeStat(statAddr, &st)
	h.skipSyscall(0)
}

func (h *SyscallHandler) handleNewfstatatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	statAddr := uintptr(h.regs.Rdx)
	flags := int(h.regs.R10)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	var info *vfs.FileInfo
	var err error

	if flags&AT_SYMLINK_NOFOLLOW != 0 {
		info, err = h.tracer.vfs.Lstat(vfsPath)
	} else {
		info, err = h.tracer.vfs.Stat(vfsPath)
	}

	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	st := info.ToStat()
	h.writeStat(statAddr, &st)
	h.skipSyscall(0)
}

func (h *SyscallHandler) handleLseekEntry() {
	fd := int(h.regs.Rdi)
	offset := int64(h.regs.Rsi)
	whence := int(h.regs.Rdx)

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	newOffset, err := fh.Seek(offset, whence)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(newOffset)
}

func (h *SyscallHandler) handleGetdents64Entry() {
	fd := int(h.regs.Rdi)
	bufAddr := uintptr(h.regs.Rsi)
	count := int(h.regs.Rdx)

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	entries, err := fh.ReadDir(-1)
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
	mode := uint32(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.Mkdir(vfsPath, mode)
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
		err = h.tracer.vfs.Rmdir(vfsPath)
	} else {
		err = h.tracer.vfs.Unlink(vfsPath)
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
	flags := uint(h.regs.R8)

	oldVfsPath, oldIntercept := h.readPathAt(oldDirfd, oldPathAddr)
	newVfsPath, newIntercept := h.readPathAt(newDirfd, newPathAddr)

	if !oldIntercept && !newIntercept {
		return
	}

	if oldIntercept != newIntercept {
		h.skipSyscall(negErrno(syscall.EXDEV))
		return
	}

	err := h.tracer.vfs.Rename(oldVfsPath, newVfsPath, flags)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
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

	err := h.tracer.vfs.Link(oldVfsPath, newVfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleSymlinkatEntry() {
	targetAddr := uintptr(h.regs.Rdi)
	newDirfd := int(int32(h.regs.Rsi))
	linkpathAddr := uintptr(h.regs.Rdx)

	target, _ := ReadString(h.proc.pid, targetAddr, 4096)
	vfsPath, intercept := h.readPathAt(newDirfd, linkpathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.Symlink(target, vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleReadlinkatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	bufAddr := uintptr(h.regs.Rdx)
	bufsize := int(h.regs.R10)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	target, err := h.tracer.vfs.Readlink(vfsPath)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	n := len(target)
	if n > bufsize {
		n = bufsize
	}

	WriteBytes(h.proc.pid, bufAddr, []byte(target[:n]))
	h.skipSyscall(int64(n))
}

func (h *SyscallHandler) handleFchmodatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	mode := uint32(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.Chmod(vfsPath, mode)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleFchownatEntry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	uid := int(int32(h.regs.Rdx))
	gid := int(int32(h.regs.R10))
	flags := int(h.regs.R8)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	var err error
	if flags&AT_SYMLINK_NOFOLLOW != 0 {
		err = h.tracer.vfs.Lchown(vfsPath, uid, gid)
	} else {
		err = h.tracer.vfs.Chown(vfsPath, uid, gid)
	}

	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleFaccessat2Entry() {
	dirfd := int(int32(h.regs.Rdi))
	pathAddr := uintptr(h.regs.Rsi)
	mode := uint32(h.regs.Rdx)

	vfsPath, intercept := h.readPathAt(dirfd, pathAddr)
	if !intercept {
		return
	}

	err := h.tracer.vfs.Access(vfsPath, mode)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleFtruncateEntry() {
	fd := int(h.regs.Rdi)
	length := int64(h.regs.Rsi)

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	fh, ok := h.tracer.fdTable.Get(fd)
	if !ok {
		h.skipSyscall(negErrno(syscall.EBADF))
		return
	}

	err := fh.Truncate(length)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	h.skipSyscall(0)
}

func (h *SyscallHandler) handleDupEntry() {
	oldfd := int(h.regs.Rdi)

	if !h.tracer.fdTable.IsVirtual(oldfd) {
		return
	}

	newfd, err := h.tracer.fdTable.Dup(oldfd)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	if path, ok := h.proc.fdPaths[oldfd]; ok {
		h.proc.fdPaths[newfd] = path
	}

	h.skipSyscall(int64(newfd))
}

func (h *SyscallHandler) handleDup2Entry() {
	oldfd := int(h.regs.Rdi)
	newfd := int(h.regs.Rsi)

	if !h.tracer.fdTable.IsVirtual(oldfd) {
		return
	}

	err := h.tracer.fdTable.Dup2(oldfd, newfd)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	if path, ok := h.proc.fdPaths[oldfd]; ok {
		h.proc.fdPaths[newfd] = path
	}

	h.skipSyscall(int64(newfd))
}

func (h *SyscallHandler) handleDup3Entry() {
	oldfd := int(h.regs.Rdi)
	newfd := int(h.regs.Rsi)

	if !h.tracer.fdTable.IsVirtual(oldfd) {
		return
	}

	if oldfd == newfd {
		h.skipSyscall(negErrno(syscall.EINVAL))
		return
	}

	err := h.tracer.fdTable.Dup2(oldfd, newfd)
	if err != nil {
		h.skipSyscall(errnoFromError(err))
		return
	}

	if path, ok := h.proc.fdPaths[oldfd]; ok {
		h.proc.fdPaths[newfd] = path
	}

	h.skipSyscall(int64(newfd))
}

func (h *SyscallHandler) handleFcntlEntry() {
	fd := int(h.regs.Rdi)
	cmd := int(h.regs.Rsi)

	if !h.tracer.fdTable.IsVirtual(fd) {
		return
	}

	const (
		F_DUPFD       = 0
		F_GETFD       = 1
		F_SETFD       = 2
		F_GETFL       = 3
		F_SETFL       = 4
		F_DUPFD_CLOEXEC = 1030
	)

	switch cmd {
	case F_DUPFD, F_DUPFD_CLOEXEC:
		newfd, err := h.tracer.fdTable.Dup(fd)
		if err != nil {
			h.skipSyscall(errnoFromError(err))
			return
		}
		if path, ok := h.proc.fdPaths[fd]; ok {
			h.proc.fdPaths[newfd] = path
		}
		h.skipSyscall(int64(newfd))
	case F_GETFD:
		h.skipSyscall(0)
	case F_SETFD:
		h.skipSyscall(0)
	case F_GETFL:
		h.skipSyscall(int64(syscall.O_RDWR))
	case F_SETFL:
		h.skipSyscall(0)
	default:
		h.skipSyscall(negErrno(syscall.EINVAL))
	}
}

func (h *SyscallHandler) writeStat(addr uintptr, st *syscall.Stat_t) {
	size := int(unsafe.Sizeof(*st))
	buf := make([]byte, size)
	ptr := unsafe.Pointer(&buf[0])
	*(*syscall.Stat_t)(ptr) = *st
	WriteBytes(h.proc.pid, addr, buf)
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
