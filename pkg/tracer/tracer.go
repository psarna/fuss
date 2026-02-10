package tracer

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"fuss/pkg/vfs"
)

const (
	PTRACE_O_TRACESYSGOOD = 0x00000001
	PTRACE_O_TRACEFORK    = 0x00000002
	PTRACE_O_TRACEVFORK   = 0x00000004
	PTRACE_O_TRACECLONE   = 0x00000008
	PTRACE_O_TRACEEXEC    = 0x00000010

	SIGTRAP_MASK = 0x80
)

type Tracer struct {
	vfs      vfs.VFS
	resolver *PathResolver
	fdTable  *FDTable
	procs    map[int]*ProcessState
}

type pendingOpen struct {
	path    string
	isDir   bool
	vfsPath string
}

type pendingDup struct {
	oldfd int
	newfd int
}

type pendingChdir struct {
	path string
	fd   int
}

type ProcessState struct {
	pid          int
	inSyscall    bool
	cwd          string
	fdPaths      map[int]string
	pendingOpen  *pendingOpen
	pendingDup   *pendingDup
	pendingChdir *pendingChdir
	attached     bool
}

func NewTracer(v vfs.VFS, mountpoint string) *Tracer {
	return &Tracer{
		vfs:      v,
		resolver: NewPathResolver(mountpoint),
		fdTable:  NewFDTable(),
		procs:    make(map[int]*ProcessState),
	}
}

func (t *Tracer) Run(args []string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	pid := cmd.Process.Pid

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("initial wait failed: %w", err)
	}

	opts := PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC
	if err := syscall.PtraceSetOptions(pid, opts); err != nil {
		return fmt.Errorf("ptrace setoptions failed: %w", err)
	}

	cwd, _ := os.Getwd()
	t.procs[pid] = &ProcessState{
		pid:      pid,
		cwd:      cwd,
		fdPaths:  make(map[int]string),
		attached: true,
	}

	return t.traceLoop(pid)
}

func (t *Tracer) traceLoop(initialPid int) error {
	if err := syscall.PtraceSyscall(initialPid, 0); err != nil {
		return fmt.Errorf("initial ptrace syscall failed: %w", err)
	}

	for len(t.procs) > 0 {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err != nil {
			if err == syscall.ECHILD {
				break
			}
			return fmt.Errorf("wait4 failed: %w", err)
		}

		if ws.Exited() || ws.Signaled() {
			delete(t.procs, pid)
			continue
		}

		proc, ok := t.procs[pid]
		if !ok {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if err != nil {
				cwd, _ = os.Getwd()
			}
			proc = &ProcessState{
				pid:     pid,
				cwd:     cwd,
				fdPaths: make(map[int]string),
			}
			t.procs[pid] = proc

			opts := PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC
			syscall.PtraceSetOptions(pid, opts)
		}

		if ws.Stopped() {
			sig := ws.StopSignal()

			if sig == syscall.SIGTRAP|SIGTRAP_MASK {
				t.handleSyscall(proc)
				syscall.PtraceSyscall(pid, 0)
			} else if sig == syscall.SIGTRAP {
				event := int(ws>>16) & 0xff
				if event == 1 || event == 2 || event == 3 {
					childPid, err := syscall.PtraceGetEventMsg(pid)
					if err == nil {
						fdCopy := make(map[int]string, len(proc.fdPaths))
						for k, v := range proc.fdPaths {
							fdCopy[k] = v
						}
						t.procs[int(childPid)] = &ProcessState{
							pid:     int(childPid),
							cwd:     proc.cwd,
							fdPaths: fdCopy,
						}
					}
				}
				syscall.PtraceSyscall(pid, 0)
			} else if sig == syscall.SIGSTOP && !proc.attached {
				proc.attached = true
				syscall.PtraceSyscall(pid, 0)
			} else if sig == syscall.SIGTTIN || sig == syscall.SIGTTOU || sig == syscall.SIGTSTP {
				// Suppress terminal job control signals to allow interactive shells to work.
				// Limitation: these signals cannot be manually delivered to traced processes.
				syscall.PtraceSyscall(pid, 0)
			} else {
				syscall.PtraceSyscall(pid, int(sig))
			}
		}
	}

	return nil
}

func (t *Tracer) handleSyscall(proc *ProcessState) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(proc.pid, &regs); err != nil {
		return
	}

	if !proc.inSyscall {
		proc.inSyscall = true
		t.handleSyscallEntry(proc, &regs)
	} else {
		proc.inSyscall = false
		t.handleSyscallExit(proc, &regs)
	}
}

func (t *Tracer) handleSyscallEntry(proc *ProcessState, regs *syscall.PtraceRegs) {
	h := &SyscallHandler{
		tracer: t,
		proc:   proc,
		regs:   regs,
	}
	h.HandleEntry()
}

func (t *Tracer) handleSyscallExit(proc *ProcessState, regs *syscall.PtraceRegs) {
	h := &SyscallHandler{
		tracer: t,
		proc:   proc,
		regs:   regs,
	}
	h.HandleExit()
}
