package tracer

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type logLevel int

const (
	logOff logLevel = iota
	logInterceptOnly
	logDebug
)

var (
	logger   = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	level    = parseLogLevel()
)

func parseLogLevel() logLevel {
	if os.Getenv("FUSS_DEBUG") != "" {
		return logDebug
	}
	level := strings.ToLower(strings.TrimSpace(os.Getenv("FUSS_LOG_LEVEL")))
	switch level {
	case "", "off", "none", "0":
		return logOff
	case "intercept", "info", "1":
		return logInterceptOnly
	case "debug", "verbose", "2":
		return logDebug
	default:
		return logOff
	}
}

func debugf(format string, args ...interface{}) {
	if level < logDebug {
		return
	}
	logger.Debug(fmt.Sprintf(format, args...))
}

func logIntercept(sysno uint64, path string, resolved string, vfsPath string) {
	if level < logInterceptOnly {
		return
	}
	logger.Info(
		"intercept",
		"syscall", syscallName(sysno),
		"path", path,
		"resolved", resolved,
		"vfs", vfsPath,
	)
}

func syscallName(sysno uint64) string {
	switch sysno {
	case SYS_OPEN:
		return "open"
	case SYS_OPENAT:
		return "openat"
	case SYS_CLOSE:
		return "close"
	case SYS_STAT:
		return "stat"
	case SYS_LSTAT:
		return "lstat"
	case SYS_NEWFSTATAT:
		return "newfstatat"
	case SYS_GETDENTS64:
		return "getdents64"
	case SYS_MKDIRAT:
		return "mkdirat"
	case SYS_UNLINK:
		return "unlink"
	case SYS_RMDIR:
		return "rmdir"
	case SYS_UNLINKAT:
		return "unlinkat"
	case SYS_RENAMEAT:
		return "renameat"
	case SYS_RENAMEAT2:
		return "renameat2"
	case SYS_LINKAT:
		return "linkat"
	case SYS_SYMLINKAT:
		return "symlinkat"
	case SYS_READLINK:
		return "readlink"
	case SYS_READLINKAT:
		return "readlinkat"
	case SYS_FCHMODAT:
		return "fchmodat"
	case SYS_FCHOWNAT:
		return "fchownat"
	case SYS_FACCESSAT2:
		return "faccessat2"
	case SYS_GETXATTR:
		return "getxattr"
	case SYS_LGETXATTR:
		return "lgetxattr"
	case SYS_LISTXATTR:
		return "listxattr"
	case SYS_LLISTXATTR:
		return "llistxattr"
	case SYS_STATFS:
		return "statfs"
	case SYS_STATX:
		return "statx"
	case SYS_DUP:
		return "dup"
	case SYS_DUP2:
		return "dup2"
	case SYS_DUP3:
		return "dup3"
	case SYS_EXECVE:
		return "execve"
	case SYS_EXECVEAT:
		return "execveat"
	case SYS_CHDIR:
		return "chdir"
	case SYS_FCHDIR:
		return "fchdir"
	default:
		return fmt.Sprintf("sys_%d", sysno)
	}
}
