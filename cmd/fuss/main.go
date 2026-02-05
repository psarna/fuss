package main

import (
	"fmt"
	"os"
	"strings"

	"fuss/pkg/overlay"
	"fuss/pkg/tracer"

	"github.com/spf13/cobra"
)

var (
	mountpoint    string
	lowerdir      string
	upperdir      string
	whiteoutStyle string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "fuss [flags] -- command [args...]",
		Short: "Filesystem in Userspace with Syscall interception",
		Long: `fuss intercepts filesystem syscalls using ptrace to provide an overlay
filesystem without requiring root privileges or kernel modules.

Example:
  fuss --mountpoint /app --upperdir /tmp/changes --lowerdir /layers/base -- ls -la /app`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE:               run,
	}

	rootCmd.Flags().StringVar(&mountpoint, "mountpoint", "", "Virtual mount point (required)")
	rootCmd.Flags().StringVar(&lowerdir, "lowerdir", "", "Read-only lower layers, colon-separated (rightmost = bottom)")
	rootCmd.Flags().StringVar(&upperdir, "upperdir", "", "Writable upper layer directory (required)")
	rootCmd.Flags().StringVar(&whiteoutStyle, "whiteout", "fileprefix", "Whiteout style: chardev or fileprefix")

	rootCmd.MarkFlagRequired("mountpoint")
	rootCmd.MarkFlagRequired("upperdir")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	var lowerDirs []string
	if lowerdir != "" {
		lowerDirs = strings.Split(lowerdir, ":")
	}

	for _, dir := range lowerDirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return fmt.Errorf("lower directory does not exist: %s", dir)
		}
	}

	if info, err := os.Stat(upperdir); err != nil || !info.IsDir() {
		return fmt.Errorf("upper directory does not exist: %s", upperdir)
	}

	var style overlay.WhiteoutStyle
	switch strings.ToLower(whiteoutStyle) {
	case "chardev":
		style = overlay.WhiteoutCharDevice
	case "fileprefix":
		style = overlay.WhiteoutFilePrefix
	default:
		return fmt.Errorf("unknown whiteout style: %s", whiteoutStyle)
	}

	vfs := overlay.New(overlay.Config{
		LowerDirs:     lowerDirs,
		UpperDir:      upperdir,
		WhiteoutStyle: style,
	})

	t := tracer.NewTracer(vfs, mountpoint)

	return t.Run(args)
}
