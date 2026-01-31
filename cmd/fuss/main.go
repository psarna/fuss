package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"fuss/pkg/overlay"
	"fuss/pkg/tracer"
)

func main() {
	var (
		mountpoint    string
		lowerdir      string
		upperdir      string
		whiteoutStyle string
	)

	flag.StringVar(&mountpoint, "mountpoint", "", "Virtual mount point (required)")
	flag.StringVar(&lowerdir, "lowerdir", "", "Read-only lower layers, colon-separated (rightmost = bottom)")
	flag.StringVar(&upperdir, "upperdir", "", "Writable upper layer directory")
	flag.StringVar(&whiteoutStyle, "whiteout", "fileprefix", "Whiteout style: chardev or fileprefix")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: fuss [options] -- command [args...]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if mountpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: --mountpoint is required")
		os.Exit(1)
	}

	if upperdir == "" {
		fmt.Fprintln(os.Stderr, "Error: --upperdir is required")
		os.Exit(1)
	}

	var lowerDirs []string
	if lowerdir != "" {
		lowerDirs = strings.Split(lowerdir, ":")
	}

	for _, dir := range lowerDirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: lower directory does not exist: %s\n", dir)
			os.Exit(1)
		}
	}

	if info, err := os.Stat(upperdir); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: upper directory does not exist: %s\n", upperdir)
		os.Exit(1)
	}

	var style overlay.WhiteoutStyle
	switch strings.ToLower(whiteoutStyle) {
	case "chardev":
		style = overlay.WhiteoutCharDevice
	case "fileprefix":
		style = overlay.WhiteoutFilePrefix
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown whiteout style: %s\n", whiteoutStyle)
		os.Exit(1)
	}

	vfs := overlay.New(overlay.Config{
		LowerDirs:     lowerDirs,
		UpperDir:      upperdir,
		WhiteoutStyle: style,
	})

	t := tracer.NewTracer(vfs, mountpoint)

	if err := t.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
