package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fuss/pkg/overlay"
	"fuss/pkg/tracer"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	mountpoint    string
	lowerdir      string
	upperdir      string
	whiteoutStyle string
)

type config struct {
	Mountpoint string `yaml:"mountpoint"`
	Lowerdir   string `yaml:"lowerdir"`
	Upperdir   string `yaml:"upperdir"`
	Whiteout   string `yaml:"whiteout"`
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".fuss")
}

func loadConfig() (*config, error) {
	path := configPath()
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return &cfg, nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "fuss [flags] -- command [args...]",
		Short: "Filesystem in Userspace with Syscall interception",
		Long: `fuss intercepts filesystem syscalls using ptrace to provide an overlay
filesystem without requiring root privileges or kernel modules.

Configuration:
  If no flags are provided, fuss reads configuration from ~/.fuss (YAML format).

  Example ~/.fuss:
    mountpoint: /app
    upperdir: /tmp/changes
    lowerdir: /layers/base:/layers/extra
    whiteout: fileprefix

Example:
  fuss --mountpoint /app --upperdir /tmp/changes --lowerdir /layers/base -- ls -la /app
  fuss -- ls -la /app  # uses ~/.fuss config`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE:               run,
	}

	rootCmd.Flags().StringVar(&mountpoint, "mountpoint", "", "Virtual mount point")
	rootCmd.Flags().StringVar(&lowerdir, "lowerdir", "", "Read-only lower layers, colon-separated (rightmost = bottom)")
	rootCmd.Flags().StringVar(&upperdir, "upperdir", "", "Writable upper layer directory")
	rootCmd.Flags().StringVar(&whiteoutStyle, "whiteout", "", "Whiteout style: chardev or fileprefix (default: fileprefix)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if mountpoint == "" && cfg != nil {
		mountpoint = cfg.Mountpoint
	}
	if upperdir == "" && cfg != nil {
		upperdir = cfg.Upperdir
	}
	if lowerdir == "" && cfg != nil {
		lowerdir = cfg.Lowerdir
	}
	if whiteoutStyle == "" {
		if cfg != nil && cfg.Whiteout != "" {
			whiteoutStyle = cfg.Whiteout
		} else {
			whiteoutStyle = "fileprefix"
		}
	}

	if mountpoint == "" {
		return fmt.Errorf("mountpoint is required (use --mountpoint or set in %s)", configPath())
	}
	if upperdir == "" {
		return fmt.Errorf("upperdir is required (use --upperdir or set in %s)", configPath())
	}

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
