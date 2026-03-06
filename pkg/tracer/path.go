package tracer

import (
	"path/filepath"
	"strings"
)

type PathResolver struct {
	mountpoint string
	backing    []string
}

func normalizeRoot(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	abs = filepath.Clean(abs)
	if abs == "." || abs == "" {
		return ""
	}
	return abs
}

func NewPathResolver(mountpoint string, backing ...string) *PathResolver {
	mp, _ := filepath.Abs(mountpoint)
	mp = filepath.Clean(mp)
	if !strings.HasSuffix(mp, "/") {
		mp += "/"
	}

	var normalizedBacking []string
	seen := map[string]struct{}{}
	for _, root := range backing {
		n := normalizeRoot(root)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		normalizedBacking = append(normalizedBacking, n)
	}

	return &PathResolver{mountpoint: mp, backing: normalizedBacking}
}

func pathWithinRoot(path, root string) (string, bool) {
	if path == root {
		return "/", true
	}
	prefix := root + "/"
	if strings.HasPrefix(path, prefix) {
		rel := strings.TrimPrefix(path, prefix)
		if rel == "" {
			return "/", true
		}
		return "/" + rel, true
	}
	return "", false
}

func (r *PathResolver) ShouldIntercept(path string) bool {
	if path == "" {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absPath = filepath.Clean(absPath)

	mp := strings.TrimSuffix(r.mountpoint, "/")
	if absPath == mp {
		return true
	}

	if strings.HasPrefix(absPath, r.mountpoint) {
		return true
	}

	for _, root := range r.backing {
		if _, ok := pathWithinRoot(absPath, root); ok {
			return true
		}
	}

	return false
}

func (r *PathResolver) TranslatePath(path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	absPath = filepath.Clean(absPath)

	mp := strings.TrimSuffix(r.mountpoint, "/")
	if absPath == mp {
		return "/"
	}

	if strings.HasPrefix(absPath, r.mountpoint) {
		rel := strings.TrimPrefix(absPath, r.mountpoint)
		if rel == "" {
			return "/"
		}
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		return rel
	}

	for _, root := range r.backing {
		if rel, ok := pathWithinRoot(absPath, root); ok {
			return rel
		}
	}

	return path
}

func (r *PathResolver) Mountpoint() string {
	return strings.TrimSuffix(r.mountpoint, "/")
}

func (r *PathResolver) ResolvePath(cwd string, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

func (r *PathResolver) ResolveAt(dirfd int, path string, cwd string, fdPaths map[int]string) string {
	const AT_FDCWD = -100

	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	if dirfd == AT_FDCWD {
		return r.ResolvePath(cwd, path)
	}

	if basePath, ok := fdPaths[dirfd]; ok {
		return filepath.Clean(filepath.Join(basePath, path))
	}

	return r.ResolvePath(cwd, path)
}
