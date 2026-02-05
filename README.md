![fuss](fuss.png)

# fuss

**F**ilesystem with **U**nions, **S**andbox-**S**tyle

Look ma, no FUSE! A userspace overlay filesystem implementation using ptrace-based syscall interception. No FUSE, no kernel modules, no mount permissions required.

## What is this?

fuss intercepts filesystem syscalls from a child process and redirects them through a virtual filesystem layer. The included overlay implementation provides copy-on-write semantics compatible with Linux overlayfs/fuse-overlayfs.

## Installation

```bash
go install github.com/psarna/fuss/cmd/fuss@latest
```

or build from source like a pro:

```bash
git clone https://github.com/psarna/fuss
cd fuss
go build -o fuss ./cmd/fuss
```

## Usage

```
fuss [options] -- command [args...]
```

Options:
- `--mountpoint PATH` - Virtual mount point (required)
- `--lowerdir PATH` - Read-only lower layers, colon-separated (rightmost = bottom)
- `--upperdir PATH` - Writable upper layer directory
- `--whiteout MODE` - Whiteout style: "chardev" or "fileprefix" (default: fileprefix)

### Examples

Basic overlay with one lower layer:

```bash
fuss --mountpoint=/app \
     --lowerdir=/opt/myapp \
     --upperdir=/tmp/changes \
     -- bash
```

Multi-layer (think Docker container):

```bash
fuss --mountpoint=/rootfs \
     --lowerdir=/layers/base:/layers/deps:/layers/app \
     --upperdir=/tmp/runtime \
     -- ./start.sh
```

Run a build in isolation:

```bash
fuss --mountpoint=/home/user/project \
     --lowerdir=/home/user/project \
     --upperdir=/tmp/build-output \
     -- make all
```

## How It Works

1. fuss starts your command as a child process with ptrace attached
2. Every filesystem syscall (open, read, write, stat, etc.) is intercepted
3. Paths under --mountpoint are redirected to the overlay VFS
4. The overlay resolves files across layers (upper first, then lowers)
5. Writes trigger copy-up from lower to upper layer
6. Deletes create whiteout markers to hide lower-layer files

## Overlay Format

fuss uses formats compatible with Linux overlayfs:

### Whiteout Styles

**fileprefix** (default, portable):
- Deleted files: `.wh.<filename>` empty file
- Opaque dirs: `.wh..wh..opq` file inside directory

**chardev** (kernel overlayfs compatible):
- Deleted files: character device with major:minor 0:0
- Opaque dirs: `trusted.overlay.opaque=y` xattr
- Requires CAP\_MKNOD

After running fuss, you can mount the same directories with fuse-overlayfs or kernel overlayfs and see consistent results.

## Extending fuss

The `pkg/passthrough` package provides a simple reference implementation of the VFS interface. Use it as a template to implement custom filesystem behaviors:

- Logging/auditing filesystem
- Encryption layer
- Caching layer
- Access control

## Limitations

- Linux x86\_64 only (ptrace is architecture-specific)
- Some syscall edge cases may not be fully handled
- Performance overhead from ptrace context switches

## Architecture

```
pkg/vfs/          - Virtual filesystem interface
pkg/tracer/       - Ptrace-based syscall interception
pkg/overlay/      - Overlay filesystem implementation
pkg/passthrough/  - Simple passthrough VFS (reference implementation)
cmd/fuss/         - CLI entry point
```

## License

MIT
