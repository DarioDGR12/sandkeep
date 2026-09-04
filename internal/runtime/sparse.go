package runtime

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// applySparseDiff copies allocated extents from diff onto base at the same
// offsets. Firecracker Diff memory files are sparse: unchanged pages are
// holes. This is the same rebase snapshot-editor does.
func applySparseDiff(basePath, diffPath string) error {
	diff, err := os.Open(diffPath)
	if err != nil {
		return fmt.Errorf("open diff: %w", err)
	}
	defer diff.Close()
	base, err := os.OpenFile(basePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open base mem: %w", err)
	}
	defer base.Close()

	var off int64
	for {
		start, err := unix.Seek(int(diff.Fd()), off, unix.SEEK_DATA)
		if err != nil {
			if err == syscall.ENXIO {
				return nil
			}
			return fmt.Errorf("seek data %d: %w", off, err)
		}
		end, err := unix.Seek(int(diff.Fd()), start, unix.SEEK_HOLE)
		if err != nil {
			return fmt.Errorf("seek hole %d: %w", start, err)
		}
		if end <= start {
			return nil
		}
		if _, err := diff.Seek(start, io.SeekStart); err != nil {
			return err
		}
		if _, err := base.Seek(start, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(base, diff, end-start); err != nil {
			return fmt.Errorf("copy extent [%d,%d): %w", start, end, err)
		}
		off = end
	}
}
