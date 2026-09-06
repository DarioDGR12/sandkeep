package runtime

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

// cloneFile makes a private copy of src at dst. It prefers cp --reflink=auto
// (cheap on btrfs/xfs/overlay) and falls back to a full userspace copy.
func cloneFile(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("clone %s: %w", src, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("clone %s: not a regular file", src)
	}
	cmd := exec.Command("cp", "--reflink=auto", "--sparse=auto", src, dst)
	if err := cmd.Run(); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

// linkOrCopy hard-links src to dst when the filesystem allows it (good for
// the read-only kernel image). Otherwise it clones.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return cloneFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy %s → %s: %w", src, dst, copyErr)
	}
	return closeErr
}
