package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// jailLayout is the host/guest path split when Firecracker runs inside the
// jailer chroot. Guest paths are what the VMM sees after pivot_root.
type jailLayout struct {
	ID         string
	ExecName   string
	ChrootBase string
	JailDir    string // {base}/{exec}/{id}
	Root       string // {JailDir}/root  — chroot_dir in the Firecracker docs
}

func newJailLayout(chrootBase, execFile, id string) (jailLayout, error) {
	if err := validateJailerID(id); err != nil {
		return jailLayout{}, err
	}
	execName := filepath.Base(execFile)
	if execName == "" || execName == "." || execName == "/" {
		return jailLayout{}, fmt.Errorf("jailer: invalid exec-file %q", execFile)
	}
	base := chrootBase
	if base == "" {
		base = "/srv/jailer"
	}
	jail := filepath.Join(base, execName, id)
	return jailLayout{
		ID:         id,
		ExecName:   execName,
		ChrootBase: base,
		JailDir:    jail,
		Root:       filepath.Join(jail, "root"),
	}, nil
}

func validateJailerID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("jailer id %q: must be 1-64 chars", id)
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("jailer id %q: only letters, digits and '-' are allowed", id)
	}
	return nil
}

// prepareJail creates the chroot tree and places kernel + rootfs where the
// jailed VMM will look for them (/vmlinux, /rootfs.ext4).
func prepareJail(layout jailLayout, kernel, rootfs string, place func(src, dst string) error) error {
	if place == nil {
		place = cloneFile
	}
	if err := os.MkdirAll(layout.Root, 0o750); err != nil {
		return fmt.Errorf("jailer mkdir %s: %w", layout.Root, err)
	}
	if err := linkOrCopy(kernel, filepath.Join(layout.Root, "vmlinux")); err != nil {
		return fmt.Errorf("jailer kernel: %w", err)
	}
	if err := place(rootfs, filepath.Join(layout.Root, "rootfs.ext4")); err != nil {
		return fmt.Errorf("jailer rootfs: %w", err)
	}
	logPath := filepath.Join(layout.Root, "firecracker.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	return f.Close()
}

func jailerCommand(cfg Config, layout jailLayout, netnsPath string) (*exec.Cmd, error) {
	if cfg.Jailer == "" {
		return nil, fmt.Errorf("jailer binary is empty")
	}
	uid, gid, err := jailerCreds(cfg)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--id", layout.ID,
		"--exec-file", cfg.Binary,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--chroot-base-dir", layout.ChrootBase,
	}
	if cfg.JailerCgroup {
		args = append(args, "--cgroup-version", "2")
	}
	if cfg.NewPIDNS {
		args = append(args, "--new-pid-ns")
	}
	if netnsPath != "" {
		args = append(args, "--netns", netnsPath)
	}
	args = append(args, "--", "--api-sock", "/api.sock")

	var cmd *exec.Cmd
	if cfg.JailerSudo {
		full := append([]string{"-n", cfg.Jailer}, args...)
		cmd = exec.Command("sudo", full...)
	} else {
		cmd = exec.Command(cfg.Jailer, args...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, nil
}

func jailerCreds(cfg Config) (uid, gid int, err error) {
	if cfg.JailerUID != 0 || cfg.JailerGID != 0 {
		if cfg.JailerUID == 0 {
			return 0, 0, fmt.Errorf("jailer refuses to drop to uid 0; set WARDEN_JAILER_UID to an unprivileged user")
		}
		return cfg.JailerUID, cfg.JailerGID, nil
	}
	u, err := user.Current()
	if err != nil {
		return 0, 0, fmt.Errorf("jailer uid: %w", err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("jailer refuses to drop to uid 0; set WARDEN_JAILER_UID to an unprivileged user")
	}
	return uid, gid, nil
}
