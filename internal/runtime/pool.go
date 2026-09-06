package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// DiskPool places a clean golden rootfs at dst. Dirty disks are never
// returned to the pool — leftover guest state would leak across jobs.
type DiskPool interface {
	Acquire(dst string) error
}

// FilePool keeps Size pre-cloned copies of Golden under Dir. A miss
// (empty pool) falls back to a synchronous clone so Boot still works
// during warmup.
type FilePool struct {
	Golden string
	Dir    string
	Size   int
	seq    atomic.Uint64
	ready  chan string
}

// NewFilePool starts Size background clones. Size < 1 returns nil.
func NewFilePool(golden, dir string, size int) *FilePool {
	if size < 1 || golden == "" || dir == "" {
		return nil
	}
	p := &FilePool{
		Golden: golden,
		Dir:    dir,
		Size:   size,
		ready:  make(chan string, size),
	}
	_ = os.MkdirAll(dir, 0o750)
	for i := 0; i < size; i++ {
		go p.fill()
	}
	return p
}

// Available is the number of ready clones. Tests use it to wait for warmup.
func (p *FilePool) Available() int {
	if p == nil {
		return 0
	}
	return len(p.ready)
}

// Acquire moves a ready clone to dst, or clones Golden synchronously.
func (p *FilePool) Acquire(dst string) error {
	if p == nil {
		return fmt.Errorf("rootfs pool is nil")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	select {
	case src := <-p.ready:
		go p.fill()
		if err := os.Rename(src, dst); err != nil {
			return cloneFile(p.Golden, dst)
		}
		return nil
	default:
		return cloneFile(p.Golden, dst)
	}
}

func (p *FilePool) fill() {
	n := p.seq.Add(1)
	path := filepath.Join(p.Dir, fmt.Sprintf("ready-%d.ext4", n))
	if err := cloneFile(p.Golden, path); err != nil {
		return
	}
	select {
	case p.ready <- path:
	default:
		_ = os.Remove(path)
	}
}
