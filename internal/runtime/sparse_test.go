package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySparseDiff(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mem")
	diff := filepath.Join(dir, "diff.mem")

	buf := make([]byte, 16*4096)
	for i := range buf {
		buf[i] = 'A'
	}
	if err := os.WriteFile(base, buf, 0o640); err != nil {
		t.Fatal(err)
	}

	df, err := os.Create(diff)
	if err != nil {
		t.Fatal(err)
	}
	if err := df.Truncate(int64(len(buf))); err != nil {
		t.Fatal(err)
	}
	patch := make([]byte, 4096)
	for i := range patch {
		patch[i] = 'B'
	}
	if _, err := df.WriteAt(patch, 3*4096); err != nil {
		t.Fatal(err)
	}
	if err := df.Close(); err != nil {
		t.Fatal(err)
	}

	if err := applySparseDiff(base, diff); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(buf) {
		t.Fatalf("len=%d", len(got))
	}
	for i := 0; i < 3*4096; i++ {
		if got[i] != 'A' {
			t.Fatalf("prefix mutated at %d", i)
		}
	}
	for i := 3 * 4096; i < 4*4096; i++ {
		if got[i] != 'B' {
			t.Fatalf("diff not applied at %d", i)
		}
	}
	for i := 4 * 4096; i < len(got); i++ {
		if got[i] != 'A' {
			t.Fatalf("suffix mutated at %d", i)
		}
	}
}
