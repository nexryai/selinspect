package procfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "42")
	if e := os.MkdirAll(filepath.Join(d, "attr"), 0700); e != nil {
		t.Fatal(e)
	}
	stat := "42 (日本語 ) name) S 1 0 0 0 0 2097152 0 0 0 0 0 0 0 0 0 0 0 0 77 0"
	for n, s := range map[string]string{"stat": stat, "status": "Uid:\t1000 1000 1000 1000\nGid:\t1001 1001 1001 1001\n", "comm": "日本語\n", "attr/current": "u:r:alpha_t:s0:c1"} {
		if e := os.WriteFile(filepath.Join(d, n), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	p, e := (Source{root}).List(context.Background())
	if e != nil || len(p) != 1 {
		t.Fatal(p, e)
	}
	if p[0].StartTimeTicks != 77 || p[0].Name != "日本語" || p[0].UID != 1000 || !p[0].ContextKnown || !p[0].KernelThread {
		t.Fatalf("%+v", p)
	}
	if len(Group(p)["alpha_t"]) != 1 {
		t.Fatal("group")
	}
	if e := os.Remove(filepath.Join(d, "stat")); e != nil {
		t.Fatal(e)
	}
	p, e = (Source{root}).List(context.Background())
	if e != nil || len(p) != 0 {
		t.Fatal(p, e)
	}
	for _, s := range []string{"", "1 (x) S", fmt.Sprint("1 (x) bad")} {
		if _, _, _, e := ParseStat(s); e == nil {
			t.Fatal(s)
		}
	}
}
