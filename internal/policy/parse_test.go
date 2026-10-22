package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsers(t *testing.T) {
	x, e := ParseType("Types: 1\n type alpha_t alias { a_t b_t }, attr_one, attr_two;\n")
	if e != nil || len(x.Attributes) != 2 || len(x.Aliases) != 2 {
		t.Fatal(x, e)
	}
	a, e := ParseAttribute("Type Attributes: 1\n attribute attr_two;\n alpha_t\n beta_t\n gamma_t\n")
	if e != nil || len(a.MemberTypes) != 3 {
		t.Fatal(a, e)
	}
	if _, e = ParseType("Types: 0"); e == nil {
		t.Fatal("absent Type")
	}
	for _, bad := range []string{"nonsense", "Types: 2\n alpha_t", ""} {
		if _, e := ParseList(bad, "Types"); e == nil {
			t.Fatal(bad)
		}
	}
	if n, e := ParseList("Types: 0", "Types"); e != nil || len(n) != 0 {
		t.Fatal(n, e)
	}
	rules, e := ParseRules("allow alpha_t beta_t:file { map read };\nallow attr_one attr_two:dir search; [ ( demo && other ) ]:False\nallowxperm alpha_t beta_t:chr_file ioctl 0x1234;")
	if e != nil || len(rules) != 3 || rules[1].ConditionState != "unknown" || rules[2].Kind != "allowxperm" {
		t.Fatal(rules, e)
	}
	if _, e := ParseRules("bogus rule"); e == nil {
		t.Fatal("unknown output accepted")
	}
	if r, e := ParseRules(""); e != nil || len(r) != 0 {
		t.Fatal(r, e)
	}
	for _, s := range []string{"a;touch x", "-x", "a.*", "a/b", "a b", "$(id)"} {
		if ValidateSymbol(s) == nil {
			t.Fatal(s)
		}
	}
}
func TestRunner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture-tool")
	// Controlled test executable, never constructed from user query input.
	if e := os.WriteFile(p, []byte("#!/bin/sh\ncase \"$1\" in\ncap) printf '1234567890';;\nfail) echo diagnostic >&2; exit 2;;\nwait) exec sleep 2;;\n*) printf '%s' \"$1\";;\nesac\n"), 0700); e != nil {
		t.Fatal(e)
	}
	r := Runner{MaxBytes: 4, Timeout: 50 * time.Millisecond}
	if _, e := r.Run(context.Background(), p, "cap"); !errors.Is(e, ErrOutputLimit) {
		t.Fatal(e)
	}
	if _, e := r.Run(context.Background(), p, "wait"); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if _, e := r.Run(context.Background(), p, "fail"); e == nil {
		t.Fatal("expected command failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.Run(ctx, p); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	out, e := (Runner{}).Run(context.Background(), p, "$(touch inert)")
	if e != nil || out.Stdout != "$(touch inert)" {
		t.Fatal(out, e)
	}
}
