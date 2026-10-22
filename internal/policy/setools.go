package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SETools struct {
	Policy string
	Runner Runner
	mu     sync.Mutex
	cache  map[string]CommandResult
	Help   map[string]string
}

func New(ctx context.Context, file string) (*SETools, error) {
	if file != "" {
		var err error
		file, err = filepath.Abs(file)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("policy must be a regular binary file")
		}
	}
	b := &SETools{Policy: file, cache: make(map[string]CommandResult), Help: make(map[string]string)}
	for _, tool := range []string{"seinfo", "sesearch"} {
		out, err := b.Runner.Run(ctx, tool, "--help")
		if err != nil {
			return b, fmt.Errorf("policy backend unavailable: %w; Rocky/RHEL: sudo dnf install setools-console", err)
		}
		b.Help[tool] = out.Stdout
	}
	return b, nil
}
func (b *SETools) Identity() string {
	file := b.Policy
	if file == "" {
		file = "/sys/fs/selinux/policy"
	}
	st, err := os.Stat(file)
	if err != nil {
		return file + ":unavailable"
	}
	extra := ""
	if b.Policy == "" {
		data, _ := os.ReadFile("/sys/fs/selinux/status")
		extra = fmt.Sprintf("%x", data)
	}
	return fmt.Sprintf("%s:%d:%d:%s", file, st.Size(), st.ModTime().UnixNano(), extra)
}
func (b *SETools) Invalidate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache = make(map[string]CommandResult)
}
func (b *SETools) run(ctx context.Context, tool string, args ...string) (CommandResult, error) {
	if b.Policy != "" {
		args = append(args, b.Policy)
	}
	key := b.Identity() + tool + strings.Join(args, "\x00")
	b.mu.Lock()
	out, ok := b.cache[key]
	b.mu.Unlock()
	if ok {
		return out, nil
	}
	out, err := b.Runner.Run(ctx, tool, args...)
	if err == nil {
		b.mu.Lock()
		b.cache[key] = out
		b.mu.Unlock()
	}
	return out, err
}
func (b *SETools) Types(ctx context.Context) ([]string, error) {
	o, e := b.run(ctx, "seinfo", "-t")
	if e != nil {
		return nil, e
	}
	return ParseList(o.Stdout, "Types")
}
func (b *SETools) Attributes(ctx context.Context) ([]string, error) {
	o, e := b.run(ctx, "seinfo", "-a")
	if e != nil {
		return nil, e
	}
	return ParseList(o.Stdout, "Type Attributes")
}
func (b *SETools) Type(ctx context.Context, n string) (TypeInfo, error) {
	if e := ValidateSymbol(n); e != nil {
		return TypeInfo{}, e
	}
	o, e := b.run(ctx, "seinfo", "-t", n, "-x")
	if e != nil {
		return TypeInfo{}, e
	}
	t, e := ParseType(o.Stdout)
	if e == nil && t.Name != n {
		found := false
		for _, a := range t.Aliases {
			if a == n {
				found = true
			}
		}
		if !found {
			return t, fmt.Errorf("Type not found: %s", n)
		}
	}
	return t, e
}
func (b *SETools) Attribute(ctx context.Context, n string) (AttributeInfo, error) {
	if e := ValidateSymbol(n); e != nil {
		return AttributeInfo{}, e
	}
	o, e := b.run(ctx, "seinfo", "-a", n, "-x")
	if e != nil {
		return AttributeInfo{}, e
	}
	a, e := ParseAttribute(o.Stdout)
	if e == nil && a.Name != n {
		return a, fmt.Errorf("Attribute not found: %s", n)
	}
	return a, e
}
func (b *SETools) PermissiveTypes(ctx context.Context) ([]string, error) {
	if !strings.Contains(b.Help["seinfo"], "--permissive") {
		return nil, fmt.Errorf("permissive query unsupported")
	}
	o, e := b.run(ctx, "seinfo", "--permissive")
	if e != nil {
		return nil, e
	}
	return ParseList(o.Stdout, "Permissive Types")
}
func (b *SETools) QueryArgs(q RuleQuery) ([]string, error) {
	args := []string{"-A"}
	for _, p := range []struct{ flag, value string }{{"-s", q.Source}, {"-t", q.Target}, {"-c", q.Class}, {"-p", q.Permission}} {
		if p.value != "" {
			if e := ValidateSymbol(p.value); e != nil {
				return nil, e
			}
			args = append(args, p.flag, p.value)
		}
	}
	if q.Target == "" {
		return nil, fmt.Errorf("a concrete target Type is required")
	}
	return args, nil
}
func (b *SETools) RawRules(ctx context.Context, q RuleQuery) (CommandResult, error) {
	for _, n := range []string{q.Source, q.Target} {
		if n != "" {
			if _, e := b.Type(ctx, n); e != nil {
				return CommandResult{}, e
			}
		}
	}
	args, e := b.QueryArgs(q)
	if e != nil {
		return CommandResult{}, e
	}
	return b.run(ctx, "sesearch", args...)
}
func (b *SETools) AllowRules(ctx context.Context, q RuleQuery) ([]Rule, error) {
	o, e := b.RawRules(ctx, q)
	if e != nil {
		return nil, e
	}
	return ParseRules(o.Stdout)
}
func (b *SETools) Description() string {
	if b.Policy != "" {
		return "offline binary policy: " + b.Policy + " (not the live enforced policy)"
	}
	return "local policy selected by SETools; captured " + time.Now().Format(time.RFC3339)
}
