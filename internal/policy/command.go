package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var symbol = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ValidateSymbol(s string) error {
	if !symbol.MatchString(s) {
		return fmt.Errorf("invalid policy symbol %q", s)
	}
	return nil
}

var ErrOutputLimit = errors.New("SETools output limit exceeded; results are incomplete")

type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := b.limit - b.buf.Len()
	if n > left {
		b.overflow = true
		p = p[:max(0, left)]
	}
	_, _ = b.buf.Write(p)
	if b.overflow {
		return n, ErrOutputLimit
	}
	return n, nil
}

type Runner struct {
	Timeout  time.Duration
	MaxBytes int
}

func (r Runner) Run(ctx context.Context, binary string, args ...string) (CommandResult, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	limit := r.MaxBytes
	if limit == 0 {
		limit = 4 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	env := os.Environ()
	clean := env[:0]
	for _, e := range env {
		if !strings.HasPrefix(e, "LC_ALL=") {
			clean = append(clean, e)
		}
	}
	cmd.Env = append(clean, "LC_ALL=C")
	stdout, stderr := &cappedBuffer{limit: limit}, &cappedBuffer{limit: limit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	result := CommandResult{binary, append([]string(nil), args...), stdout.buf.String(), stderr.buf.String()}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if stdout.overflow || stderr.overflow {
		return result, ErrOutputLimit
	}
	if err != nil {
		return result, fmt.Errorf("%s: %w: %s", binary, err, strings.TrimSpace(result.Stderr))
	}
	return result, nil
}
