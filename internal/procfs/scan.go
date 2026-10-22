package procfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nexryai/selinspect/internal/selinux"
)

type Process struct {
	PID, PPID                       int
	StartTimeTicks                  uint64
	UID, GID                        uint32
	Name, RawContext, ContextStatus string
	Context                         selinux.SecurityContext
	ContextKnown, KernelThread      bool
}
type ProcessSource interface {
	List(context.Context) ([]Process, error)
}
type Source struct{ Root string }

// ParseStat handles spaces and closing parentheses inside the comm field.
func ParseStat(raw string) (ppid int, start uint64, kernel bool, err error) {
	i := strings.LastIndex(raw, ") ")
	if i < 0 {
		return 0, 0, false, fmt.Errorf("malformed proc stat")
	}
	f := strings.Fields(raw[i+2:])
	if len(f) < 20 {
		return 0, 0, false, fmt.Errorf("short proc stat")
	}
	ppid, err = strconv.Atoi(f[1])
	if err != nil {
		return
	}
	start, err = strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return
	}
	flags, e := strconv.ParseUint(f[6], 10, 64)
	if e != nil {
		err = e
		return
	}
	kernel = flags&0x00200000 != 0
	return
}

func (s Source) List(ctx context.Context) ([]Process, error) {
	root := s.Root
	if root == "" {
		root = "/proc"
	}
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []Process
	for _, d := range dirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, e := strconv.Atoi(d.Name())
		if e != nil || !d.IsDir() {
			continue
		}
		dir := filepath.Join(root, d.Name())
		stat, e := os.ReadFile(filepath.Join(dir, "stat"))
		if e != nil {
			continue
		}
		ppid, start, kernel, e := ParseStat(string(stat))
		if e != nil {
			continue
		}
		p := Process{PID: pid, PPID: ppid, StartTimeTicks: start, KernelThread: kernel, ContextStatus: "unavailable"}
		status, e := os.ReadFile(filepath.Join(dir, "status"))
		if e != nil {
			continue
		}
		uidKnown, gidKnown := false, false
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			if f[0] == "Uid:" || f[0] == "Gid:" {
				n, e := strconv.ParseUint(f[1], 10, 32)
				if e != nil {
					continue
				}
				if f[0] == "Uid:" {
					p.UID = uint32(n)
					uidKnown = true
				} else {
					p.GID = uint32(n)
					gidKnown = true
				}
			}
		}
		if !uidKnown || !gidKnown {
			continue
		}
		name, e := os.ReadFile(filepath.Join(dir, "comm"))
		if e == nil {
			p.Name = strings.TrimSpace(string(name))
		} else {
			p.Name = "(unavailable)"
		}
		raw, e := os.ReadFile(filepath.Join(dir, "attr/current"))
		if e == nil {
			p.RawContext = strings.TrimSpace(strings.TrimRight(string(raw), "\x00"))
			p.Context, e = selinux.ParseContext(p.RawContext)
			if e == nil {
				p.ContextKnown = true
				p.ContextStatus = "known"
			} else {
				p.ContextStatus = "no SELinux context"
			}
		} else {
			p.ContextStatus = e.Error()
		}
		// Recheck identity after all reads to avoid mixing data from a reused PID.
		again, e := os.ReadFile(filepath.Join(dir, "stat"))
		if e != nil {
			continue
		}
		_, check, _, e := ParseStat(string(again))
		if e != nil || check != start {
			continue
		}
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func Group(processes []Process) map[string][]Process {
	groups := make(map[string][]Process)
	for _, p := range processes {
		key := "[context unavailable]"
		if p.ContextKnown {
			key = p.Context.Type
		}
		groups[key] = append(groups[key], p)
	}
	return groups
}
