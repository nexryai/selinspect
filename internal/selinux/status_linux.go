package selinux

import (
	"os"
	"strings"
)

func Enforcement() string {
	b, err := os.ReadFile("/sys/fs/selinux/enforce")
	if os.IsNotExist(err) {
		if _, e := os.Stat("/sys/fs/selinux"); os.IsNotExist(e) {
			return "disabled"
		}
		return "unknown (SELinux filesystem unavailable)"
	}
	if err != nil {
		return "unknown: " + err.Error()
	}
	switch strings.TrimSpace(string(b)) {
	case "1":
		return "enforcing"
	case "0":
		return "global-permissive"
	}
	return "unknown"
}
