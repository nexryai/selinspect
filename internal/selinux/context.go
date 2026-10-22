package selinux

import (
	"fmt"
	"strings"
)

type SecurityContext struct{ User, Role, Type, Range string }

func ParseContext(raw string) (SecurityContext, error) {
	raw = strings.TrimSpace(strings.TrimRight(raw, "\x00"))
	p := strings.SplitN(raw, ":", 4)
	if len(p) != 4 {
		return SecurityContext{}, fmt.Errorf("unavailable or malformed SELinux context")
	}
	for _, s := range p {
		if s == "" || strings.ContainsAny(s, "\n\r\t ") {
			return SecurityContext{}, fmt.Errorf("malformed SELinux context")
		}
	}
	return SecurityContext{p[0], p[1], p[2], p[3]}, nil
}
