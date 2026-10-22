package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func lines(raw string) []string { return strings.Split(strings.TrimSpace(raw), "\n") }
func ParseList(raw, heading string) ([]string, error) {
	var names []string
	seenHeader := false
	count := -1
	for _, l := range lines(raw) {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, heading+":") {
			var e error
			count, e = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, heading+":")))
			if e != nil {
				return nil, fmt.Errorf("invalid %s count", heading)
			}
			seenHeader = true
			continue
		}
		if !seenHeader || ValidateSymbol(l) != nil {
			return nil, fmt.Errorf("unsupported %s output: %q", heading, l)
		}
		names = append(names, l)
	}
	if !seenHeader || count != len(names) {
		return nil, fmt.Errorf("incomplete %s output", heading)
	}
	sort.Strings(names)
	return names, nil
}

var typeLine = regexp.MustCompile(`^type ([A-Za-z_][A-Za-z0-9_]*)(?: alias (\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*))?(?:, (.*))?;$`)

func ParseType(raw string) (TypeInfo, error) {
	var t TypeInfo
	for _, l := range lines(raw) {
		l = strings.TrimSpace(l)
		if l == "" || l == "Types: 1" {
			continue
		}
		m := typeLine.FindStringSubmatch(l)
		if m == nil || t.Name != "" {
			return t, fmt.Errorf("unsupported Type output: %q", l)
		}
		t.Name = m[1]
		t.Aliases = strings.Fields(strings.Trim(m[2], "{} "))
		if m[3] != "" {
			for _, a := range strings.Split(m[3], ",") {
				a = strings.TrimSpace(a)
				if ValidateSymbol(a) != nil {
					return t, fmt.Errorf("invalid Attribute")
				}
				t.Attributes = append(t.Attributes, a)
			}
		}
	}
	if t.Name == "" {
		return t, fmt.Errorf("Type not found")
	}
	return t, nil
}
func ParseAttribute(raw string) (AttributeInfo, error) {
	var a AttributeInfo
	for _, l := range lines(raw) {
		l = strings.TrimSpace(l)
		if l == "" || l == "Type Attributes: 1" {
			continue
		}
		if strings.HasPrefix(l, "attribute ") && strings.HasSuffix(l, ";") && a.Name == "" {
			a.Name = strings.TrimSuffix(strings.TrimPrefix(l, "attribute "), ";")
			if ValidateSymbol(a.Name) != nil {
				return a, fmt.Errorf("invalid Attribute")
			}
			continue
		}
		if a.Name == "" || ValidateSymbol(l) != nil {
			return a, fmt.Errorf("unsupported Attribute output: %q", l)
		}
		a.MemberTypes = append(a.MemberTypes, l)
	}
	if a.Name == "" {
		return a, fmt.Errorf("Attribute not found")
	}
	return a, nil
}

var ruleLine = regexp.MustCompile(`^(allow|allowxperm) ([A-Za-z_][A-Za-z0-9_]*) ([A-Za-z_][A-Za-z0-9_]*):([A-Za-z_][A-Za-z0-9_]*) (.+);(?:\s+\[ (.+) \]:(True|False))?$`)

func ParseRules(raw string) ([]Rule, error) {
	var rules []Rule
	for _, l := range lines(raw) {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		m := ruleLine.FindStringSubmatch(l)
		if m == nil {
			return nil, fmt.Errorf("unsupported rule output: %q", l)
		}
		r := Rule{Kind: m[1], SourceSymbol: m[2], TargetSymbol: m[3], Class: m[4], Raw: l, Condition: m[6], Branch: m[7], ConditionState: "unconditional"}
		if r.Condition != "" {
			r.ConditionState = "unknown"
		}
		if r.Kind == "allow" {
			r.Permissions = strings.Fields(strings.Trim(m[5], "{} "))
			for _, p := range r.Permissions {
				if ValidateSymbol(p) != nil {
					return nil, fmt.Errorf("unsupported permission expression")
				}
			}
			if len(r.Permissions) == 0 {
				return nil, fmt.Errorf("empty permissions")
			}
		}
		rules = append(rules, r)
	}
	return rules, nil
}
