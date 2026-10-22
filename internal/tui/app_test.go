package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func key(s string) tea.KeyPressMsg { return tea.KeyPressMsg{Code: []rune(s)[0], Text: s} }
func TestNavigationAndResize(t *testing.T) {
	m := New(nil, Options{}, "limited mode")
	for i := 0; i < 10000; i++ {
		m.rows = append(m.rows, row{label: fmt.Sprintf("Type_%05d", i), kind: "type"})
	}
	mm, _ := m.Update(key("j"))
	m = mm.(Model)
	if m.selected != 1 {
		t.Fatal(m.selected)
	}
	m.filter = "09999"
	if len(m.filtered()) != 1 {
		t.Fatal("filter")
	}
	m.filter = ""
	m.selected = 9999
	for _, w := range []int{20, 80, 120} {
		mm, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		m = mm.(Model)
		v := m.View().Content
		if len(strings.Split(v, "\n")) > 24 {
			t.Fatal("too tall")
		}
		for _, l := range strings.Split(v, "\n") {
			if ansi.StringWidth(l) > w {
				t.Fatalf("too wide %d: %q", w, l)
			}
		}
		if strings.Contains(v, "Type_00000") {
			t.Fatal("pagination failed")
		}
	}
	mm, _ = m.Update(key("?"))
	m = mm.(Model)
	if !m.focusDetail || !strings.Contains(m.detail, "many-to-many") {
		t.Fatal("help")
	}
	m.request = 9
	mm, _ = m.Update(result{id: 8, detail: "stale"})
	if mm.(Model).detail == "stale" {
		t.Fatal("stale response")
	}
	mm, _ = m.Update(result{id: 9, err: fmt.Errorf("backend missing")})
	if !strings.Contains(mm.(Model).detail, "No policy/access conclusion") {
		t.Fatal("limited mode")
	}
}
func TestUntrustedTerminalContent(t *testing.T) {
	s := SafeText("hello\x1b[2J\x1b]52;c;YQ==\a\rbye")
	if strings.ContainsAny(s, "\x1b\a\r") || !strings.Contains(s, "hello") {
		t.Fatalf("%q", s)
	}
}
