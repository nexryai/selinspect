// Package tui contains the keyboard interface. Policy and host reads run outside Update.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/nexryai/selinspect/internal/policy"
	"github.com/nexryai/selinspect/internal/procfs"
	"github.com/nexryai/selinspect/internal/selinux"
)

type Options struct {
	PID                                           int
	Type, Path, Source, Target, Class, Permission string
	NoColor                                       bool
}
type row struct {
	label, kind, value string
	process            *procfs.Process
}
type result struct {
	id       int
	rows     []row
	detail   string
	err      error
	snapshot []procfs.Process
	at       time.Time
}
type Model struct {
	preservePID                int
	preserveStart              uint64
	backend                    *policy.SETools
	options                    Options
	mode                       string
	rows                       []row
	processes                  []procfs.Process
	snapshotAt                 time.Time
	selected                   int
	filter                     string
	width, height              int
	detail                     string
	viewport                   viewport.Model
	input                      textinput.Model
	editing                    string
	focusDetail, grouped, busy bool
	request                    int
	cancel                     context.CancelFunc
	diagnostics                string
}

func New(b *policy.SETools, opts Options, diagnostics string) Model {
	input := textinput.New()
	input.CharLimit = 4096
	input.Prompt = "> "
	v := viewport.New()
	v.SetWidth(80)
	v.SetHeight(15)
	return Model{backend: b, options: opts, mode: "Processes", width: 80, height: 24, viewport: v, input: input, diagnostics: diagnostics}
}
func (m Model) Init() tea.Cmd { return func() tea.Msg { return startMsg{} } }

type startMsg struct{}

func (m *Model) task(work func(context.Context) result) tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.request++
	id := m.request
	m.busy = true
	return func() tea.Msg { r := work(ctx); r.id = id; return r }
}
func (m *Model) setDetail(s string) { m.detail = s; m.viewport.SetContent(s); m.viewport.GotoTop() }
func (m *Model) load(mode string) tea.Cmd {
	if mode == "Processes" && m.mode == mode {
		rr := m.filtered()
		if len(rr) > 0 && m.selected < len(rr) && rr[m.selected].process != nil {
			p := rr[m.selected].process
			m.preservePID = p.PID
			m.preserveStart = p.StartTimeTicks
		}
	}
	m.mode = mode
	m.filter = ""
	m.selected = 0
	m.rows = nil
	m.focusDetail = false
	m.setDetail("")
	b := m.backend
	grouped := m.grouped
	return m.task(func(ctx context.Context) result {
		if mode == "Processes" {
			p, e := (procfs.Source{}).List(ctx)
			r := result{snapshot: p, at: time.Now(), err: e}
			if grouped {
				groups := procfs.Group(p)
				keys := make([]string, 0, len(groups))
				for k := range groups {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					r.rows = append(r.rows, row{label: fmt.Sprintf("%s (%d processes)", k, len(groups[k])), kind: "group", value: k})
				}
			} else {
				for i := range p {
					item := p[i]
					domain := "[" + item.ContextStatus + "]"
					if item.ContextKnown {
						domain = item.Context.Type
					}
					r.rows = append(r.rows, row{label: fmt.Sprintf("%d uid:%d %s %s", item.PID, item.UID, item.Name, domain), kind: "process", value: strconv.Itoa(item.PID), process: &item})
				}
			}
			r.detail = "Live process snapshot. Enter: context and memberships. g: group by domain.\n/proc command lines and environments are never read."
			return r
		}
		if b == nil {
			return result{err: fmt.Errorf("policy backend unavailable; Rocky/RHEL: sudo dnf install setools-console")}
		}
		var names []string
		var e error
		kind := "type"
		if mode == "Attributes" {
			names, e = b.Attributes(ctx)
			kind = "attribute"
		} else {
			names, e = b.Types(ctx)
		}
		r := result{err: e, rows: make([]row, 0)}
		for _, n := range names {
			r.rows = append(r.rows, row{label: n, kind: kind, value: n})
		}
		r.detail = "Select a symbol and press Enter. Membership is many-to-many, never inheritance."
		return r
	})
}
func typeDetail(ctx context.Context, b *policy.SETools, n string) result {
	if b == nil {
		return result{err: fmt.Errorf("process domain known, but policy backend unavailable")}
	}
	t, e := b.Type(ctx, n)
	if e != nil {
		return result{err: e}
	}
	state := "unknown"
	permissive, pe := b.PermissiveTypes(ctx)
	if pe == nil {
		state = "no"
		for _, p := range permissive {
			if p == t.Name {
				state = "yes (compiled policy)"
			}
		}
	}
	var s strings.Builder
	fmt.Fprintf(&s, "Type: %s\nAliases: %s\nDomain permissive: %s\n\nType                    Attribute\n", t.Name, strings.Join(t.Aliases, ", "), state)
	r := result{rows: make([]row, 0)}
	for _, a := range t.Attributes {
		fmt.Fprintf(&s, "%s --[member of]--> %s\n", t.Name, a)
		r.rows = append(r.rows, row{label: a, kind: "attribute", value: a})
	}
	fmt.Fprintf(&s, "\n%d memberships. Enter an Attribute to see its members.\ns: select this Type as source; t: target (on Type rows).\n:source TYPE / :target TYPE also work here.", len(t.Attributes))
	r.detail = s.String()
	return r
}
func (m *Model) open() tea.Cmd {
	rows := m.filtered()
	if len(rows) == 0 {
		return nil
	}
	item := rows[min(m.selected, len(rows)-1)]
	b := m.backend
	if item.kind == "group" {
		var r []row
		for _, p := range m.processes {
			key := "[context unavailable]"
			if p.ContextKnown {
				key = p.Context.Type
			}
			if key == item.value {
				copy := p
				r = append(r, row{label: fmt.Sprintf("%d uid:%d %s", p.PID, p.UID, p.Name), kind: "process", process: &copy})
			}
		}
		m.rows = r
		m.filter = ""
		m.selected = 0
		return nil
	}
	return m.task(func(ctx context.Context) result {
		if item.kind == "attribute" {
			if b == nil {
				return result{err: fmt.Errorf("backend unavailable")}
			}
			a, e := b.Attribute(ctx, item.value)
			if e != nil {
				return result{err: e}
			}
			r := result{rows: make([]row, 0)}
			for _, n := range a.MemberTypes {
				r.rows = append(r.rows, row{label: n, kind: "type", value: n})
			}
			r.detail = fmt.Sprintf("Attribute: %s\nMembers: %d\n\nType --[member of]--> Attribute\nSelect any Type for all its independent memberships.\nAttribute --[contains]--> Type is the inverse relation.\n\nUse / to filter and PgDown to page through all members.", a.Name, len(a.MemberTypes))
			return r
		}
		if item.process != nil {
			p := item.process
			s := fmt.Sprintf("PID %d (start ticks %d), PPID %d\nName: %s\nLinux UID/GID: %d/%d\nKernel thread: %t\nRaw context: %s\nContext status: %s\n", p.PID, p.StartTimeTicks, p.PPID, p.Name, p.UID, p.GID, p.KernelThread, p.RawContext, p.ContextStatus)
			if p.ContextKnown {
				c := p.Context
				s += fmt.Sprintf("User: %s\nRole: %s\nType/domain: %s\nRange: %s\n\n", c.User, c.Role, c.Type, c.Range)
				r := typeDetail(ctx, b, c.Type)
				r.detail = s + r.detail
				return r
			}
			return result{detail: s}
		}
		return typeDetail(ctx, b, item.value)
	})
}

// SafeText removes terminal control sequences and untrusted control characters.
func SafeText(s string) string {
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
func (m Model) filtered() []row {
	if m.filter == "" {
		return m.rows
	}
	var out []row
	for _, r := range m.rows {
		if strings.Contains(strings.ToLower(r.label), strings.ToLower(m.filter)) {
			out = append(out, r)
		}
	}
	return out
}
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case startMsg:
		if m.backend != nil && m.backend.Policy != "" && m.options.Type == "" {
			return m, m.load("Types")
		}
		if m.options.Type != "" {
			n := m.options.Type
			b := m.backend
			m.mode = "Types"
			return m, m.task(func(ctx context.Context) result { return typeDetail(ctx, b, n) })
		}
		return m, m.load("Processes")
	case tea.WindowSizeMsg:
		m.width = max(10, msg.Width)
		m.height = max(8, msg.Height)
		m.resize()
		return m, nil
	case result:
		if msg.id != m.request {
			return m, nil
		}
		m.busy = false
		if msg.snapshot != nil {
			m.processes = msg.snapshot
			m.snapshotAt = msg.at
		}
		if msg.err != nil {
			m.setDetail("Query unavailable: " + msg.err.Error() + "\nNo policy/access conclusion is available.")
		} else {
			if msg.rows != nil {
				m.rows = msg.rows
				m.selected = 0
				m.filter = ""
			}
			m.setDetail(msg.detail)
			if m.preservePID != 0 {
				found := false
				for i, r := range m.rows {
					if r.process != nil && r.process.PID == m.preservePID && r.process.StartTimeTicks == m.preserveStart {
						m.selected = i
						found = true
						break
					}
				}
				if !found {
					m.setDetail("Selected process exited or PID identity changed. Select a process again.")
				}
				m.preservePID = 0
			}
			if m.options.PID != 0 {
				for i, r := range m.rows {
					if r.process != nil && r.process.PID == m.options.PID {
						m.selected = i
						break
					}
				}
				m.options.PID = 0
			}
		}
		return m, nil
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		if m.editing != "" {
			if key == "esc" {
				m.editing = ""
				m.input.Blur()
				return m, nil
			}
			if key == "enter" {
				value := m.input.Value()
				editing := m.editing
				m.editing = ""
				m.input.Blur()
				if editing == "filter" {
					m.filter = value
					m.selected = 0
					return m, nil
				}
				return m, m.command(value)
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
		switch key {
		case "q":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "esc":
			if m.cancel != nil {
				m.cancel()
			}
			m.request++
			m.busy = false
			return m, m.load(m.mode)
		case "1":
			return m, m.load("Processes")
		case "2":
			return m, m.load("Types")
		case "3":
			return m, m.load("Attributes")
		case "g":
			m.grouped = !m.grouped
			return m, m.load("Processes")
		case "r":
			if m.backend != nil {
				m.backend.Invalidate()
			}
			return m, m.load(m.mode)
		case "?":
			m.focusDetail = true
			m.setDetail(help)
			return m, nil
		case "/", ":":
			m.editing = "command"
			if key == "/" {
				m.editing = "filter"
			}
			m.input.SetValue("")
			return m, m.input.Focus()
		case "tab":
			m.focusDetail = !m.focusDetail
			return m, nil
		case "enter":
			return m, m.open()
		case "j", "down":
			if m.focusDetail {
				m.viewport.ScrollDown(1)
			} else {
				m.selected = min(m.selected+1, max(0, len(m.filtered())-1))
			}
			return m, nil
		case "k", "up":
			if m.focusDetail {
				m.viewport.ScrollUp(1)
			} else {
				m.selected = max(0, m.selected-1)
			}
			return m, nil
		case "pgdown":
			if m.focusDetail {
				m.viewport.PageDown()
			} else {
				m.selected = min(m.selected+max(1, m.height-9), max(0, len(m.filtered())-1))
			}
			return m, nil
		case "pgup":
			if m.focusDetail {
				m.viewport.PageUp()
			} else {
				m.selected = max(0, m.selected-max(1, m.height-9))
			}
			return m, nil
		case "s", "t":
			rows := m.filtered()
			if len(rows) > 0 {
				item := rows[min(m.selected, len(rows)-1)]
				n := item.value
				if item.process != nil && item.process.ContextKnown {
					n = item.process.Context.Type
				}
				if item.kind == "type" || (item.process != nil && item.process.ContextKnown) {
					field := "source"
					if key == "t" {
						field = "target"
					}
					return m, m.command(field + " " + n)
				}
			}
			return m, nil
		}
	}
	return m, nil
}
func (m *Model) command(value string) tea.Cmd {
	f := strings.Fields(value)
	if len(f) == 0 {
		return nil
	}
	if (f[0] == "type" || f[0] == "attribute") && len(f) == 2 {
		m.rows = []row{{kind: f[0], value: f[1]}}
		m.selected = 0
		m.filter = ""
		return m.open()
	}
	m.setDetail("Unknown command. Press ? for keyboard help.")
	return nil
}
func (m *Model) resize() {
	width := m.width
	if width >= 100 {
		width = width - width/3 - 3
	}
	m.viewport.SetWidth(max(1, width))
	m.viewport.SetHeight(max(1, m.height-9))
	m.input.SetWidth(max(1, m.width-16))
}
func (m Model) View() tea.View {
	m.resize()
	var left strings.Builder
	rows := m.filtered()
	height := max(1, m.height-9)
	start := max(0, m.selected-height+1)
	fmt.Fprintf(&left, "%s (%d/%d) filter:%s\n", m.mode, len(rows), len(m.rows), SafeText(m.filter))
	for i := start; i < min(len(rows), start+height-1); i++ {
		marker := "  "
		if i == m.selected {
			marker = "> "
		}
		fmt.Fprintln(&left, marker+SafeText(rows[i].label))
	}
	if len(rows) == 0 {
		left.WriteString("No results\n")
	}
	body := left.String()
	if m.width >= 100 {
		lw := m.width / 3
		body = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(lw).MaxWidth(lw).Render(body), " | ", m.viewport.View())
	} else if m.focusDetail {
		body = m.viewport.View()
	}
	status := "ready"
	if m.busy {
		status = "query running (Esc cancels)"
	}
	footer := "1 Processes  2 Types  3 Attributes  / filter  : command  ? help  q quit"
	if m.editing != "" {
		footer = m.editing + ": " + m.input.View()
	}
	policySource := "backend unavailable"
	if m.backend != nil {
		policySource = m.backend.Description()
	}
	header := fmt.Sprintf("selinspect | SELinux: %s | %s\n%s\nsource=%s target=%s class=%s permission=%s\n%s", selinux.Enforcement(), status, policySource, m.options.Source, m.options.Target, m.options.Class, m.options.Permission, m.diagnostics)
	output := header + "\n" + body + "\n" + footer + "\nTab: list/details  Enter: expand  j/k arrows: scroll  PgUp/PgDn: page  r: refresh"
	// Crop every line to the terminal. Viewport handles detail scrolling.
	ll := strings.Split(output, "\n")
	for i := range ll {
		ll[i] = ansi.Truncate(SafeText(ll[i]), m.width, "")
	}
	if len(ll) > m.height {
		ll = ll[:m.height]
	}
	v := tea.NewView(strings.Join(ll, "\n"))
	v.AltScreen = true
	return v
}

const help = `selinspect — keyboard help
1 Processes  2 Types  3 Attributes
j/k or arrows: move selection; Enter: expand selected symbol
Tab: switch list/detail pane (also on narrow terminals)
PgUp/PgDown: page list or detail; /: filter current list
Esc: cancel query and return to current entry view
r: refresh snapshot and invalidate policy cache; g: group processes
q / Ctrl+C: quit; ?: help; : opens command input
:type TYPE    :attribute ATTRIBUTE

Legend: process / Type / Attribute / object class / permission /
allow-rule / conditional. Type --[member of]--> Attribute;
Attribute --[contains]--> Type. Membership is many-to-many.
SELinux User differs from UNIX UID. A role is not an allow rule.
Root does not automatically bypass SELinux. TE matches are policy
findings; DAC, MLS/MCS, constraints and actual access are not evaluated.
Use the selected process's actual Type, never infer it from its name.`
