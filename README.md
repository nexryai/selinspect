# selinspect

Read-only SELinux policy relationship explorer for Linux. This repository is being built in tested milestones; the first milestone provides a Go core for SELinux contexts, `/proc` inventory and bounded SETools queries.

## Requirements

Go 1.26.10 or newer (the repository's initial toolchain), Linux, and `seinfo` / `sesearch` from SETools. On Rocky/RHEL, installation advice is `sudo dnf install setools-console`; the application never installs packages or elevates privileges. Development host: Go 1.26.10, SETools 4.6.0. Rocky/RHEL 10 live validation is still required.

Bubble Tea v2.1.0, Bubbles v2.2.1 and Lip Gloss v2.0.6 are pinned; their published Go module requirements were checked against the installed toolchain. All use v2 import paths. Primary references: [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), [Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Semantics and safety

Types and Attributes form many-to-many membership sets, not inheritance. Original rule symbols are preserved. A TE allow-rule match never proves successful filesystem access: DAC, parent traversal, MLS/MCS, constraints, capabilities, namespaces, mounts and other mechanisms are not fully evaluated. Conditional rule branches remain unknown until live Boolean evaluation is available. `map`, `open`, `read` and `dir:search` are distinct operations. Root is not automatically exempt from SELinux.

Commands use validated argv, `LC_ALL=C`, a 15 second deadline and separate 4 MiB stdout/stderr limits. Incomplete, canceled and malformed outputs are errors, never complete results. The binary reads neither process arguments nor environments. It does not mutate policy, labels or enforcement. Fictional test Types are never runtime defaults.

## Checks

```sh
gofmt -w cmd internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/selinspect
```

Fixture tests do not need SELinux or root. Live integration must discover installed symbols first; no Docker or custom policy is required.

The phase 0 executable reports enforcement, process count and backend availability. `go run ./cmd/selinspect --help` and `--version` are available. Interactive navigation follows in the next milestone.
