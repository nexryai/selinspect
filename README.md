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

## Interactive process and policy browser

```sh
go build ./cmd/selinspect
./selinspect
./selinspect --pid PID
./selinspect --type EXISTING_TYPE
./selinspect --policy /absolute/path/to/policy.bin --type EXISTING_TYPE
./selinspect --no-color
```

`1` opens processes, `2` Types and `3` Attributes. Use arrows or `j/k`, `Enter` to expand, `/` to filter, `Tab` to switch list/details, `PgUp/PgDn` to page, `g` to group processes by domain, `r` to refresh, `Esc` to cancel/back, `?` for help, and `q` to quit. At widths below 100 columns, Tab switches the visible pane. All output works in monochrome; control sequences from external names/output are stripped. `:type NAME` and `:attribute NAME` open a symbol directly. Entering an Attribute lists its complete membership with pagination; entering a member Type lists all its independent memberships.

The process view includes PID, Linux numeric UID, name, domain and details including PPID, GID, kernel-thread flag and start ticks. Process reads are rechecked for PID reuse. Refresh preserves PID + start-tick identity. Unreadable labels stay unavailable. Queries run asynchronously; canceled and stale responses cannot replace a newer view. No policy query runs per PID during inventory. Offline policy starts in Types; its banner explicitly distinguishes policy-file findings from host contexts.
