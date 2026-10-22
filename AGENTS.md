# AGENTS.md — selinspect: SELinux Policy Relationship Explorer

> Engineering and product specification for an implementation agent.
> Revised for Rocky Linux 10.2 / RHEL 10, but designed to work with **any installed SELinux policy**, including an untouched default policy with **no locally defined Types**.

## 1. Mission

Implement **`selinspect`**, a **read-only Go terminal user interface (TUI)** for understanding how SELinux confines running processes and controls access to files and other objects. Its principal job is to make the relationships among **process domains, object Types, Type Attributes, object classes, permissions, and `allow` rules** transparent and navigable.

The tool is motivated by investigating privileged background services on a Rocky Linux server and learning why a root process is not automatically exempt from SELinux. It must teach the *general mechanism*, not implement a special-purpose `/var/compose` inspector.

**Primary outcomes:**

1. Choose a **currently running process**; inspect the actual process security context, Type and Type Attributes.
2. Choose **any existing filesystem path** or **any Type already present in the loaded policy** as the target. A path and a running process are **not prerequisites** to investigate a Type-to-Type rule.
3. Explain whether and **why a specified TE `allow` rule matches**, including on either or both sides via Type Attributes.
4. Browse Type-to-Attribute and Attribute-to-Type membership in both directions to demonstrate their **many-to-many relationship**.
5. Investigate a target Type in reverse: **which source domains / rules might permit reading, writing, creating, or traversing it?** Correlate matches with currently running processes without claiming that a matching source Type is necessarily active.
6. Distinguish a **policy rule match** from actual end-to-end access (DAC, file kind, parent directories, mode, SELinux enforcement, conditional rules, MLS/MCS, namespaces, etc.).

Provide useful, safe, honest results even where a target Type has no `allow` matches, a daemon's SELinux context is unreadable, the policy contains no custom Types, or tools cannot access policy data.

## 2. Scope and supported environments

- Primary tested target: **Rocky Linux 10.2**. Also target RHEL 10 and closely compatible Linux systems using SELinux targeted policies.
- The application **MUST NOT depend on** `compose_data_t`, `container_runtime_t`, Docker, Podman, `/var/compose`, a custom policy module, a particular process name, or a particular SELinux User/Role being present.
- No fixed Types, Attributes, paths, Boolean names, or PIDs in the runtime logic. All discovered symbols come from the selected policy and live host.
- SELinux must be checked at startup. When disabled or policy tools are missing, show a meaningful **limited-mode UI** (process inventory if readable, diagnostics, installation advice); do not crash or invent rules.
- Prefer an ordinary user account; handle permissions explicitly. Never silently invoke `sudo` or require a daemon.
- Must work in SSH sessions and standard terminals without mouse, graphical UI, or a Docker socket.
- All features described as MVP below are read-only. Policy editing, enforcement changes, label mutation, domain transitions, and attempts to impersonate system daemons are **out of scope**.

## 3. SELinux semantics — rules all implementations must respect

These constraints are more important than UI polish. Incorrect SELinux explanations are release-blocking bugs.

### 3.1 Four-part security contexts

A context generally has `SELinuxUser:Role:Type:Range`, e.g.:

```text
system_u:system_r:NetworkManager_t:s0
unconfined_u:unconfined_r:container_runtime_t:s0-s0:c0.c1023
system_u:object_r:var_t:s0
```

- Parse only the **first three `:` separators**; the MLS/MCS component may contain additional colons.
- For a process, Type is the **domain**; for a labeled file, Type is the **object Type**.
- SELinux User is not the UNIX UID. `root` and a `system_r` role do not automatically determine access.
- `object_r` on a file is normal; do not try to match the process and target's SELinux User or Role as if equal values were an access rule.
- Explain that Type Enforcement (TE) is the main focus for ordinary targeted-policy diagnostics, but other SELinux mechanisms can matter.

### 3.2 Type Attributes are sets, not inheritance

- A Type may belong to **several Attributes**.
- An Attribute may contain **several Types**.
- This is a **many-to-many membership relation**, **not a class hierarchy** and not a chain such as `file_type -> non_security_file_type -> some_type`.
- `Type -> Attribute` edges mean **member of**; `Attribute -> Type` edges mean **contains** (the inverse view of the same membership).
- Attributes can appear in `allow` rules as their source or target. A rule can therefore match a concrete Type even when the rule never spells that Type's name.
- The Reference Policy `files_type(T)` macro may assign both `file_type` and `non_security_file_type` to `T`; this is **two memberships**, not inheritance. Validate each membership from the actual policy rather than inferring it from a macro name.
- `file_type` is a Type Attribute; `file` is an object class; `read` is a permission. **They are different node kinds.**

### 3.3 Allow-rule matching

Illustrative policy rule (NOT assumed present):

```selinux
allow files_unconfined_type file_type:file { getattr open read write };
```

For a particular source and target, explain all required match components:

```text
Source concrete Type --[member of]--> Source Attribute
                                              \
                                               matches rule source
                                                [ allow ... :file read ]
                                               matches rule target
                                              /
Target concrete Type --[member of]--> Target Attribute
```

If a rule names a concrete Type directly, show `direct Type match` rather than inventing an Attribute hop. If either side matches via multiple memberships or there are multiple rules, show **multiple independently verifiable evidence paths**. Bound large cross products, with totals and expansion available on demand.

`sesearch` normally matches source and target **indirectly through Type Attributes**; be careful with `-ds`/`-dt` (the options change indirect-matching behavior). Preserve the actual original rule's source and target symbols instead of replacing them with the selected concrete Types.

A rule matching only `map` **does not imply** `open`, `read`, or `write`. Likewise, `getattr` is not `read`; `dir:search` is different from `file:read`; file creation may require distinct directory and file permissions. Do not label a domain "allowed to read the file" based on an unrelated permission.

### 3.4 Never confuse TE with observed access

- **DAC and SELinux are independent layers.** SELinux does not override POSIX permissions; both can deny access. Privileged UNIX users may bypass aspects of DAC but not automatically SELinux.
- A successful `sesearch` match is a **policy finding**, **not proof of a successful `open(2)`**.
- No rule for a specified permission means **"No matching TE allow rule was found for this query"**, not an unconditional assertion about all possible access paths.
- Evaluate/indicate relevant Boolean conditions and whether the selected rule is effective; preserve unknown when the evaluation cannot be trusted or live Boolean state is unavailable.
- A printed conditional rule `[ some_boolean ]:True` needs explicit Boolean/branch handling; do not turn `True` in arbitrary tool output into a global authorization verdict.
- Global Enforcing/Permissive and **domain-specific permissive** are separate. A Type may be permissive through a built-in policy definition; don't rely solely on `semanage permissive -l` output or an absent local override.
- A process name such as `NetworkManager` **is not** its Type. `NetworkManager_ssh_t` and `NetworkManager_t` are distinct Types. `chronyc_t` and `chronyd_t` are also distinct.
- A failure to run `/bin/sh` via `runcon -t SERVICE_DOMAIN` is **not** proof that the service domain cannot read an unrelated path. Never use `runcon` as an MVP "access test".
- Data labeled with an arbitrary custom Type does **not** imply an executing process has that same Type.
- MLS/MCS constraints, neverallow-derived policy design, `constrain`/`mlsconstrain`, type bounds, mount restrictions, capabilities, Linux namespaces, seccomp, UID/GID mappings, ACLs, existing open FDs, and other LSMs may affect behavior. Claim only checks actually performed.

## 4. User experience: entry points and flows

Design every workflow to work without tutorial-specific names. The user must be able to start with any of these entry points.

### 4.1 Running processes (primary entry)

1. Open `selinspect`, see live processes with PID, Linux owner, executable/process name, SELinux domain, and (if available) service metadata.
2. Search by PID / name / UNIX user / domain; group by Type to avoid repetitive kernel threads.
3. Select process -> see its raw context, parsed User/Role/Type/Range, Type Attributes, and permissive/enforcement status.
4. Open **Attributes** to inspect membership sets, then **Rules** or **Compare** to select a target Type or file path.
5. Inspect evidence explaining direct vs Attribute-mediated `allow` matches and which requested permissions they cover.

### 4.2 Target path (independent entry)

1. Enter an absolute path such as `/etc/passwd`, `/var/log`, or any user-chosen path.
2. Read its **actual** SELinux label, file kind, numeric UID/GID, mode, and if possible parent-directory labels. Preserve symlink identity unless explicitly following a target.
3. Select object class appropriate for the file kind (`file`, `dir`, `lnk_file`, `sock_file`, etc.).
4. Select an active process Type or manually enter an existing source Type; choose a permission and inspect matching rules.
5. In **Who can access?**, search inbound rules and optionally filter results down to Types observed in live processes. Do not treat "matches a rule" as "can read this entire path".

### 4.3 Type / Attribute browser (no process or path required)

1. Search policy Types and Attributes globally, even if no processes of that Type are currently running.
2. Selecting a Type displays aliases, every Attribute membership, and rules involving it.
3. Selecting an Attribute displays all member Types, with reverse navigation and counts.
4. Open a relation to see concrete policy evidence; e.g. selected Type -> membership -> rule -> target membership -> target Type.
5. Permit comparing **any two Types present in the current policy** with a chosen class/permission, without a filesystem path.

### 4.4 Reverse access discovery / Type comparison

Given target Type `T`, query policy sources for `class` and `permission`, expand source Attribute memberships **lazily**, and offer views:

- **Rule view:** unique original `allow` statements with source expression, Boolean conditions, and permissions.
- **Domain view:** concrete source Types whose Attribute membership can match those rules (not necessarily running).
- **Active process view:** intersection of that Type set with domains observed in `/proc`; list matching PIDs, and note snapshot time.

Optionally compare the matches for two target Types (e.g. a generic `var_t` versus another Type the user selects). Report differences **relative to the selected permission/class and loaded policy**; do not claim the new Type "blocks all root daemons".

## 5. Detailed MVP features

### 5.1 Process inventory and context details

- Prefer reading `/proc` directly (`/proc/<pid>/attr/current`, `status`, `stat`, `comm`, optionally redacted `cmdline`). No use of `ps -auxZ` as a required backend.
- Include PID, PPID, Linux UID/GID, process name, actual SELinux context, parsed domain, and process start identity.
- Preserve selection by PID + `/proc/<pid>/stat` start-time ticks to protect against PID reuse. Handle disappearing PIDs and protected `/proc` entries.
- Group by domain; show count and allow expanding members. Support search, type filter, UID filter, and refresh.
- Hide/truncate potentially sensitive command line arguments by default. Never read `/proc/<pid>/environ`.
- Show context unavailable / kernel thread / no SELinux context as explicit states, not fake Types.

### 5.2 Type/Attribute relationship explorer

- `Type -> all assigned Attributes`; `Attribute -> all member Types`.
- Show aliases and accurate membership counts; handle empty sets, names with aliases, and large attributes such as `domain` and `file_type`.
- Support search and interactive expansion on either side; do not render enormous graphs at once.
- Explicit legend: **Type / Attribute / object class / permission / allow-rule / conditional**.
- Render a **bipartite many-to-many relationship visualization** when browsing memberships; ASCII tree projection is only one presentation of this graph.
- Never imply a Type can contain another Type by inheritance simply because of shared membership.

### 5.3 Policy rules and permission filtering

- Source Type is the selected process's real domain or any user-selected Type.
- Target Type is from a selected path or any user-selected Type.
- Class is chosen explicitly; default based on file kind when known, otherwise start with `file` but show the choice.
- Permission is selectable and class-sensitive (`file:open`, `file:read`, `file:write`, `dir:search`, `dir:read`, etc.).
- Search `allow` rules and show the **original policy statement**, source and target symbol kinds, membership proof for both sides, conditional expression/branch, and separate raw SETools output.
- Provide `All matching rules`, `Matched requested permission`, and `Other permissions on these rules` views. A rule that doesn't include the requested permission must not be marked as satisfying it.
- Show conditional rules with relevant Boolean state if verified. Mark disabled branches separately from unconditional or enabled matches.
- Offer a read-only copyable equivalent `sesearch` command; never execute user input via a shell.
- Include a **No match** state and uncertainty annotation, not a red "Access denied" claim.

### 5.4 Real path, DAC and enforcement context

- For existing paths, retrieve labels without modifying them (e.g. `lgetxattr("security.selinux")` using a suitable Linux API). Respect `lstat`/`stat` and symlink semantics.
- Show file kind, owner, mode and parent components if accessible. Report `EACCES` vs missing path vs unsupported filesystem distinctively.
- Show **actual label** separately from optional **default file-context mapping**; do not assume `semanage fcontext -l` reflects actual on-disk labels.
- Explain when `file` queries cannot establish `dir` traversal or file creation outcomes. DAC result remains **not fully evaluated** unless explicitly checked; supplementary groups, ACLs, capabilities, namespace mappings, and mount state matter.
- Read global enforcing state via `/sys/fs/selinux/enforce` if available. Read built-in permissive Types from the loaded policy where supported (`seinfo --permissive`), not merely local permissive additions.
- List policy source + capture timestamp; flag stale process snapshots/changed policy when possible.

### 5.5 UI and graph navigation

**Preferred UI:** keyboard-first two-column or three-panel TUI, responsive to terminal widths. Use text-rendered directed edges, not misleading nested inheritance.

```text
┌─ Sources ──────────────────────┬─ Selected Type / Attributes ─────────────┐
│ [Processes] [Types] [Paths]    │ source_t (PID 452, Linux UID 0)          │
│ / filter                       │ user:role:source_t:s0                    │
│ > source_t  PID 452            │ Attrs: domain, attribute_A, ...          │
│   other_t   PID 891            │ Object class: file  Permission: read    │
├───────────────────────────────┴──────────────────────────────────────────┤
│ Target: target_t                 Policy: local, loaded, Enforcing       │
│                                                                         │
│ source_t ──[member of]──> attribute_A                                  │
│                              │                                          │
│                              └── source side matches ─┐                │
│    allow attribute_A attribute_B:file { read open };  │                │
│                              ┌── target side matches ─┘                │
│ target_t ──[member of]──> attribute_B                                  │
│                                                                         │
│ TE: rule matched  Boolean: unconditional  DAC: not evaluated           │
│ [Raw rule] [All evidence] [Show attribute members] [Help]              │
└─────────────────────────────────────────────────────────────────────────┘
```

This UI is illustrative only; `source_t`, `target_t`, `attribute_A` and `attribute_B` are **placeholders**, never bundled policy assumptions.

- Views: `Processes`, `Types`, `Attributes`, `Paths`, `Rules`, `Explain`, `Reverse lookup`, `Compare`, `Help`.
- Keyboard: `j/k` and arrows, `/` filter, `Tab` switch pane, `Enter` expand, `Esc` back, `r` refresh, `?` help, `q` quit; document all.
- Color optional; text/shape/legend must convey meaning in monochrome and over SSH. Support widths starting around 80 columns, scrolling, resizing, pagination and canceled queries.
- Node selection must explain each edge: `member of`, `matched rule source`, `matched rule target`, `grants permission` (TE-only), `conditional on`.
- Large matches: show count, limit default expansion (e.g. 50 members / 25 rules / 10 evidence paths) and allow further pages/search; never eagerly materialize every combination of massive Attribute sets.

## 6. Backend: Go and SETools

### 6.1 Tooling

- Go modules; portable, testable core packages. Linux-specific `/proc` and xattr adapters isolated behind interfaces.
- TUI: **Bubble Tea v2** (`charm.land/bubbletea/v2`), **Bubbles v2**, **Lip Gloss v2**. Pin compatible versions after checking actual `go version` and each dependency's `go.mod`; do not mix v1/v2 imports or assume the distro supplies the latest Go.
- SELinux policy read backend: **`setools-console`**, via `seinfo` and `sesearch`, with `exec.CommandContext` and strict time/output bounds. No Python runtime or CGO needed by the Go binary itself (SETools commands may have their own runtime dependencies).
- Detect whether tools are installed; show guidance for Rocky/RHEL: `sudo dnf install setools-console` (printed advice only; never install from the app).
- Optionally support a user-supplied **binary policy file path** (`--policy FILE`) in an offline policy-explorer mode. Distinguish that file's rules from **live process** labels; never silently equate policy file with currently enforced policy.

### 6.2 SETools commands to support

The exact installed version's help/man output takes precedence if versions vary.

```bash
# Concrete Type and assigned Attributes
seinfo -t TYPE -x

# Attribute and member Types
seinfo -a ATTRIBUTE -x

# List/search Types and Attributes (pagination implemented in Go)
seinfo -t
seinfo -a

# Conditional TE allow query, indirect Attribute matching by default
sesearch -A -s SOURCE_TYPE -t TARGET_TYPE -c file -p read

# Directory traversal query (different object class)
sesearch -A -s SOURCE_TYPE -t TARGET_TYPE -c dir -p search

# Reverse lookup of rules which target a Type
sesearch -A -t TARGET_TYPE -c file -p read

# Built-in policy permissive Types if available
seinfo --permissive
```

Use `--help` capability checks before relying on optional flags. `sesearch -A` may include `allowxperm` as well as ordinary `allow`; **filter and classify rule kinds carefully**. Capture errors, empty results, and policy-access failures distinctly.

For reverse lookup, attribute-valued sources in rules must be expanded using **`seinfo -a ATTR -x`** if the UI needs concrete candidate Types. Always distinguish original source symbol from expanded members, and limit output.

### 6.3 Safe command execution and caching

- Call binaries with positional argument arrays; **never** invoke `sh -c` with query values. Validate SELinux symbol names, class names and permissions; no implicit regular-expression search.
- Use `LC_ALL=C` for parsed tool output. Store original stdout/stderr and command arguments for diagnostic/reproducibility views.
- Bound stdout/stderr bytes and runtime; expose canceled/time-out/parse-error states instead of showing partial results as complete.
- No `sesearch` per PID on initial scan. Process list comes from `/proc`; policy calls are lazy per distinct Type/query.
- Cache `seinfo` data per Type/Attribute, and rule matches by `(policy identity, source, target, class, permissions, Boolean state where relevant)`.
- Invalidate on policy change, switch to offline policy, or Boolean-state change; separate compiled policy snapshot from live boolean values.
- Never read secrets to provide a demonstration. Handle access denied to `/proc` or xattrs without privilege escalation.

## 7. Data model and interfaces

Model **meaning**, not just parsed lines:

```go
type SecurityContext struct {
    User, Role, Type, Range string
}

type Process struct {
    PID, PPID int
    StartTimeTicks uint64
    UID, GID uint32
    Name string
    Context SecurityContext
    ContextKnown bool
}

type TypeInfo struct {
    Name string
    Aliases []string
    Attributes []string     // Many memberships; not parents
    IsPermissive *bool      // nil = unknown
}

type AttributeInfo struct {
    Name string
    MemberTypes []string    // Many members; not children/subclasses
}

type Rule struct {
    Kind string             // allow, allowxperm, ...
    SourceSymbol string     // Type OR Attribute as stated in policy
    TargetSymbol string     // Type OR Attribute as stated in policy
    Class string
    Permissions []string
    Condition string
    ConditionState string   // unconditional | enabled | disabled | unknown
    Raw string
}

type Evidence struct {
    SourceConcreteType, TargetConcreteType string
    SourceMatch string      // direct | attribute
    TargetMatch string      // direct | attribute
    SourceAttribute, TargetAttribute string
    Rule Rule
    RequestedPermissions []string
    MatchedPermissions []string
    Verified bool          // policy-symbol / membership proof verified
}

type AccessAssessment struct {
    TEPermissionState string  // matched-enabled | matched-disabled | no-match | unknown
    EnforcementState string  // enforcing | domain-permissive | global-permissive | disabled | unknown
    DACState string          // metadata-only | unknown (never overclaim)
    Limitations []string
}
```

Implement these as separated interfaces, names flexible:

```go
type ProcessSource interface {
    List(ctx context.Context) ([]Process, error)
}

type PolicyBackend interface {
    Type(ctx context.Context, name string) (TypeInfo, error)
    Attribute(ctx context.Context, name string) (AttributeInfo, error)
    Types(ctx context.Context) ([]string, error)
    Attributes(ctx context.Context) ([]string, error)
    AllowRules(ctx context.Context, query RuleQuery) ([]Rule, error)
    PermissiveTypes(ctx context.Context) ([]string, error)
}
```

- `RuleQuery` should support optional concrete source and target, class, permission(s), and policy snapshot reference.
- The graph has distinct node kinds: `process`, `type`, `attribute`, `object-class`, `permission`, `rule`, `boolean`. Never conflate membership and a TE allow edge.
- Build traceable, reproducible evidence paths only when the actual symbol membership is confirmed; classify partial/unsupported parses explicitly.
- Keep UI rendering, policy evaluation, process inventory and graph construction independent and fixture-testable.

Suggested layout:

```text
cmd/selinspect/main.go
internal/procfs/{scan,context,identity}.go
internal/selinux/{context,status,filesystem}.go
internal/policy/{backend,setools,parse,types,query}.go
internal/analysis/{evidence,reverse,compare,assessment}.go
internal/graph/{nodes,edges,build}.go
internal/tui/{app,processes,types,attributes,paths,rules,explain,compare,help}.go
internal/export/{json,dot}.go             # later
internal/fixtures/                      # sanitized offline policy outputs
testdata/
README.md
AGENTS.md
```

## 8. CLI UX (design target; ship incrementally)

```bash
selinspect                       # live, process-first TUI
selinspect --pid 855             # highlight an existing PID, if present
selinspect --type var_t          # open an installed Type even with no processes
selinspect --path /etc/passwd    # open target file path
selinspect --source SOURCE_TYPE --target TARGET_TYPE --class file --permission read
selinspect --policy /path/to/policy.bin --type EXISTING_TYPE   # offline policy mode
selinspect --no-color
```

- A `--type`, `--source`, or `--target` value **MUST be resolved against the actual policy**; show `Type not found` for absent symbols, with searchable alternatives. Never autogenerate them.
- If flags describe mutually exclusive modes, give clear help; do not let stale process state leak into offline policy analysis.
- MVP can be TUI-only; non-interactive `--explain`/`--format json` are optional later. Never advertise unimplemented flags.

## 9. Learning-oriented explanations and status vocabulary

User-facing UI should make the investigation from the motivating article reproducible in any environment.

- **`Rule matched: source via Attribute X; target via Attribute Y`** — evidence for indirect matching.
- **`Direct match: rule names source_t explicitly`** — no invented attribute hop.
- **`No TE allow rule found for file:read in this policy`** — scoped finding, not global denial.
- **`Only file:map matched; read/open not established`** — permissions are not equivalent.
- **`Conditional rule; Boolean inactive / condition not verified`** — not unconditional permission.
- **`SELinux policy permits requested TE operation; actual path access not evaluated`** — positive bounded claim.
- **`DAC metadata: mode 0700, owner UID N; no complete DAC decision`** — namespace and group caveats.
- **`Process domain known, but policy backend unavailable`** — graceful degradation.

Use concise, contextual help to explain User/Role/Type, object class, Attribute membership, Booleans, per-domain permissive, and why root is still constrained. Default copy can be Japanese; support English in architecture and documentation. Do not flood the terminal with introductory text.

## 10. Implementation milestones

### Phase 0 — Inspect repo, bootstrap, fixture foundations

- Respect existing repository contents and git state; do not overwrite user code.
- Check `go version` and available `seinfo`/`sesearch` versions; document required toolchain compatibility.
- Establish interfaces, a typed context parser, `setools-console` capability checks, fixture-based tests and a README.
- Implement `--help`, `--version`, robust errors and no-color mode.

### Phase 1 — Live process and standalone Type navigation

- Build TUI with running process inventory and Type search as independent entry points.
- Show actual contexts and correct parsed domains; support filtering, refresh, PID reuse and narrow terminals.
- **Acceptance:** Type browser works when user-created policy modules and Docker are absent.

### Phase 2 — Many-to-many membership explorer

- Add bidirectional `seinfo`-backed Type/Attribute browser.
- Build non-hierarchical graph model and collapsible textual views; show Attribute membership counts.
- **Acceptance:** multiple Types sharing an Attribute and one Type in multiple Attributes are both clearly visible.

### Phase 3 — TE rule explanation

- Add generic source/target Type + class + permission query UI and exact rule evidence.
- Explain direct vs source/target/both Attribute matches; conditional rule states; no match, `map` vs `read`, file vs dir permissions.
- Add read-only copyable command; no feature may depend on custom policy names.

### Phase 4 — Path inspection and reverse discovery

- Add `--path`/path picker, actual labels, DAC metadata, symlink/parent-directory notes.
- Add target-first reverse lookup with `rule`, `candidate domain`, and `running process` facets; pagination/limits.
- Compare two selected existing Types without modifying labels or installed policy.

### Phase 5 — Quality, packaging and optional exports

- Polish accessibility, SSH/monochrome, error states and terminal resizing.
- Add optional JSON/DOT export of the **currently filtered** evidence graph (not an indiscriminate dump of the entire policy).
- Build binaries/packaging and document SELinux-independent fixture tests versus live integration tests.

**Finish each phase end-to-end:** working feature + tests + README update + targeted commit. Avoid unfinished placeholder buttons or unsupported promises.

## 11. Tests and acceptance criteria

### Required fixture tests (no SELinux host required)

1. **Context parser:** process/file contexts, long MLS/MCS range, malformed labels, missing labels.
2. **Process scan:** vanishing PID, permission denial, kernel thread, PID reuse, grouping, Unicode names.
3. **Type/Attribute many-to-many:** fixture `alpha_t` belongs to `attr_one` and `attr_two`; `beta_t` belongs to both; `gamma_t` belongs to `attr_two`. Both directions must agree. These fixture symbols are fictional and **never expected on a real host**.
4. **Rule match:** direct source+direct target; indirect source only; indirect target only; both sides indirect; multiple valid evidence paths; an attribute member not covered by the queried rule.
5. **Permission/class:** `file:map` not `file:read`; `file:read` not `file:open`; `dir:search` independent; no-match is a scoped result.
6. **Conditional state:** unconditional, Boolean true/false, complex expression, unknown/live-state unavailable, rule branch not effective.
7. **SETtools parsers:** empty output, Type aliases, long Attribute list, expected and unexpected output, command error, canceled query, output cap, optional `allowxperm`.
8. **Path inspector:** normal file, directory, inaccessible path, symlink, UID namespace-looking ownership, absent label.
9. **UI:** multiple views, keyboard nav, no result, narrow terminal, resize, screen readers/monochrome, huge response pagination.
10. **Security:** shell metacharacters in path/type rejected or treated as inert argv data, never shell-executed; no secret env reads; no mutation commands.

### Live integration: stock Rocky Linux / RHEL 10

Do not require `compose_data_t` or Docker. Discover **existing Types first**:

```bash
getenforce
seinfo -t
seinfo -a
seinfo --permissive
ps -eZ -o label=,pid=,comm=
```

Pick any Type returned by `seinfo -t` and inspect it; then choose one of its assigned Attributes (if any) and confirm it appears in the Attribute's reverse member list. Pick an actual process Type from `/proc` and any installed target Type, and compare `sesearch` raw output with rendered evidence.

Suggested *examples* to attempt **only if installed**: `NetworkManager_t`, `var_t`, `etc_t`, `syslogd_t`. None is a mandatory fixture or a required installed Type.

Optional extra integration when the machine happens to have custom types or rootless containers:

- Choose a custom Type such as `compose_data_t` **only if it exists**.
- Choose a process that is actually running in `container_runtime_t` **only if it exists**.
- If `container_runtime_t` belongs to `files_unconfined_type` and target belongs to `file_type`, explain the matching broad allow rule **only when that rule is actually present**.
- A container in `container_runtime_t` instead of `container_t` is a *potential investigation item*, not an assumption about all rootless Docker installs.

### Quality gates

```bash
gofmt -w <changed-Go-files>
go vet ./...
go test ./...
go test -race ./...  # when feasible
go build ./cmd/selinspect
```

### Definition of Done — MVP

- A normal user can inspect a currently running process's true SELinux domain.
- A user can find and inspect any **installed** Type and Attribute even when no relevant process or path exists.
- Both directions of Type/Attribute membership can be navigated; UI calls it many-to-many, not hierarchy.
- User can select arbitrary existing source/target Types, class and permission; see original matching rules and the precise direct/Attribute-mediated evidence.
- No matching rule, conditional-disabled rule and an insufficient permission are presented as distinct outcomes.
- File path inspector reflects actual labels and DAC metadata without mutating the host.
- Target-first reverse lookup links source rule symbols, expanded Types and running processes without conflating them.
- Limited/degraded operation works if SELinux is disabled or binaries are missing; no crash or false allow/deny claims.
- No Docker, `compose_data_t`, `/var/compose`, custom policies or root privileges are prerequisites.
- Tests, vet and build pass, and README documents behavior/limitations.

## 12. Work rules for coding agents

1. Inspect current repository and git state before modifying anything.
2. Keep Go code idiomatic, small, testable and independent of TUI where feasible; do not add a background service.
3. Make frequent, meaningful Git commits. **Before each commit**, run `gofmt`, `go vet ./...`, `go test ./...`; run race tests as practical. Do not commit broken code.
4. Use the installed tool's `--help` and actual policy to resolve version-specific assumptions. Prefer cited primary docs over guessed semantics.
5. `exec.CommandContext` with validated argv only; **no shell interpolation**, no silent elevation, no policy mutations.
6. Never put secrets, private file contents, raw real-process command lines, environment variables, credentials or unsanitized server dumps in fixtures, screenshots, logs, telemetry or repository commits.
7. Report the exact tests actually run. If live SELinux validation is not possible, explain that limitation and rely on sanitized recorded fixtures.
8. Don't encode the motivating tutorial's names as defaults or mandatory test cases; add them only as opt-in examples and skip when absent.
9. Maintain truthful, bounded conclusions about SELinux TE versus DAC/MLS/MCS/constraints and real system-call outcomes.
10. Update README/CLI help along with each new feature and provide keyboard discoverability.

## 13. References (verify against installed versions)

- Red Hat Enterprise Linux 10 SELinux documentation: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/
- RHEL 10 custom policy: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/writing-a-custom-selinux-policy
- SELinux Reference Policy and attributes: https://github.com/SELinuxProject/selinux-notebook/blob/main/src/type_statements.md
- SETools `seinfo` (source): https://github.com/SELinuxProject/setools/blob/main/seinfo
- SETools `sesearch` (source; `-ds`/`-dt` indirect behavior): https://github.com/SELinuxProject/setools/blob/main/sesearch
- Bubble Tea v2: https://github.com/charmbracelet/bubbletea
- Bubbles v2 upgrade guide: https://github.com/charmbracelet/bubbles/blob/main/UPGRADE_GUIDE_V2.md
- Docker rootless mode (optional context, not a dependency): https://docs.docker.com/engine/security/rootless/

The binary running on the user's system, the currently loaded SELinux policy and its active Booleans are authoritative for that system. This document defines **behavior and safety requirements**, not guaranteed permissions on any particular installation.
