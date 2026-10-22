package policy

import "context"

type TypeInfo struct {
	Name                string
	Aliases, Attributes []string
	IsPermissive        *bool
}
type AttributeInfo struct {
	Name        string
	MemberTypes []string
}
type Rule struct {
	Kind, SourceSymbol, TargetSymbol, Class string
	Permissions                             []string
	Condition, Branch, ConditionState, Raw  string
}
type RuleQuery struct{ Source, Target, Class, Permission string }
type Backend interface {
	Type(context.Context, string) (TypeInfo, error)
	Attribute(context.Context, string) (AttributeInfo, error)
	Types(context.Context) ([]string, error)
	Attributes(context.Context) ([]string, error)
	AllowRules(context.Context, RuleQuery) ([]Rule, error)
	PermissiveTypes(context.Context) ([]string, error)
}
type CommandResult struct {
	Binary         string
	Args           []string
	Stdout, Stderr string
}
