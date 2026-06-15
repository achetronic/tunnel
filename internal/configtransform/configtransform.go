// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package configtransform

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"sigs.k8s.io/yaml"
)

// Apply postprocesses a JSON config document by evaluating a set of CEL transform
// rules against it. Each rule writes the result of its CEL expression into the
// config at its path; later rules observe earlier rules' writes. A path is a
// dot-separated list of map keys and bracketed list indices (e.g.
// "wireguard.peers[0].allowedIPs[1]"); missing intermediate objects and lists are
// created. The full config is exposed to every expression as the `config`
// variable. It returns the postprocessed JSON. A nil/empty rules document is a
// no-op that returns the config unchanged.
//
// Beyond the CEL standard library and the strings extension (split, trim, ...),
// these helper functions are available:
//
//	getenv(name) string          read an environment variable
//	readFile(path) string        read a file's contents
//	fromJSON(text) dyn           parse a JSON string into a value
//	fromYAML(text) dyn           parse a YAML string into a value
//	cidrHost(cidr, index) string the index-th host address of a CIDR
func Apply(configJSON, rulesYAML []byte) ([]byte, error) {
	if len(rulesYAML) == 0 {
		return configJSON, nil
	}

	var ruleset Ruleset
	if err := yaml.Unmarshal(rulesYAML, &ruleset); err != nil {
		return nil, fmt.Errorf("parse transform rules: %w", err)
	}
	if len(ruleset.Transforms) == 0 {
		return configJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}

	for i, rule := range ruleset.Transforms {
		if rule.Path == "" {
			return nil, fmt.Errorf("transform %d: path is empty", i)
		}
		val, err := evalRule(env, rule.Expr, root)
		if err != nil {
			return nil, fmt.Errorf("transform %d (%s): %w", i, rule.Path, err)
		}
		if err := setByPath(root, rule.Path, val); err != nil {
			return nil, fmt.Errorf("transform %d (%s): %w", i, rule.Path, err)
		}
	}

	out, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return out, nil
}

// newEnv builds the CEL environment: the `config` variable, the strings
// extension, and the custom helper functions.
func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("config", cel.DynType),
		ext.Strings(),
		ext.Bindings(),
		cel.Function("getenv",
			cel.Overload("getenv_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					name, ok := arg.Value().(string)
					if !ok {
						return types.NewErr("getenv: argument must be a string")
					}
					return types.String(os.Getenv(name))
				}))),
		cel.Function("readFile",
			cel.Overload("readFile_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					path, ok := arg.Value().(string)
					if !ok {
						return types.NewErr("readFile: argument must be a string")
					}
					b, err := os.ReadFile(path)
					if err != nil {
						return types.NewErr("readFile: %v", err)
					}
					return types.String(string(b))
				}))),
		cel.Function("fromJSON",
			cel.Overload("fromJSON_string", []*cel.Type{cel.StringType}, cel.DynType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					return parseInto(arg, json.Unmarshal, "fromJSON")
				}))),
		cel.Function("fromYAML",
			cel.Overload("fromYAML_string", []*cel.Type{cel.StringType}, cel.DynType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					return parseInto(arg, func(b []byte, v any) error { return yaml.Unmarshal(b, v) }, "fromYAML")
				}))),
		cel.Function("cidrHost",
			cel.Overload("cidrHost_string_int", []*cel.Type{cel.StringType, cel.IntType}, cel.StringType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					cidr, ok := lhs.Value().(string)
					if !ok {
						return types.NewErr("cidrHost: first argument must be a string")
					}
					idx, ok := rhs.Value().(int64)
					if !ok {
						return types.NewErr("cidrHost: second argument must be an int")
					}
					host, err := cidrHost(cidr, idx)
					if err != nil {
						return types.NewErr("cidrHost: %v", err)
					}
					return types.String(host)
				}))),
	)
}

// parseInto decodes the string argument with the given unmarshaler (JSON or
// YAML) and adapts the result back into a CEL value.
func parseInto(arg ref.Val, unmarshal func([]byte, any) error, fn string) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("%s: argument must be a string", fn)
	}
	var v any
	if err := unmarshal([]byte(s), &v); err != nil {
		return types.NewErr("%s: %v", fn, err)
	}
	return types.DefaultTypeAdapter.NativeToValue(v)
}

// evalRule compiles and evaluates expr with root bound to the `config` variable,
// returning the result as a native Go value.
func evalRule(env *cel.Env, expr string, root map[string]any) (any, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compile: %w", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}
	out, _, err := prg.Eval(map[string]any{"config": root})
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	return out.Value(), nil
}

// accessorKind distinguishes a map key from a list index in a parsed path.
type accessorKind int

const (
	keyAccessor accessorKind = iota
	indexAccessor
)

// accessor is one step of a parsed path: either a map key or a list index.
type accessor struct {
	kind  accessorKind
	key   string
	index int
}

// maxIndex caps list indices so a typo cannot trigger a huge allocation when a
// list is grown to reach the requested position.
const maxIndex = 1 << 16

// setByPath sets val at path in root. A path is a dot-separated list of segments;
// a segment is a map key optionally followed by one or more list indices, e.g.
// "wireguard.interface.address" or "wireguard.peers[0].allowedIPs[1]". Missing
// intermediate objects and lists are created, and lists are grown (with null
// fillers) to reach the requested index, so a path can build new structure. It
// returns an error only when an existing intermediate value has a type that is
// incompatible with the next accessor (for example indexing a string).
func setByPath(root map[string]any, path string, val any) error {
	accs, err := parsePath(path)
	if err != nil {
		return err
	}
	_, err = setPath(root, accs, val)
	return err
}

// parsePath turns a dot/bracket path into a flat list of accessors.
func parsePath(path string) ([]accessor, error) {
	var accs []accessor
	for seg := range strings.SplitSeq(path, ".") {
		name := seg
		brackets := ""
		if i := strings.IndexByte(seg, '['); i >= 0 {
			name = seg[:i]
			brackets = seg[i:]
		}
		if name != "" {
			accs = append(accs, accessor{kind: keyAccessor, key: name})
		} else if brackets == "" {
			return nil, fmt.Errorf("empty path segment in %q", path)
		}
		for brackets != "" {
			if brackets[0] != '[' {
				return nil, fmt.Errorf("invalid index syntax %q in %q", brackets, seg)
			}
			end := strings.IndexByte(brackets, ']')
			if end < 0 {
				return nil, fmt.Errorf("unclosed '[' in %q", seg)
			}
			n, err := strconv.Atoi(brackets[1:end])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid index %q in %q", brackets[1:end], seg)
			}
			if n > maxIndex {
				return nil, fmt.Errorf("index %d exceeds the maximum of %d", n, maxIndex)
			}
			accs = append(accs, accessor{kind: indexAccessor, index: n})
			brackets = brackets[end+1:]
		}
	}
	if len(accs) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	return accs, nil
}

// setPath recursively sets val at accessors within node, creating maps and lists
// as needed, and returns the (possibly newly created or grown) node so the
// caller can reassign it (lists are value types and must be written back).
func setPath(node any, accessors []accessor, val any) (any, error) {
	if len(accessors) == 0 {
		return val, nil
	}
	acc := accessors[0]
	switch acc.kind {
	case keyAccessor:
		m, ok := node.(map[string]any)
		if node == nil {
			m, ok = map[string]any{}, true
		}
		if !ok {
			return nil, fmt.Errorf("path expects an object at key %q but found %T", acc.key, node)
		}
		child, err := setPath(m[acc.key], accessors[1:], val)
		if err != nil {
			return nil, err
		}
		m[acc.key] = child
		return m, nil
	case indexAccessor:
		s, ok := node.([]any)
		if node == nil {
			s, ok = []any{}, true
		}
		if !ok {
			return nil, fmt.Errorf("path expects a list at index %d but found %T", acc.index, node)
		}
		for len(s) <= acc.index {
			s = append(s, nil)
		}
		child, err := setPath(s[acc.index], accessors[1:], val)
		if err != nil {
			return nil, err
		}
		s[acc.index] = child
		return s, nil
	default:
		return nil, fmt.Errorf("unknown path accessor")
	}
}

// cidrHost returns the index-th host address of cidr (index 0 is the network
// address). It mirrors Terraform's cidrhost and works for both IPv4 and IPv6.
func cidrHost(cidr string, index int64) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	base := prefix.Masked().Addr()
	b := base.As16()
	n := new(big.Int).SetBytes(b[:])
	n.Add(n, big.NewInt(index))

	var buf [16]byte
	nb := n.Bytes()
	if len(nb) > 16 {
		return "", fmt.Errorf("index %d overflows the address space", index)
	}
	copy(buf[16-len(nb):], nb)
	out := netip.AddrFrom16(buf)
	if base.Is4() {
		out = out.Unmap()
	}
	return out.String(), nil
}
