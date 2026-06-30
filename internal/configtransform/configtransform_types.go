// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package configtransform postprocesses a desired-state config document by
// evaluating declarative CEL expressions against it. The transforms live in a
// separate rules document (YAML or JSON), each one targeting a dot-separated
// path in the config and replacing its value with the result of a CEL
// expression. It lets one shared config render differently per node (for
// example each uplink replica deriving its own tunnel address and private key
// from its environment) without bespoke Go per node.
package configtransform

// Rule is a single declarative transform: evaluate Expr (a CEL expression) and
// write its result into the config at Path.
type Rule struct {
	// Path is the dot-separated location in the config whose value is replaced,
	// e.g. "wireguard.interface.address".
	Path string `json:"path"`
	// Expr is the CEL expression evaluated to produce the new value. The whole
	// config is available as the `config` variable, plus the helper functions
	// documented on Apply.
	Expr string `json:"expr"`
}

// Ruleset is the ordered list of transforms decoded from the rules document.
// Rules are applied in order, so a later rule observes the writes of earlier
// ones.
type Ruleset struct {
	// Transforms is the ordered list of replacements to apply.
	Transforms []Rule `json:"transforms"`
}
