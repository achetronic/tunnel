// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package version exposes the operator's build version as a single source of
// truth. The value is stamped at build time with the Go linker:
//
//	-ldflags "-X github.com/achetronic/tunnel/internal/version.Version=<semver>"
//
// It defaults to "dev" for un-stamped local builds. The controller reuses it as
// the tunnelctl release to download onto each VPS, so tunnelctl always travels
// in lockstep with the operator that manages it.
package version

// Version is the operator's semantic version, stamped at build time. "dev" means
// the binary was built without a version (a local go build/run), in which case
// any release-asset download keyed on it will not resolve.
var Version = "dev"
