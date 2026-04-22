// Copyright 2026 Miek Gieben and the Golang pkcs11 Contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX-License-Identifier: BSD-3-Clause

//go:build release
// +build release

package pkcs11

import "fmt"

// Release is current version of the pkcs11 library.
var Release = R{1, 1, 0}

// R holds the version of this library.
type R struct {
	Major, Minor, Patch int
}

func (r R) String() string {
	return fmt.Sprintf("%d.%d.%d", r.Major, r.Minor, r.Patch)
}
