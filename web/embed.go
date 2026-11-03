package web

import _ "embed"

// Viewer is the fixed recipient page. Its bytes do not depend on the id.
//
//go:embed viewer.html
var Viewer []byte

// Admin is the administrator page. The placeholder __PUBLIC_ORIGIN__ is
// replaced at startup. The script does not contain the origin.
//
//go:embed admin.html
var Admin []byte
