//go:build !slim

package skin

import "embed"

//go:embed assets/*
var assetsFS embed.FS

const Enabled = true
