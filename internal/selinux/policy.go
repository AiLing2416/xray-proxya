package selinux

import _ "embed"

// PolicySource is compiled locally by `xray-proxya doctor selinux`. Keeping
// it in the binary makes deployment deterministic while still letting Fedora
// compile it against its installed SELinux reference policy.
//
//go:embed policy/xray_proxya.te
var PolicySource string
