package selinux

import _ "embed"

// PolicySource is compiled locally by `xray-proxya selinux install`. Keeping
// it in the binary makes deployment deterministic while still letting Fedora
// compile it against its installed SELinux reference policy.
//
//go:embed policy/xray_proxya.te
var PolicySource string
