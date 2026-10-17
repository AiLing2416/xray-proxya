package service

import (
	"fmt"
)

// BuildOpenRCServiceContent generates the /etc/init.d/xray-proxya service script content.
func BuildOpenRCServiceContent(binPath, workDir, assetDir string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run

name="Xray-Proxya Service"
description="Xray-Proxya Core Service"

command="%s"
command_args="run"
directory="%s"

pidfile="/run/${RC_SVCNAME}.pid"
supervisor="supervise-daemon"
respawn_delay=2
respawn_max=5

output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.err"

export XRAY_LOCATION_ASSET="%s"

depend() {
	need net
	after firewall
}

start_pre() {
	checkpath -d -m 0755 /var/log
	checkpath -d -m 0700 -o root:root "%s"
	checkpath -d -m 0700 -o root:root "%s"
}
`, binPath, workDir, assetDir, workDir, assetDir)
}

// BuildOpenRCSubServiceContent generates the /etc/init.d/xray-proxya-sub service script content.
func BuildOpenRCSubServiceContent(binPath, workDir, assetDir string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run

name="Xray-Proxya Subscription Server"
description="Xray-Proxya Subscription Service"

command="%s"
command_args="sub run"
directory="%s"

pidfile="/run/${RC_SVCNAME}.pid"
supervisor="supervise-daemon"
respawn_delay=2
respawn_max=5

output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.err"

export XRAY_LOCATION_ASSET="%s"

depend() {
	need net
	after firewall
}

start_pre() {
	checkpath -d -m 0755 /var/log
	checkpath -d -m 0700 -o root:root "%s"
	checkpath -d -m 0700 -o root:root "%s"
	"%s" sub validate
}
`, binPath, workDir, assetDir, workDir, assetDir, binPath)
}

// BuildOpenRCPathdServiceContent generates the /etc/init.d/xray-proxya-pathd service script content.
func BuildOpenRCPathdServiceContent(pathdBin, pathdConfig string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run

name="Xray-Proxya PathLink Agent"
description="PathLink ICMP latency & health daemon"

command="%s"
command_args="serve --config %s"

pidfile="/run/${RC_SVCNAME}.pid"
supervisor="supervise-daemon"
respawn_delay=2
respawn_max=5

output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.err"

depend() {
	need net
	after firewall
}

start_pre() {
	checkpath -d -m 0755 /var/log
}
`, pathdBin, pathdConfig)
}
