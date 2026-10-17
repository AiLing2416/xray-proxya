package service

import (
	"fmt"
)

// BuildProcdServiceContent generates the /etc/init.d/xray-proxya service script content.
func BuildProcdServiceContent(binPath, workDir, assetDir string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

PROG="%s"
WORKDIR="%s"
ASSETDIR="%s"

start_service() {
	mkdir -p "$WORKDIR" "$ASSETDIR"
	chmod 0700 "$WORKDIR" "$ASSETDIR"

	procd_open_instance "main"
	procd_set_param command "$PROG" run
	procd_set_param env XRAY_LOCATION_ASSET="$ASSETDIR"
	procd_set_param respawn 3600 2 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param user root
	procd_close_instance
}

stop_service() {
	return 0
}

reload_service() {
	restart
}
`, binPath, workDir, assetDir)
}

// BuildProcdSubServiceContent generates the /etc/init.d/xray-proxya-sub service script content.
func BuildProcdSubServiceContent(binPath, workDir, assetDir string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=96
STOP=10
USE_PROCD=1

PROG="%s"
WORKDIR="%s"
ASSETDIR="%s"

start_service() {
	mkdir -p "$WORKDIR" "$ASSETDIR"
	chmod 0700 "$WORKDIR" "$ASSETDIR"
	"$PROG" sub validate || return 1

	procd_open_instance "sub"
	procd_set_param command "$PROG" sub run
	procd_set_param env XRAY_LOCATION_ASSET="$ASSETDIR"
	procd_set_param respawn 3600 2 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param user root
	procd_close_instance
}

stop_service() {
	return 0
}

reload_service() {
	restart
}
`, binPath, workDir, assetDir)
}

// BuildProcdPathdServiceContent generates the /etc/init.d/xray-proxya-pathd service script content.
func BuildProcdPathdServiceContent(pathdBin, pathdConfig string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=97
STOP=10
USE_PROCD=1

PROG="%s"
CONF="%s"

start_service() {
	procd_open_instance "pathd"
	procd_set_param command "$PROG" serve --config "$CONF"
	procd_set_param respawn 3600 2 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param user root
	procd_close_instance
}

stop_service() {
	return 0
}

reload_service() {
	restart
}
`, pathdBin, pathdConfig)
}
