package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

func TestAuditConfigPortsBothPresetsSharePort(t *testing.T) {
	// Find a free TCP+UDP port
	ports, err := utils.GetFreePorts(1)
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	sharedPort := ports[0]

	apiPort, err := utils.GetFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free API port: %v", err)
	}

	cfg := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: sharedPort},
			{Mode: config.ModeVLESSReality, Enabled: false, Port: 8443},
			{Mode: config.ModeVLESSXHTTP, Enabled: false, Port: 8080},
			{Mode: config.ModeVMessWS, Enabled: false, Port: 8081},
			{Mode: config.ModeShadowsocksTCP, Enabled: false, Port: 8082},
			{Mode: config.ModeHysteria2, Enabled: true, Port: sharedPort},
		},
	}

	changed, err := auditConfigPorts(cfg, false)
	if err != nil {
		t.Fatalf("expected auditConfigPorts to succeed for both presets sharing port, got: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false when ports are free, got changed=true")
	}
	if cfg.Presets[0].Port != sharedPort || cfg.Presets[5].Port != sharedPort {
		t.Fatalf("preset ports drifted unexpectedly: vision=%d, hysteria2=%d, want=%d",
			cfg.Presets[0].Port, cfg.Presets[5].Port, sharedPort)
	}
}

func TestAuditConfigPortsTCPOccupiedDistinguishesProtocols(t *testing.T) {
	ports, err := utils.GetFreePorts(1)
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	targetPort := ports[0]

	// Occupy TCP port only
	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to listen on TCP port %d: %v", targetPort, err)
	}
	defer tcpLn.Close()

	apiPort, err := utils.GetFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free API port: %v", err)
	}

	// 1. Only Preset 6 (hysteria2) enabled: TCP occupied should NOT block hysteria2
	cfgHy2Only := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: false, Port: targetPort},
			{Mode: config.ModeHysteria2, Enabled: true, Port: targetPort},
		},
	}

	changed, err := auditConfigPorts(cfgHy2Only, false)
	if err != nil {
		t.Fatalf("hysteria2 should not fail when only TCP port is occupied: %v", err)
	}
	if changed {
		t.Fatalf("hysteria2 should not drift when its UDP port is free")
	}
	if cfgHy2Only.Presets[1].Port != targetPort {
		t.Fatalf("hysteria2 port changed to %d, want %d", cfgHy2Only.Presets[1].Port, targetPort)
	}

	// 2. Preset 1 (TCP) enabled without --audit: should fail
	cfgVisionOnly := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: targetPort},
			{Mode: config.ModeHysteria2, Enabled: false, Port: targetPort},
		},
	}

	_, err = auditConfigPorts(cfgVisionOnly, false)
	if err == nil {
		t.Fatalf("expected error for TCP preset when TCP port is occupied, got nil")
	}
	if !strings.Contains(err.Error(), "is occupied") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 3. Preset 1 (TCP) enabled with --audit: should drift to new port
	changed, err = auditConfigPorts(cfgVisionOnly, true)
	if err != nil {
		t.Fatalf("expected audit to succeed with runAudit=true: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true when TCP port was occupied")
	}
	if cfgVisionOnly.Presets[0].Port == targetPort {
		t.Fatalf("expected vision port to drift away from occupied port %d", targetPort)
	}
}

func TestAuditConfigPortsUDPOccupiedDistinguishesProtocols(t *testing.T) {
	ports, err := utils.GetFreePorts(1)
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	targetPort := ports[0]

	// Occupy UDP port only
	udpConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", targetPort))
	if err != nil {
		t.Fatalf("failed to listen on UDP port %d: %v", targetPort, err)
	}
	defer udpConn.Close()

	apiPort, err := utils.GetFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free API port: %v", err)
	}

	// 1. Only Preset 1 (vless-vision-reality-tcp) enabled: UDP occupied should NOT block Vision
	cfgVisionOnly := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: targetPort},
			{Mode: config.ModeHysteria2, Enabled: false, Port: targetPort},
		},
	}

	changed, err := auditConfigPorts(cfgVisionOnly, false)
	if err != nil {
		t.Fatalf("vision preset should not fail when only UDP port is occupied: %v", err)
	}
	if changed {
		t.Fatalf("vision preset should not drift when its TCP port is free")
	}
	if cfgVisionOnly.Presets[0].Port != targetPort {
		t.Fatalf("vision port changed to %d, want %d", cfgVisionOnly.Presets[0].Port, targetPort)
	}

	// 2. Preset 6 (hysteria2) enabled without --audit: should fail
	cfgHy2Only := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: false, Port: targetPort},
			{Mode: config.ModeHysteria2, Enabled: true, Port: targetPort},
		},
	}

	_, err = auditConfigPorts(cfgHy2Only, false)
	if err == nil {
		t.Fatalf("expected error for hysteria2 when UDP port is occupied, got nil")
	}
	if !strings.Contains(err.Error(), "is occupied") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 3. Preset 6 (hysteria2) enabled with --audit: should drift to new free UDP port
	changed, err = auditConfigPorts(cfgHy2Only, true)
	if err != nil {
		t.Fatalf("expected audit to succeed with runAudit=true for hysteria2: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true when UDP port was occupied")
	}
	newUDPPort := cfgHy2Only.Presets[1].Port
	if newUDPPort == targetPort {
		t.Fatalf("expected hysteria2 port to drift away from occupied port %d", targetPort)
	}
	if !utils.IsUDPPortFree(newUDPPort) {
		t.Fatalf("hysteria2 drifted to port %d which is not free on UDP", newUDPPort)
	}
}

func TestAuditConfigPortsTwoTCPPresetsSharePortCollides(t *testing.T) {
	ports, err := utils.GetFreePorts(1)
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	sharedPort := ports[0]

	apiPort, err := utils.GetFreePort()
	if err != nil {
		t.Fatalf("failed to allocate free API port: %v", err)
	}

	// Two TCP presets (Vision and Reality) sharing the same port
	cfg := &config.UserConfig{
		Role:       config.RoleServer,
		APIInbound: apiPort,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: sharedPort},
			{Mode: config.ModeVLESSReality, Enabled: true, Port: sharedPort},
		},
	}

	// 1. Without --audit: should detect collision and return error
	_, err = auditConfigPorts(cfg, false)
	if err == nil {
		t.Fatalf("expected error when two TCP presets share the same port, got nil")
	}
	if !strings.Contains(err.Error(), "is occupied") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. With --audit: should resolve collision by drifting one preset to an unclaimed port
	changed, err := auditConfigPorts(cfg, true)
	if err != nil {
		t.Fatalf("expected audit to succeed with runAudit=true: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true due to port collision resolution")
	}
	if cfg.Presets[0].Port == cfg.Presets[1].Port {
		t.Fatalf("both TCP presets still have the same port: %d", cfg.Presets[0].Port)
	}
}

