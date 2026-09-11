package applyops

import (
	"fmt"
	"os"
	"strings"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/service"
	"xray-proxya/internal/xray"
)

// StaticValidationStep validates configuration syntax, REALITY target reachability, and certificates.
type StaticValidationStep struct{}

func (s *StaticValidationStep) Name() string {
	return "Static Validation"
}

func (s *StaticValidationStep) ShouldRun(ctx *ApplyContext) bool {
	return !ctx.Options.Force && (ctx.Options.Full || ctx.Impact.XrayConfigChanged)
}

func (s *StaticValidationStep) Run(ctx *ApplyContext) error {
	testOverrides := map[string]int{"gateway-tun-disabled": 1}
	ctx.AppendLine("🔍 Stage 1: Static Validation...")

	cfg := ctx.StagingCfg
	activeCfg := ctx.ActiveCfg

	// Invariant and online validation for changed/newly-enabled REALITY presets
	for _, m := range cfg.Presets {
		if !m.Enabled {
			continue
		}
		if m.Mode == config.ModeVLESSVision || m.Mode == config.ModeVLESSReality {
			isLocalDest := strings.HasPrefix(m.Dest, "127.0.0.1:") || strings.HasPrefix(m.Dest, "localhost:")
			if m.Skin != "" && isLocalDest {
				cert := cfg.FindCert(m.SNI)
				if cert == nil && m.SkinDomain != "" {
					cert = cfg.FindCert(m.SkinDomain)
				}
				if cert == nil {
					return fmt.Errorf("REALITY preset %s has skin enabled for domain %s, but certificate is not registered", m.Mode, m.SNI)
				}
			} else {
				if _, _, err := config.ValidateRealitySNIAndDest(m.SNI, m.Dest); err != nil {
					return fmt.Errorf("REALITY preset %s configuration invalid: %w", m.Mode, err)
				}
				var activeM *config.ModeInfo
				if activeCfg != nil {
					for j := range activeCfg.Presets {
						if activeCfg.Presets[j].Mode == m.Mode {
							activeM = &activeCfg.Presets[j]
							break
						}
					}
				}
				needsOnlineValidation := activeM == nil || !activeM.Enabled || activeM.SNI != m.SNI || activeM.Dest != m.Dest
				if needsOnlineValidation {
					ctx.AppendLine(fmt.Sprintf("🔍 Validating REALITY target for preset %s: %s (%s)...", m.Mode, m.SNI, m.Dest))
					if _, err := config.ValidateRealityTarget(m.Dest, 5*time.Second); err != nil {
						return fmt.Errorf("REALITY target %s (%s) validation failed during apply: %w", m.SNI, m.Dest, err)
					}
					ctx.AppendLine(fmt.Sprintf("✅ REALITY target validated for preset %s.", m.Mode))
				}
			}
		}
	}

	jsonData, err := xray.GenerateXrayJSON(cfg, testOverrides, "")
	if err != nil {
		return fmt.Errorf("static configuration generation failed: %w", err)
	}
	if err := xray.ValidateConfig(jsonData); err != nil {
		return fmt.Errorf("static validation failed: %w", err)
	}
	ctx.AppendLine("✅ Syntax OK.")
	return nil
}

// RuntimeIsolationStep starts an isolated temporary Xray instance with dynamic randomized ports.
type RuntimeIsolationStep struct{}

func (s *RuntimeIsolationStep) Name() string {
	return "Runtime Isolation"
}

func (s *RuntimeIsolationStep) ShouldRun(ctx *ApplyContext) bool {
	return !ctx.Options.Force && (ctx.Options.Full || ctx.Impact.XrayConfigChanged)
}

func (s *RuntimeIsolationStep) Run(ctx *ApplyContext) error {
	ctx.AppendLine("🔍 Stage 2: Runtime Isolation Test...")
	if err := xray.ValidateRuntime(ctx.StagingCfg); err != nil {
		return fmt.Errorf("runtime isolation test failed: %w", err)
	}
	ctx.AppendLine("✅ Runtime isolation test passed (using randomized ports).")
	return nil
}

// CommitStagingStep commits the staged configuration to active storage.
type CommitStagingStep struct{}

func (s *CommitStagingStep) Name() string {
	return "Commit Staging"
}

func (s *CommitStagingStep) ShouldRun(ctx *ApplyContext) bool {
	return true
}

func (s *CommitStagingStep) Run(ctx *ApplyContext) error {
	ctx.AppendLine("🚀 Stage 3: Committing changes...")
	if data, err := os.ReadFile(config.GetConfigPath()); err == nil {
		ctx.ActiveBackupRaw = data
	}
	if data, err := os.ReadFile(config.GetConfigPathEx(true)); err == nil {
		ctx.StagingBackupRaw = data
	}

	if err := config.CommitStaging(); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}
	ctx.Committed = true
	if len(ctx.Impact.ChangedSections) > 0 {
		ctx.AppendLine(fmt.Sprintf("ℹ️  Changed sections: %v", ctx.Impact.ChangedSections))
	}
	if len(ctx.Impact.EndpointDiffs) > 0 {
		ctx.AppendLine("ℹ️  Endpoint changes:")
		for _, diff := range ctx.Impact.EndpointDiffs {
			ctx.AppendLine(fmt.Sprintf("   • %s", diff))
		}
	}
	return nil
}

// PathdSyncStep synchronizes PathLink agent configurations.
type PathdSyncStep struct{}

func (s *PathdSyncStep) Name() string {
	return "Pathd Sync"
}

func (s *PathdSyncStep) ShouldRun(ctx *ApplyContext) bool {
	return ctx.Impact.PathdConfigChanged
}

func (s *PathdSyncStep) Run(ctx *ApplyContext) error {
	pathdWasActive := IsPathdServiceActive()
	if err := syncPathdConfig(ctx.StagingCfg); err != nil {
		return fmt.Errorf("synchronize Pathd configuration: %w", err)
	}
	if pathdWasActive {
		ctx.AppendLine("✅ Pathd configuration synchronized and active service restarted.")
	} else if ctx.Options.Start && os.Geteuid() == 0 && service.IsUnitInstalled(service.PathdUnit) {
		ctx.AppendLine("🚀 Starting Pathd service (--start requested)...")
		if err := service.Start(service.PathdUnit); err != nil {
			return fmt.Errorf("start Pathd service: %w", err)
		}
		ctx.AppendLine("✅ Pathd service started.")
	} else {
		ctx.AppendLine("✅ Pathd configuration synchronized (service is stopped; skipping restart).")
	}
	return nil
}

// XrayGatewaySyncStep handles Xray core restarts and transparent gateway TUN synchronization.
type XrayGatewaySyncStep struct{}

func (s *XrayGatewaySyncStep) Name() string {
	return "Xray & Gateway Sync"
}

func (s *XrayGatewaySyncStep) ShouldRun(ctx *ApplyContext) bool {
	return true
}

func (s *XrayGatewaySyncStep) Run(ctx *ApplyContext) error {
	xrayActive := xray.IsServiceActive()
	opts := ctx.Options
	impact := ctx.Impact
	cfg := ctx.StagingCfg

	if opts.Full || impact.XrayConfigChanged {
		if !xrayActive {
			if opts.Start {
				ctx.AppendLine("🚀 Starting Xray service (--start requested)...")
				if err := service.Start(service.MainUnit); err != nil {
					ctx.AppendLine(fmt.Sprintf("❌ Error starting Xray service: %v", err))
					return fmt.Errorf("start Xray service: %w", err)
				}
				xrayActive = true
				ctx.XrayRestarted = true
			} else {
				ctx.AppendLine("ℹ️  Xray service is currently stopped (skipping restart).")
				ctx.AppendLine("   💡 Hint: To start the service with new configuration, run:")
				ctx.AppendLine("      xray-proxya service start core")
			}
		} else if ctx.GatewaySyncRequired {
			ctx.AppendLine("🔄 Restarting Xray and synchronizing Gateway runtime...")
		} else {
			ctx.AppendLine("🔄 Restarting Xray service...")
			if err := xray.RestartXrayServiceWithoutHook(); err != nil {
				ctx.AppendLine(fmt.Sprintf("❌ Error restarting Xray service: %v", err))
				return fmt.Errorf("restart Xray service: %w", err)
			}
			if cfg.Role == config.RoleGateway {
				if err := gateway.RestoreTunStateLocked(cfg); err != nil {
					ctx.AppendLine(fmt.Sprintf("❌ Error restoring Gateway runtime: %v", err))
					return fmt.Errorf("failed to restore gateway runtime: %w", err)
				}
			}
			ctx.XrayRestarted = true
		}
	} else {
		ctx.AppendLine("ℹ️  Xray restart skipped: no Xray-facing changes detected.")
	}

	if ctx.GatewaySyncRequired {
		if !xrayActive {
			ctx.AppendLine("ℹ️  Gateway runtime synchronization skipped: Xray service is stopped.")
		} else if err := gateway.SyncDesiredLocked(cfg); err != nil {
			ctx.AppendLine(fmt.Sprintf("❌ Failed to synchronize gateway runtime: %v", err))
			return fmt.Errorf("failed to synchronize gateway runtime: %w", err)
		} else {
			ctx.XrayRestarted = true
			ctx.AppendLine("✅ Gateway runtime synchronized with active configuration.")
		}
	}
	return nil
}

// SubServiceSyncStep restarts or reloads the subscription service.
type SubServiceSyncStep struct{}

func (s *SubServiceSyncStep) Name() string {
	return "Subscription Service Sync"
}

func (s *SubServiceSyncStep) ShouldRun(ctx *ApplyContext) bool {
	return true
}

func (s *SubServiceSyncStep) Run(ctx *ApplyContext) error {
	opts := ctx.Options
	impact := ctx.Impact

	if opts.Full || impact.SubListenerChanged {
		if HasSubServiceInstalled() {
			if AnySubServiceActive() {
				ctx.AppendLine("🔄 Restarting active subscription service...")
				if err := RestartSubServiceIfInstalled(); err != nil {
					ctx.AppendLine(fmt.Sprintf("❌ Error restarting subscription service: %v", err))
					return fmt.Errorf("restart subscription service: %w", err)
				}
				ctx.SubRestarted = true
			} else {
				if opts.Start {
					ctx.AppendLine("🚀 Starting subscription service (--start requested)...")
					if err := service.Start(service.SubUnit); err != nil {
						ctx.AppendLine(fmt.Sprintf("❌ Error starting subscription service: %v", err))
						return fmt.Errorf("start subscription service: %w", err)
					}
					ctx.SubRestarted = true
				} else {
					ctx.AppendLine("ℹ️  Subscription service is currently stopped (skipping restart).")
					ctx.AppendLine("   💡 Hint: To start the service with new configuration, run:")
					ctx.AppendLine("      xray-proxya service start sub")
				}
			}
		} else if impact.SubListenerChanged {
			ctx.AppendLine("ℹ️  Subscription listener changed, but no installed subscription service was found.")
		}
	} else if impact.SubContentChanged {
		ctx.AppendLine("ℹ️  Subscription content updated; no restart needed because the sub server reloads config on each request.")
	}
	return nil
}
