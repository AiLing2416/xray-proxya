package applyops

import (
	"os"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
)

// ApplyContext carries execution state, configuration snapshots, and output logs throughout the apply pipeline.
type ApplyContext struct {
	Options                  Options
	ActiveCfg                *config.UserConfig
	StagingCfg               *config.UserConfig
	Impact                   Impact
	Lines                    []string
	XrayRestarted            bool
	SubRestarted             bool
	GatewaySyncRequired      bool
	Committed                bool
	ActiveBackupRaw          []byte
	StagingBackupRaw         []byte
	GatewayActiveBackupRaw   []byte
	GatewayActiveExisted     bool
	GatewayStagingBackupRaw  []byte
	GatewayStagingExisted    bool
	GatewayTunDisabledBefore bool
	GatewayTunDisabledKnown  bool
}

var rollbackRuntimeFn = defaultRollbackRuntime

func defaultRollbackRuntime(actx *ApplyContext) {
	if actx == nil || actx.ActiveCfg == nil || !xray.IsServiceActive() {
		return
	}
	if !actx.XrayRestarted && !actx.GatewaySyncRequired {
		return
	}
	if actx.ActiveCfg.Role == config.RoleGateway {
		if actx.GatewayTunDisabledKnown && actx.GatewayTunDisabledBefore {
			_ = xray.RestartXrayServiceWithoutHook()
			_ = gateway.ApplyFirewall(actx.ActiveCfg)
			return
		}
		_ = gateway.SyncDesiredLocked(actx.ActiveCfg)
		return
	}
	_ = xray.RestartXrayServiceWithoutHook()
}

// AppendLine appends a user-facing log or status line to the context.
func (c *ApplyContext) AppendLine(line string) {
	c.Lines = append(c.Lines, line)
}

// ApplyStep represents a single, well-defined lifecycle phase or component sync during apply.
type ApplyStep interface {
	Name() string
	ShouldRun(ctx *ApplyContext) bool
	Run(ctx *ApplyContext) error
}

// ApplyPipeline coordinates the sequential execution of ApplyStep phases.
type ApplyPipeline struct {
	steps []ApplyStep
}

// NewApplyPipeline builds the standard production apply pipeline.
func NewApplyPipeline() *ApplyPipeline {
	return &ApplyPipeline{
		steps: []ApplyStep{
			&StaticValidationStep{},
			&RuntimeIsolationStep{},
			&CommitStagingStep{},
			&PathdSyncStep{},
			&XrayGatewaySyncStep{},
			&SubServiceSyncStep{},
		},
	}
}

// Execute runs all enabled steps sequentially against the provided context.
func (p *ApplyPipeline) Execute(actx *ApplyContext) error {
	for _, step := range p.steps {
		if step.ShouldRun(actx) {
			if err := step.Run(actx); err != nil {
				if actx.Committed && len(actx.ActiveBackupRaw) > 0 {
					_ = os.WriteFile(config.GetConfigPath(), actx.ActiveBackupRaw, 0600)
					if len(actx.StagingBackupRaw) > 0 {
						_ = os.WriteFile(config.GetConfigPathEx(true), actx.StagingBackupRaw, 0600)
					}
					if len(actx.GatewayActiveBackupRaw) > 0 {
						_ = os.WriteFile(config.GetGatewayConfPath(), actx.GatewayActiveBackupRaw, 0600)
					} else if !actx.GatewayActiveExisted && actx.GatewayTunDisabledKnown {
						_ = os.Remove(config.GetGatewayConfPath())
					}
					if len(actx.GatewayStagingBackupRaw) > 0 {
						_ = os.WriteFile(config.GetGatewayConfPathEx(true), actx.GatewayStagingBackupRaw, 0600)
					} else if actx.GatewayStagingExisted {
						_ = os.Remove(config.GetGatewayConfPathEx(true))
					}
					if actx.GatewayTunDisabledKnown {
						_ = config.SetGatewayTunDisabled(actx.GatewayTunDisabledBefore)
					}
					rollbackRuntimeFn(actx)
					actx.AppendLine("⚠️ Apply failed after commit. Automatically rolled back active configuration to protect system state.")
				}
				return err
			}
		}
	}
	return nil
}
