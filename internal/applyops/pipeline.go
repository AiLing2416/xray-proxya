package applyops

import (
	"xray-proxya/internal/config"
)

// ApplyContext carries execution state, configuration snapshots, and output logs throughout the apply pipeline.
type ApplyContext struct {
	Options             Options
	ActiveCfg           *config.UserConfig
	StagingCfg          *config.UserConfig
	Impact              Impact
	Lines               []string
	XrayRestarted       bool
	SubRestarted        bool
	GatewaySyncRequired bool
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
			&IPv6RotateSyncStep{},
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
				return err
			}
		}
	}
	return nil
}
