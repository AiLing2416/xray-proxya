package applyops

import (
	"errors"
	"testing"
	"xray-proxya/internal/config"
)

type mockStep struct {
	name      string
	shouldRun bool
	runErr    error
	executed  *bool
}

func (m *mockStep) Name() string {
	return m.name
}

func (m *mockStep) ShouldRun(ctx *ApplyContext) bool {
	return m.shouldRun
}

func (m *mockStep) Run(ctx *ApplyContext) error {
	if m.executed != nil {
		*m.executed = true
	}
	ctx.AppendLine("executed: " + m.name)
	return m.runErr
}

func TestPipelineExecutionOrder(t *testing.T) {
	var step1Run, step2Run bool
	pipeline := &ApplyPipeline{
		steps: []ApplyStep{
			&mockStep{name: "step-1", shouldRun: true, executed: &step1Run},
			&mockStep{name: "step-2", shouldRun: true, executed: &step2Run},
		},
	}

	actx := &ApplyContext{
		StagingCfg: &config.UserConfig{},
	}

	if err := pipeline.Execute(actx); err != nil {
		t.Fatalf("unexpected pipeline execution error: %v", err)
	}

	if !step1Run || !step2Run {
		t.Fatalf("expected both steps to run, got step1=%v step2=%v", step1Run, step2Run)
	}

	if len(actx.Lines) != 2 || actx.Lines[0] != "executed: step-1" || actx.Lines[1] != "executed: step-2" {
		t.Fatalf("unexpected lines: %#v", actx.Lines)
	}
}

func TestPipelineStepSkipping(t *testing.T) {
	var step1Run, step2Run bool
	pipeline := &ApplyPipeline{
		steps: []ApplyStep{
			&mockStep{name: "step-1", shouldRun: false, executed: &step1Run},
			&mockStep{name: "step-2", shouldRun: true, executed: &step2Run},
		},
	}

	actx := &ApplyContext{
		StagingCfg: &config.UserConfig{},
	}

	if err := pipeline.Execute(actx); err != nil {
		t.Fatalf("unexpected pipeline error: %v", err)
	}

	if step1Run {
		t.Fatal("step-1 should have been skipped")
	}
	if !step2Run {
		t.Fatal("step-2 should have executed")
	}
}

func TestPipelineStepErrorHalts(t *testing.T) {
	expectedErr := errors.New("simulated step error")
	var step2Run bool
	pipeline := &ApplyPipeline{
		steps: []ApplyStep{
			&mockStep{name: "step-1", shouldRun: true, runErr: expectedErr},
			&mockStep{name: "step-2", shouldRun: true, executed: &step2Run},
		},
	}

	actx := &ApplyContext{
		StagingCfg: &config.UserConfig{},
	}

	err := pipeline.Execute(actx)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}

	if step2Run {
		t.Fatal("step-2 should not have run after step-1 error")
	}
}

func TestDefaultPipelineStepsCount(t *testing.T) {
	p := NewApplyPipeline()
	if len(p.steps) != 7 {
		t.Fatalf("expected 7 default apply steps, got %d", len(p.steps))
	}
}
