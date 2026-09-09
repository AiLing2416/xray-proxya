package applyops

import (
	"errors"
	"os"
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

func TestPipelineRollbackOnFailureAfterCommit(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	activePath := config.GetConfigPath()
	stagingPath := config.GetConfigPathEx(true)

	origActive := []byte(`{"role":"server","uuid":"orig-active"}`)
	origStaging := []byte(`{"role":"server","uuid":"orig-staging"}`)

	if err := os.WriteFile(activePath, []byte(`{"role":"server","uuid":"overwritten-by-commit"}`), 0600); err != nil {
		t.Fatal(err)
	}

	pipeline := &ApplyPipeline{
		steps: []ApplyStep{
			&mockStep{name: "step-fail", shouldRun: true, runErr: errors.New("post-commit sync failed")},
		},
	}

	actx := &ApplyContext{
		Committed:        true,
		ActiveBackupRaw:  origActive,
		StagingBackupRaw: origStaging,
	}

	err := pipeline.Execute(actx)
	if err == nil {
		t.Fatal("expected pipeline error, got nil")
	}

	restoredActive, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active after rollback: %v", err)
	}
	if string(restoredActive) != string(origActive) {
		t.Fatalf("active config not rolled back: got %s, want %s", string(restoredActive), string(origActive))
	}

	restoredStaging, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("read staging after rollback: %v", err)
	}
	if string(restoredStaging) != string(origStaging) {
		t.Fatalf("staging config not rolled back: got %s, want %s", string(restoredStaging), string(origStaging))
	}
}

