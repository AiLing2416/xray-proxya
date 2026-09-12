package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// FlashType represents the semantic style of a temporary visual feedback.
type FlashType int

const (
	FlashNone FlashType = iota
	FlashSuccess
	FlashError
	FlashInfo
	FlashWarn
)

// FlashExpiryMsg is delivered via tea.Tick when a flash duration expires.
type FlashExpiryMsg struct {
	ID string
}

// FlashEntry tracks an active transient feedback state.
type FlashEntry struct {
	Type     FlashType
	Until    time.Time
	Duration time.Duration
}

// FlashManager manages temporary color changes and feedback states for TUI elements.
type FlashManager struct {
	entries map[string]FlashEntry
	styles  map[FlashType]lipgloss.Style
}

// NewFlashManager creates an initialized FlashManager with standard high-contrast styles.
func NewFlashManager() *FlashManager {
	return &FlashManager{
		entries: make(map[string]FlashEntry),
		styles: map[FlashType]lipgloss.Style{
			FlashSuccess: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("2")),
			FlashError:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("9")),
			FlashInfo:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("33")),
			FlashWarn:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("3")),
		},
	}
}

// SetCustomStyle overrides or assigns a custom lipgloss.Style for a FlashType.
func (fm *FlashManager) SetCustomStyle(ft FlashType, style lipgloss.Style) {
	if fm.styles == nil {
		fm.styles = make(map[FlashType]lipgloss.Style)
	}
	fm.styles[ft] = style
}

// Trigger starts a transient flash state for an ID and returns a tea.Cmd that triggers automatic re-render upon expiration.
func (fm *FlashManager) Trigger(id string, ft FlashType, d time.Duration) tea.Cmd {
	if fm.entries == nil {
		fm.entries = make(map[string]FlashEntry)
	}
	fm.entries[id] = FlashEntry{
		Type:     ft,
		Until:    time.Now().Add(d),
		Duration: d,
	}
	return tea.Tick(d, func(time.Time) tea.Msg {
		return FlashExpiryMsg{ID: id}
	})
}

// IsActive reports whether the given ID currently has an active, unexpired flash state.
func (fm *FlashManager) IsActive(id string) bool {
	if fm == nil || fm.entries == nil {
		return false
	}
	entry, ok := fm.entries[id]
	if !ok {
		return false
	}
	return time.Now().Before(entry.Until)
}

// GetType returns the active FlashType for an ID, or FlashNone if inactive or expired.
func (fm *FlashManager) GetType(id string) FlashType {
	if fm == nil || fm.entries == nil {
		return FlashNone
	}
	entry, ok := fm.entries[id]
	if !ok || time.Now().After(entry.Until) {
		return FlashNone
	}
	return entry.Type
}

// Expire removes an entry if its expiration time has elapsed.
func (fm *FlashManager) Expire(id string) {
	if fm == nil || fm.entries == nil {
		return
	}
	if entry, ok := fm.entries[id]; ok && time.Now().After(entry.Until) {
		delete(fm.entries, id)
	}
}

// Clear explicitly terminates any active flash state for an ID.
func (fm *FlashManager) Clear(id string) {
	if fm == nil || fm.entries == nil {
		return
	}
	delete(fm.entries, id)
}

// Render renders the text using the active flash style if active, or falls back to defaultStyle.
func (fm *FlashManager) Render(id, text string, defaultStyle lipgloss.Style) string {
	ft := fm.GetType(id)
	if ft != FlashNone {
		if style, ok := fm.styles[ft]; ok {
			return style.Render(text)
		}
	}
	return defaultStyle.Render(text)
}
