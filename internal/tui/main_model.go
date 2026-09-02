/*
================================================================================
                       XRAY-PROXYA TUI DESIGN PRINCIPLES
================================================================================
1. STAGING-FIRST ARCHITECTURE:
   - All configuration modifications (Presets, Relays, Guests, Gateway config)
     are staged immediately in staging memory/file.
   - Global [A] applies pending changes with validation; [U] discards (Undo).
   - [X] Remove directly deletes items from staging without modals because
     staging safety guarantees undoability.

2. CLEAN INFORMATION BAR (INFO PANE):
   - Content is pure data (links, details, logs, metrics). No key hints inside.
   - In-place interaction: [Enter] on multi-choice items or [Z] Zero opens
     prompt/selection directly inside the Info Bar.
   - All prompt titles and labels use regular non-bold blue styling.
   - Large Info Mode [+/-] expands height to 40% of terminal for deep inspection.
   - Transient messages (status/notice) temporarily take over Info Bar content
     for 1 second before reverting to underlying data.
   - Sticky Override messages (e.g. system call exit!=0 error output or in-flight
     test state) replace normal info until user interacts or test finishes.
   - Relay test/info/speed results are preserved in memory per item until exit.

3. DUAL-CLIPBOARD & TERMINAL INTEGRATION:
   - [C] Copy triggers OSC 52 (remote SSH/local clipboard write) + local clipboard.
   - Visual feedback: [C] Copy badge in footer glows GREEN for 1s upon copying.
   - OSC 8 hyperlinking is attached directly to the [C] Copy footer badge.

4. HARMONIZED SHORTCUTS & NAVIGATION:
   - [Space] universally toggles boolean states across all tabs.
   - [Enter] universally activates in-bar selection for multi-choice options.
   - [L] triggers a one-time log tail snapshot.
   - [F] triggers live log follow mode (Green Title), stops on any keypress.
   - Footer auto-wraps cleanly across multiple lines on narrow terminals.
================================================================================
*/

package tui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/relaytest"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
)

type sessionTab int

const (
	tabStatus sessionTab = iota
	tabService
	tabPresets
	tabRelays
	tabGuests
	tabGateway
)

type inputMode int

const (
	inputNone inputMode = iota
	inputAddRelayAlias
	inputAddRelay
	inputAddGuest
	inputSetGuestQuota
	inputSetGuestZero
	inputSetGuestOutbound
	inputBypassCountries
)

type statsMsg struct {
	direct   int64
	relay    int64
	active   bool
	pid      int
	allStats map[string]int64
	service  xray.ServiceState
}

type applyResultMsg struct {
	lines []string
	err   error
}

type serviceActionMsg struct {
	action string
	output string
	err    error
	state  xray.ServiceState
}

type serviceFollowTickMsg struct{}
type clearNoticeMsg struct{}

type serviceLogsMsg struct {
	body string
	err  error
}

type publicIPMsg struct {
	ip string
}

type relayInfoMsg struct {
	alias string
	body  string
	err   error
}

type relaySpeedMsg struct {
	alias string
	body  string
	err   error
}

type relayTestMsg struct {
	alias string
	tcp   string
	udp   string
	dns   string
	ipv4  string
	ipv6  string
	raw   string
	err   error
}

type Model struct {
	active             *config.UserConfig
	staging            *config.UserConfig
	currentTab         sessionTab
	cursor             int
	width              int
	height             int
	directStat         int64
	relayStat          int64
	coreActive         bool
	corePID            int
	lastStats          map[string]int64
	relayResults       map[string]relayTestMsg
	relayTestMap       map[string]string
	relayInfoMap       map[string]string
	relaySpeedMap      map[string]string
	relayViewMode      map[string]string
	relayLoading       string
	portBuffer         string
	detailScroll       int
	cachedIP           string
	localIP            string
	useLocalIP         bool
	serviceState       xray.ServiceState
	managedServices    []ManagedServiceItem
	serviceFollow      bool
	serviceLogs        string
	relayAlias         string

	// Unified transient notice in info bar (1s overlay)
	transientMsg       string
	transientUntil     time.Time

	// Temporary override info (e.g. in-flight testing state or exit != 0 output)
	overrideMsg        string

	// Large info pane (40% height)
	largeInfo          bool
	// Copy feedback timer (1s green badge)
	copyFeedbackUntil  time.Time

	// In-bar input mode
	inputMode          inputMode
	textInput          textinput.Model
	inputValidationError string

	// In-bar selection mode
	infoSelectMode     bool
	infoSelectTitle    string
	infoSelectChoices  []string
	infoSelectIdx      int
	infoSelectTarget   string // "guest-outbound-choice", "gw-state", "gw-iface", "gw-relay"

	// Logs in info bar
	infoShowLogs       bool

	// Service configuration management (two-tier in-bar tree)
	servicePropMode        bool
	servicePropEdit        bool
	serviceConfigItem      ManagedServiceItem
	serviceProps           []ServiceProperty
	servicePropIndex       int
	serviceChoiceOptions   []string
	serviceChoiceIdx       int
	serviceValidationError string

	// Gateway runtime flags
	gwNftables         bool
	gwTun              bool
	gwForward          bool
	gwLocalTestIP      string
	gwLANTestIP        string
}

func (m *Model) setNotice(msg string) tea.Cmd {
	m.transientMsg = msg
	m.transientUntil = time.Now().Add(1 * time.Second)
	return tea.Tick(1*time.Second, func(time.Time) tea.Msg {
		return clearNoticeMsg{}
	})
}

func (m *Model) setOverride(msg string) {
	m.overrideMsg = msg
}

func tickStats(apiPort int) tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		service := xray.GetServiceState()
		active, pid := service.Active, service.PID
		allStats, _ := xray.GetXrayStats(apiPort)
		summary := trafficstats.Summarize(allStats)
		return statsMsg{
			direct:   summary.Direct,
			relay:    summary.Relay,
			active:   active,
			pid:      pid,
			allStats: allStats,
			service:  service,
		}
	})
}

func tickServiceLogs() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return serviceFollowTickMsg{}
	})
}

func refreshServiceLogs(lines int) tea.Cmd {
	return func() tea.Msg {
		body, err := xray.ReadLogTail(lines)
		return serviceLogsMsg{body: body, err: err}
	}
}

func refreshUnitLogs(unit string, lines int) tea.Cmd {
	return func() tea.Msg {
		body, err := xray.JournalTail(unit, lines)
		return serviceLogsMsg{body: body, err: err}
	}
}

func fetchPublicIP() tea.Cmd {
	return func() tea.Msg {
		ip := utils.GetPublicIPv4()
		if ip == "" {
			ip = utils.GetLocalIP()
		}
		return publicIPMsg{ip: ip}
	}
}

func fetchRelayTest(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayTestMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "test", alias, "--json")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return relayTestMsg{alias: alias, tcp: "Fail", udp: "Fail", dns: "Fail", ipv4: "--", ipv6: "--", raw: string(out), err: err}
		}
		var res relaytest.TestResult
		if err := json.Unmarshal(out, &res); err == nil {
			tcpStr := "--"
			if res.Transport.TCPRTTMs > 0 {
				tcpStr = fmt.Sprintf("%dms", res.Transport.TCPRTTMs)
			} else if res.Transport.TCPStatus != "" {
				tcpStr = string(res.Transport.TCPStatus)
			}
			udpStr := "--"
			if res.Transport.UDPRTTMs > 0 {
				udpStr = fmt.Sprintf("%dms", res.Transport.UDPRTTMs)
			} else if res.Transport.UDPStatus != "" {
				udpStr = string(res.Transport.UDPStatus)
			}
			dnsStr := "--"
			if item, ok := res.Transport.RawItems["dns53"]; ok {
				if item.RTTMs > 0 {
					dnsStr = fmt.Sprintf("%dms", item.RTTMs)
				} else {
					dnsStr = string(item.Status)
				}
			} else if res.Transport.UDPStatus == relaytest.StatusPass {
				dnsStr = "OK"
			}
			ipv4Str := res.ExitIP.IPv4
			if ipv4Str == "" {
				ipv4Str = "--"
			}
			ipv6Str := res.ExitIP.IPv6
			if ipv6Str == "" {
				ipv6Str = "--"
			}
			terminalText := strings.TrimSpace(relaytest.RenderTerminal([]*relaytest.TestResult{&res}))
			return relayTestMsg{
				alias: alias,
				tcp:   tcpStr,
				udp:   udpStr,
				dns:   dnsStr,
				ipv4:  ipv4Str,
				ipv6:  ipv6Str,
				raw:   terminalText,
			}
		}
		return relayTestMsg{alias: alias, tcp: "OK", udp: "OK", dns: "OK", ipv4: "--", ipv6: "--", raw: strings.TrimSpace(string(out))}
	}
}

func fetchRelayInfo(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayInfoMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "info", alias)
		out, err := cmd.CombinedOutput()
		return relayInfoMsg{alias: alias, body: strings.TrimSpace(string(out)), err: err}
	}
}

func fetchRelaySpeed(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relaySpeedMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "speed", alias)
		out, err := cmd.CombinedOutput()
		return relaySpeedMsg{alias: alias, body: strings.TrimSpace(string(out)), err: err}
	}
}

func InitialModel() Model {
	active, _ := config.LoadConfig()
	staging, _ := config.LoadConfigEx(true)
	if staging == nil {
		staging = active
	}

	ti := textinput.New()
	ti.Focus()

	nft, tun, fwd := checkGatewayStatus()
	services := QueryManagedServices(active)

	return Model{
		active:          active,
		staging:         staging,
		currentTab:      tabStatus,
		cursor:          0,
		relayResults:    make(map[string]relayTestMsg),
		relayTestMap:    make(map[string]string),
		relayInfoMap:    make(map[string]string),
		relaySpeedMap:   make(map[string]string),
		relayViewMode:   make(map[string]string),
		serviceState:    xray.GetServiceState(),
		managedServices: services,
		textInput:       ti,
		cachedIP:        "127.0.0.1",
		localIP:         utils.GetLocalIP(),
		gwNftables:      nft,
		gwTun:           tun,
		gwForward:       fwd,
	}
}

func (m Model) Init() tea.Cmd {
	apiPort := 10085
	if m.staging != nil && m.staging.APIInbound > 0 {
		apiPort = m.staging.APIInbound
	}
	return tea.Batch(
		tickStats(apiPort),
		fetchPublicIP(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case clearNoticeMsg:
		return m, nil

	case statsMsg:
		m.directStat = msg.direct
		m.relayStat = msg.relay
		m.coreActive = msg.active
		m.corePID = msg.pid
		m.lastStats = msg.allStats
		m.serviceState = msg.service
		apiPort := 10085
		if m.staging != nil && m.staging.APIInbound > 0 {
			apiPort = m.staging.APIInbound
		}
		return m, tickStats(apiPort)

	case publicIPMsg:
		if msg.ip != "" {
			m.cachedIP = msg.ip
		}
		return m, nil

	case relayTestMsg:
		m.relayLoading = ""
		m.relayResults[msg.alias] = msg
		if msg.err != nil {
			m.setOverride(fmt.Sprintf("Relay Test Error (exit != 0):\n%v\n%s", msg.err, msg.raw))
			return m, nil
		}
		m.relayTestMap[msg.alias] = msg.raw
		m.relayViewMode[msg.alias] = "test"
		m.overrideMsg = ""
		return m, nil

	case relayInfoMsg:
		m.relayLoading = ""
		if msg.err != nil {
			m.setOverride(fmt.Sprintf("Relay Info Error (exit != 0):\n%v\n%s", msg.err, msg.body))
			return m, nil
		}
		m.relayInfoMap[msg.alias] = msg.body
		m.relayViewMode[msg.alias] = "info"
		m.overrideMsg = ""
		return m, nil

	case relaySpeedMsg:
		m.relayLoading = ""
		if msg.err != nil {
			m.setOverride(fmt.Sprintf("Relay Speed Error (exit != 0):\n%v\n%s", msg.err, msg.body))
			return m, nil
		}
		m.relaySpeedMap[msg.alias] = msg.body
		m.relayViewMode[msg.alias] = "speed"
		m.overrideMsg = ""
		return m, nil

	case serviceLogsMsg:
		m.serviceLogs = msg.body
		return m, nil

	case serviceFollowTickMsg:
		if m.serviceFollow && m.infoShowLogs {
			unit := xray.MainServiceUnit
			if m.currentTab == tabService && m.cursor < len(m.managedServices) {
				unit = m.managedServices[m.cursor].UnitName
			}
			return m, tea.Batch(refreshUnitLogs(unit, m.getLargeInfoLineCount()), tickServiceLogs())
		}
		return m, nil

	case serviceActionMsg:
		m.serviceState = msg.state
		m.managedServices = QueryManagedServices(m.active)
		var cmd tea.Cmd
		if msg.err != nil {
			errMsg := fmt.Sprintf("Service Error (exit != 0):\n%v", msg.err)
			if msg.output != "" {
				errMsg += "\n" + msg.output
			}
			m.setOverride(errMsg)
			cmd = m.setNotice(fmt.Sprintf("%s failed", msg.action))
		} else {
			m.overrideMsg = ""
			cmd = m.setNotice(fmt.Sprintf("%s completed", msg.action))
		}
		return m, cmd

	case applyResultMsg:
		var cmd tea.Cmd
		if msg.err != nil {
			outText := strings.Join(msg.lines, "\n")
			if strings.TrimSpace(outText) == "" {
				outText = msg.err.Error()
			}
			m.setOverride(fmt.Sprintf("Apply Error (exit != 0):\n%s", outText))
			cmd = m.setNotice("apply failed")
		} else {
			m.overrideMsg = ""
			cmd = m.setNotice(summarizeActionResult(msg.lines, msg.err))
			m.active, _ = config.LoadConfig()
			m.staging, _ = config.LoadConfigEx(true)
			if m.staging == nil {
				m.staging = m.active
			}
			m.serviceState = xray.GetServiceState()
			m.managedServices = QueryManagedServices(m.active)
			m.gwNftables, m.gwTun, m.gwForward = checkGatewayStatus()
		}
		return m, cmd

	case gatewayActionResultMsg:
		m.gwNftables, m.gwTun, m.gwForward = checkGatewayStatus()
		var cmd tea.Cmd
		if msg.err != nil {
			m.setOverride(fmt.Sprintf("Gateway %s Error (exit != 0):\n%v", msg.action, msg.err))
			cmd = m.setNotice(fmt.Sprintf("gateway %s failed", msg.action))
		} else {
			m.overrideMsg = ""
			cmd = m.setNotice(fmt.Sprintf("gateway %s applied", msg.action))
		}
		return m, cmd

	case gatewayTestResultMsg:
		var cmd tea.Cmd
		if msg.err != nil {
			if msg.row == 0 {
				m.gwLocalTestIP = "ERR"
			} else {
				m.gwLANTestIP = "ERR"
			}
			m.setOverride(fmt.Sprintf("Gateway Route Test Error:\n%v", msg.err))
			cmd = m.setNotice("test failed")
		} else {
			if msg.row == 0 {
				m.gwLocalTestIP = msg.ip
			} else {
				m.gwLANTestIP = msg.ip
			}
			m.overrideMsg = ""
			cmd = m.setNotice(fmt.Sprintf("test completed, egress: %s", msg.ip))
		}
		return m, cmd

	case tea.KeyMsg:
		s := msg.String()

		// Any keypress stops live log follow mode (unless it's 'f'/'F' which explicitly toggles follow)
		if m.serviceFollow && s != "f" && s != "F" {
			m.serviceFollow = false
			if s == "tab" || s == "shift+tab" {
				m.infoShowLogs = false
			}
		}

		// -------------------------------------------------------------
		// 1. IN-BAR INPUT MODE HANDLING
		// -------------------------------------------------------------
		if m.inputMode != inputNone {
			switch s {
			case "esc":
				m.inputMode = inputNone
				m.inputValidationError = ""
				m.textInput.Blur()
				return m, nil
			case "enter":
				return m.submitInput()
			default:
				if m.inputValidationError != "" {
					m.inputValidationError = ""
				}
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		}

		// -------------------------------------------------------------
		// 2. IN-BAR SELECTION MODE HANDLING
		// -------------------------------------------------------------
		if m.infoSelectMode {
			switch s {
			case "esc":
				m.infoSelectMode = false
				return m, nil
			case "up", "k", "left", "h":
				if len(m.infoSelectChoices) > 0 {
					m.infoSelectIdx = (m.infoSelectIdx - 1 + len(m.infoSelectChoices)) % len(m.infoSelectChoices)
				}
				return m, nil
			case "down", "j", "right", "l":
				if len(m.infoSelectChoices) > 0 {
					m.infoSelectIdx = (m.infoSelectIdx + 1) % len(m.infoSelectChoices)
				}
				return m, nil
			case "enter":
				return m.confirmInfoSelect()
			}
			return m, nil
		}

		// -------------------------------------------------------------
		// 2b. SERVICE PROPERTY EDIT MODE (Level 2)
		// -------------------------------------------------------------
		if m.servicePropEdit {
			if s == "ctrl+c" {
				return m, tea.Quit
			}
			if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
				prop := m.serviceProps[m.servicePropIndex]
				if prop.Type == PropInput {
					switch s {
					case "esc":
						m.servicePropEdit = false
						m.serviceValidationError = ""
						m.textInput.Blur()
						return m, nil
					case "enter":
						val := m.textInput.Value()
						if err := validateAndApplyServiceProp(m.staging, m.serviceConfigItem, prop, val); err != nil {
							m.serviceValidationError = err.Error()
							return m, nil
						}
						_ = m.staging.SaveEx(true)
						m.servicePropEdit = false
						m.serviceValidationError = ""
						m.textInput.Blur()
						m.serviceProps = loadServiceProperties(m.staging, m.serviceConfigItem)
						return m, nil
					default:
						if m.serviceValidationError != "" {
							m.serviceValidationError = ""
						}
						var cmd tea.Cmd
						m.textInput, cmd = m.textInput.Update(msg)
						return m, cmd
					}
				} else if prop.Type == PropChoice {
					switch s {
					case "esc":
						m.servicePropEdit = false
						m.serviceValidationError = ""
						return m, nil
					case "up", "k", "left", "h":
						if len(m.serviceChoiceOptions) > 0 {
							m.serviceChoiceIdx = (m.serviceChoiceIdx - 1 + len(m.serviceChoiceOptions)) % len(m.serviceChoiceOptions)
						}
						return m, nil
					case "down", "j", "right", "l":
						if len(m.serviceChoiceOptions) > 0 {
							m.serviceChoiceIdx = (m.serviceChoiceIdx + 1) % len(m.serviceChoiceOptions)
						}
						return m, nil
					case "enter":
						if len(m.serviceChoiceOptions) > 0 {
							val := m.serviceChoiceOptions[m.serviceChoiceIdx]
							if err := validateAndApplyServiceProp(m.staging, m.serviceConfigItem, prop, val); err != nil {
								m.serviceValidationError = err.Error()
								return m, nil
							}
							_ = m.staging.SaveEx(true)
							m.servicePropEdit = false
							m.serviceValidationError = ""
							m.serviceProps = loadServiceProperties(m.staging, m.serviceConfigItem)
							return m, nil
						}
						m.servicePropEdit = false
						return m, nil
					}
					return m, nil
				}
			}
			m.servicePropEdit = false
			return m, nil
		}

		// -------------------------------------------------------------
		// 2c. SERVICE PROPERTY LIST MODE (Level 1)
		// -------------------------------------------------------------
		if m.servicePropMode {
			if s == "ctrl+c" {
				return m, tea.Quit
			}
			switch s {
			case "esc":
				m.servicePropMode = false
				m.serviceValidationError = ""
				return m, nil
			case "up", "k":
				if m.servicePropIndex > 0 {
					m.servicePropIndex--
				}
				return m, nil
			case "down", "j":
				if m.servicePropIndex < len(m.serviceProps)-1 {
					m.servicePropIndex++
				}
				return m, nil
			case " ":
				if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
					prop := m.serviceProps[m.servicePropIndex]
					if prop.Type == PropBool {
						newBool := !prop.BoolVal
						_ = validateAndApplyServiceProp(m.staging, m.serviceConfigItem, prop, boolToString(newBool))
						_ = m.staging.SaveEx(true)
						m.serviceProps = loadServiceProperties(m.staging, m.serviceConfigItem)
						return m, nil
					}
				}
				return m, nil
			case "enter":
				if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
					prop := m.serviceProps[m.servicePropIndex]
					if prop.Type == PropBool {
						newBool := !prop.BoolVal
						_ = validateAndApplyServiceProp(m.staging, m.serviceConfigItem, prop, boolToString(newBool))
						_ = m.staging.SaveEx(true)
						m.serviceProps = loadServiceProperties(m.staging, m.serviceConfigItem)
						return m, nil
					}
					if prop.Type == PropInput {
						m.servicePropEdit = true
						m.serviceValidationError = ""
						m.textInput.SetValue(prop.Value)
						m.textInput.Focus()
						return m, nil
					}
					if prop.Type == PropChoice {
						m.servicePropEdit = true
						m.serviceValidationError = ""
						m.serviceChoiceOptions = prop.Choices
						m.serviceChoiceIdx = 0
						for i, c := range prop.Choices {
							if c == prop.Value {
								m.serviceChoiceIdx = i
								break
							}
						}
						return m, nil
					}
				}
				return m, nil
			case "+", "=":
				m.largeInfo = true
				return m, nil
			case "-":
				m.largeInfo = false
				return m, nil
			}
			return m, nil
		}

		// -------------------------------------------------------------
		// 3. GLOBAL SHORTCUTS
		// -------------------------------------------------------------
		switch s {
		case "ctrl+c", "q", "Q":
			return m, tea.Quit

		case "tab":
			m.nextTab()
			return m, nil

		case "shift+tab":
			m.prevTab()
			return m, nil

		case "+", "=":
			m.largeInfo = true
			return m, nil

		case "-":
			m.largeInfo = false
			return m, nil

		case "a", "A":
			if m.currentTab == tabStatus {
				return m, nil
			}
			if m.currentTab == tabService {
				if m.servicePropMode || m.servicePropEdit {
					return m, nil
				}
				if !hasAnyServiceStagedChanges(m.active, m.staging, m.managedServices) {
					return m, nil
				}
			}
			return m, m.performApply()

		case "u", "U":
			if m.currentTab == tabStatus {
				return m, nil
			}
			if m.currentTab == tabService {
				if m.servicePropMode || m.servicePropEdit {
					return m, nil
				}
				if !hasAnyServiceStagedChanges(m.active, m.staging, m.managedServices) {
					return m, nil
				}
			}
			_ = applyops.ClearPending()
			m.active, _ = config.LoadConfig()
			m.staging, _ = config.LoadConfigEx(true)
			if m.staging == nil {
				m.staging = m.active
			}
			m.relayResults = make(map[string]relayTestMsg)
			m.overrideMsg = ""
			return m, m.setNotice("staging reset")

		case "c", "C":
			if m.currentTab == tabStatus || m.currentTab == tabService {
				return m, nil
			}
			text := m.getSelectedCopyContent()
			if text != "" {
				writeOSC52(text)
				_ = clipboard.WriteAll(text)
				m.copyFeedbackUntil = time.Now().Add(1 * time.Second)
			}
			return m, nil
		}

		// -------------------------------------------------------------
		// 4. TAB-SPECIFIC SHORTCUTS
		// -------------------------------------------------------------
		switch m.currentTab {

		// =============================================================
		// STATUS TAB
		// =============================================================
		case tabStatus:
			switch s {
			case "s", "S":
				action := "start"
				if m.serviceState.Active {
					action = "stop"
				}
				noticeCmd := m.setNotice(fmt.Sprintf("%sing main service...", action))
				return m, tea.Batch(runMainServiceAction(action), noticeCmd)

			case "r", "R":
				noticeCmd := m.setNotice("restarting main service...")
				return m, tea.Batch(runMainServiceAction("restart"), noticeCmd)

			case "l", "L":
				m.infoShowLogs = true
				m.serviceFollow = false
				m.overrideMsg = ""
				return m, refreshServiceLogs(m.getLargeInfoLineCount())

			case "f", "F":
				m.serviceFollow = !m.serviceFollow
				m.infoShowLogs = true
				m.overrideMsg = ""
				if m.serviceFollow {
					return m, tea.Batch(refreshServiceLogs(m.getLargeInfoLineCount()), tickServiceLogs())
				}
				return m, nil
			}

		// =============================================================
		// SERVICE TAB (List-based management)
		// =============================================================
		case tabService:
			switch s {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.overrideMsg = ""
				}
				return m, nil

			case "down", "j":
				if m.cursor < len(m.managedServices)-1 {
					m.cursor++
					m.overrideMsg = ""
				}
				return m, nil

			case "enter":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					m.servicePropMode = true
					m.servicePropEdit = false
					m.serviceValidationError = ""
					m.serviceConfigItem = item
					m.servicePropIndex = 0
					m.serviceProps = loadServiceProperties(m.staging, item)
					m.infoShowLogs = false
					m.serviceFollow = false
					m.transientMsg = ""
					m.transientUntil = time.Time{}
					m.overrideMsg = ""
					return m, nil
				}
				return m, nil

			case " ", "s", "S":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					if serviceHasStagedChanges(m.active, m.staging, item) {
						return m, m.setNotice("pending changes: press [A] to apply first")
					}
					action := "start"
					if item.Active {
						action = "stop"
					}
					noticeCmd := m.setNotice(fmt.Sprintf("%sing %s...", action, item.DisplayName))
					return m, tea.Batch(runUnitServiceAction(action, item.UnitName), noticeCmd)
				}

			case "e", "E":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					noticeCmd := m.setNotice(fmt.Sprintf("enabling %s...", item.DisplayName))
					return m, tea.Batch(runUnitServiceAction("enable", item.UnitName), noticeCmd)
				}

			case "d", "D":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					noticeCmd := m.setNotice(fmt.Sprintf("disabling %s...", item.DisplayName))
					return m, tea.Batch(runUnitServiceAction("disable", item.UnitName), noticeCmd)
				}

			case "r", "R":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					if serviceHasStagedChanges(m.active, m.staging, item) {
						return m, m.setNotice("pending changes: press [A] to apply first")
					}
					noticeCmd := m.setNotice(fmt.Sprintf("restarting %s...", item.DisplayName))
					return m, tea.Batch(runUnitServiceAction("restart", item.UnitName), noticeCmd)
				}

			case "l", "L":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					m.infoShowLogs = true
					m.serviceFollow = false
					m.overrideMsg = ""
					return m, refreshUnitLogs(item.UnitName, m.getLargeInfoLineCount())
				}
				return m, nil

			case "f", "F":
				if m.cursor >= 0 && m.cursor < len(m.managedServices) {
					item := m.managedServices[m.cursor]
					m.serviceFollow = !m.serviceFollow
					m.infoShowLogs = true
					m.overrideMsg = ""
					if m.serviceFollow {
						return m, tea.Batch(refreshUnitLogs(item.UnitName, m.getLargeInfoLineCount()), tickServiceLogs())
					}
				}
				return m, nil
			}

		// =============================================================
		// PRESETS TAB
		// =============================================================
		case tabPresets:
			switch s {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.portBuffer = ""
					m.overrideMsg = ""
				}
				return m, nil

			case "down", "j":
				if m.staging != nil && m.cursor < len(m.staging.Presets)-1 {
					m.cursor++
					m.portBuffer = ""
					m.overrideMsg = ""
				}
				return m, nil

			case " ":
				if m.staging != nil && m.cursor < len(m.staging.Presets) {
					m.staging.Presets[m.cursor].Enabled = !m.staging.Presets[m.cursor].Enabled
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("preset %s toggled", m.staging.Presets[m.cursor].Mode))
				}
				return m, nil

			case "r", "R":
				if m.staging != nil && m.cursor < len(m.staging.Presets) {
					m.staging.Presets[m.cursor].RegenFlag = !m.staging.Presets[m.cursor].RegenFlag
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("regen flag toggled for %s", m.staging.Presets[m.cursor].Mode))
				}
				return m, nil

			case "backspace":
				if m.staging != nil && m.cursor < len(m.staging.Presets) && len(m.portBuffer) > 0 {
					m.portBuffer = m.portBuffer[:len(m.portBuffer)-1]
					var port int
					if m.portBuffer != "" {
						fmt.Sscanf(m.portBuffer, "%d", &port)
					}
					m.staging.Presets[m.cursor].Port = port
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("port => %d", port))
				}
				return m, nil

			default:
				if s >= "0" && s <= "9" && m.staging != nil && m.cursor < len(m.staging.Presets) {
					if len(m.portBuffer) >= 5 {
						m.portBuffer = ""
					}
					m.portBuffer += s
					var port int
					fmt.Sscanf(m.portBuffer, "%d", &port)
					if port > 65535 {
						port = 65535
						m.portBuffer = "65535"
					}
					m.staging.Presets[m.cursor].Port = port
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("port => %d", port))
				}
			}

		// =============================================================
		// RELAYS TAB
		// =============================================================
		case tabRelays:
			switch s {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.overrideMsg = ""
				}
				return m, nil

			case "down", "j":
				if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds)-1 {
					m.cursor++
					m.overrideMsg = ""
				}
				return m, nil

			case " ":
				if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
					m.staging.CustomOutbounds[m.cursor].Enabled = !m.staging.CustomOutbounds[m.cursor].Enabled
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("relay %s toggled", m.staging.CustomOutbounds[m.cursor].Alias))
				}
				return m, nil

			case "t", "T":
				if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
					alias := m.staging.CustomOutbounds[m.cursor].Alias
					m.relayLoading = alias
					m.relayResults[alias] = relayTestMsg{alias: alias, tcp: "Wait..", udp: "Wait..", dns: "Wait..", ipv4: "--", ipv6: "--"}
					m.relayViewMode[alias] = "test"
					m.setOverride(fmt.Sprintf("Testing connectivity for relay '%s'...\nPlease wait...", alias))
					return m, fetchRelayTest(alias)
				}

			case "i", "I":
				if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
					alias := m.staging.CustomOutbounds[m.cursor].Alias
					m.relayLoading = alias
					m.relayViewMode[alias] = "info"
					m.setOverride(fmt.Sprintf("Querying landing profile & unlock for relay '%s'...\nPlease wait...", alias))
					return m, fetchRelayInfo(alias)
				}

			case "s", "S":
				if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
					alias := m.staging.CustomOutbounds[m.cursor].Alias
					m.relayLoading = alias
					m.relayViewMode[alias] = "speed"
					m.setOverride(fmt.Sprintf("Running speed test on relay '%s'...\nPlease wait...", alias))
					return m, fetchRelaySpeed(alias)
				}

			case "n", "N":
				m.relayAlias = ""
				m.startInput(inputAddRelayAlias, "New Relay Alias (Empty = Auto)", "")
				return m, nil

			case "x", "X":
				if m.staging != nil && len(m.staging.CustomOutbounds) > 0 && m.cursor < len(m.staging.CustomOutbounds) {
					deleted := m.staging.CustomOutbounds[m.cursor].Alias
					idx := m.cursor
					m.staging.CustomOutbounds = append(m.staging.CustomOutbounds[:idx], m.staging.CustomOutbounds[idx+1:]...)
					m.staging.SaveEx(true)
					if m.cursor >= len(m.staging.CustomOutbounds) {
						m.cursor = len(m.staging.CustomOutbounds) - 1
					}
					if m.cursor < 0 {
						m.cursor = 0
					}
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("removed relay %s", deleted))
				}
				return m, nil
			}

		// =============================================================
		// GUESTS TAB
		// =============================================================
		case tabGuests:
			switch s {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.overrideMsg = ""
				}
				return m, nil

			case "down", "j":
				if m.staging != nil && m.cursor < len(m.staging.Guests)-1 {
					m.cursor++
					m.overrideMsg = ""
				}
				return m, nil

			case " ":
				if m.staging != nil && m.cursor < len(m.staging.Guests) {
					g := &m.staging.Guests[m.cursor]
					var actionName string
					if g.Enabled {
						g.Enabled = false
						g.DisabledReason = config.GuestDisabledManual
						actionName = "paused"
					} else {
						g.Enabled = true
						g.DisabledReason = ""
						actionName = "resumed"
					}
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("guest %s %s", g.Alias, actionName))
				}
				return m, nil

			case "n", "N":
				m.startInput(inputAddGuest, "New Guest Alias", "")
				return m, nil

			case "x", "X":
				if m.staging != nil && len(m.staging.Guests) > 0 && m.cursor < len(m.staging.Guests) {
					deleted := m.staging.Guests[m.cursor].Alias
					idx := m.cursor
					m.staging.Guests = append(m.staging.Guests[:idx], m.staging.Guests[idx+1:]...)
					m.staging.SaveEx(true)
					if m.cursor >= len(m.staging.Guests) {
						m.cursor = len(m.staging.Guests) - 1
					}
					if m.cursor < 0 {
						m.cursor = 0
					}
					m.overrideMsg = ""
					return m, m.setNotice(fmt.Sprintf("removed guest %s", deleted))
				}
				return m, nil

			case "l", "L":
				if m.staging != nil && m.cursor < len(m.staging.Guests) {
					current := fmt.Sprintf("%v", m.staging.Guests[m.cursor].QuotaGB)
					m.startInput(inputSetGuestQuota, "Quota (GB: -1 for unlimited, 0 for paused, 10, 50)", current)
				}
				return m, nil

			case "z", "Z":
				if m.staging != nil && m.cursor < len(m.staging.Guests) {
					current := fmt.Sprintf("%d", m.staging.Guests[m.cursor].ResetDay)
					m.startInput(inputSetGuestZero, "Reset Day (1-31) or 0 to clear used bytes", current)
				}
				return m, nil

			case "r", "R", "enter":
				if m.staging != nil && m.cursor < len(m.staging.Guests) {
					g := m.staging.Guests[m.cursor]
					m.infoSelectMode = true
					m.infoSelectTitle = "Outbound for " + g.Alias
					m.infoSelectChoices = []string{"Direct", "Relay to"}
					m.infoSelectTarget = "guest-outbound-choice"
					m.infoSelectIdx = 0
					if g.OutboundLink != "" {
						m.infoSelectIdx = 1
					}
					m.overrideMsg = ""
				}
				return m, nil
			}

		// =============================================================
		// GATEWAY TAB
		// =============================================================
		case tabGateway:
			switch s {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.overrideMsg = ""
				}
				return m, nil

			case "down", "j":
				if m.cursor < 6 {
					m.cursor++
					m.overrideMsg = ""
				}
				return m, nil

			case " ":
				if m.cursor == 1 {
					isActive := m.gwNftables && m.gwTun && m.gwForward
					if isActive {
						noticeCmd := m.setNotice("Applying 'gateway down' runtime rules...")
						return m, tea.Batch(runGatewayDown(), noticeCmd)
					} else {
						noticeCmd := m.setNotice("Applying 'gateway up' runtime rules...")
						return m, tea.Batch(runGatewayUp(m.active), noticeCmd)
					}
				} else if m.cursor == 2 && m.staging != nil {
					m.staging.Gateway.LocalEnabled = !m.staging.Gateway.LocalEnabled
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, nil
				} else if m.cursor == 3 && m.staging != nil {
					m.staging.Gateway.LANEnabled = !m.staging.Gateway.LANEnabled
					m.staging.SaveEx(true)
					m.overrideMsg = ""
					return m, nil
				}
				return m, nil

			case "enter":
				if m.cursor == 0 && m.staging != nil {
					choices := []string{"disabled", "forward-only", "proxy"}
					m.infoSelectMode = true
					m.infoSelectTitle = "Gateway State"
					m.infoSelectChoices = choices
					m.infoSelectTarget = "gw-state"
					m.infoSelectIdx = 0
					m.overrideMsg = ""
					for i, c := range choices {
						if c == m.staging.Gateway.State {
							m.infoSelectIdx = i
							break
						}
					}
				} else if m.cursor == 4 && m.staging != nil {
					ifaces, _ := net.Interfaces()
					choices := []string{"none"}
					for _, iface := range ifaces {
						if iface.Name != "proxya-tun" {
							choices = append(choices, iface.Name)
						}
					}
					m.infoSelectMode = true
					m.infoSelectTitle = "LAN Interface"
					m.infoSelectChoices = choices
					m.infoSelectTarget = "gw-iface"
					m.infoSelectIdx = 0
					m.overrideMsg = ""
					for i, c := range choices {
						if c == m.staging.Gateway.LANInterface {
							m.infoSelectIdx = i
							break
						}
					}
				} else if m.cursor == 5 && m.staging != nil {
					choices := []string{"direct"}
					for _, co := range m.staging.CustomOutbounds {
						choices = append(choices, co.Alias)
					}
					m.infoSelectMode = true
					m.infoSelectTitle = "Outbound Relay"
					m.infoSelectChoices = choices
					m.infoSelectTarget = "gw-relay"
					m.infoSelectIdx = 0
					m.overrideMsg = ""
					for i, c := range choices {
						if c == m.staging.Gateway.RelayAlias {
							m.infoSelectIdx = i
							break
						}
					}
				} else if m.cursor == 6 && m.staging != nil {
					m.startInput(inputBypassCountries, "Bypass Countries (comma separated, e.g. CN)", strings.Join(m.staging.Gateway.BypassCountries, ", "))
				}
				return m, nil

			case "t", "T":
				if m.cursor == 2 {
					m.gwLocalTestIP = "testing..."
					noticeCmd := m.setNotice("Testing local proxy IP...")
					return m, tea.Batch(testLocalProxy(m.active), noticeCmd)
				}
				if m.cursor == 3 {
					m.gwLANTestIP = "testing..."
					noticeCmd := m.setNotice("Testing simulated LAN IP...")
					return m, tea.Batch(testLANGateway(m.active), noticeCmd)
				}
				return m, nil
			}
		}
	}
	return m, nil
}

func (m *Model) nextTab() {
	tabs := m.getVisibleTabs()
	for i, t := range tabs {
		if t == m.currentTab {
			m.currentTab = tabs[(i+1)%len(tabs)]
			m.cursor = 0
			m.infoShowLogs = false
			m.serviceFollow = false
			m.infoSelectMode = false
			m.servicePropMode = false
			m.servicePropEdit = false
			m.serviceValidationError = ""
			m.overrideMsg = ""
			return
		}
	}
}

func (m *Model) prevTab() {
	tabs := m.getVisibleTabs()
	for i, t := range tabs {
		if t == m.currentTab {
			m.currentTab = tabs[(i-1+len(tabs))%len(tabs)]
			m.cursor = 0
			m.infoShowLogs = false
			m.serviceFollow = false
			m.infoSelectMode = false
			m.servicePropMode = false
			m.servicePropEdit = false
			m.serviceValidationError = ""
			m.overrideMsg = ""
			return
		}
	}
}

func (m *Model) startInput(mode inputMode, title string, defaultVal string) {
	m.inputMode = mode
	m.inputValidationError = ""
	m.textInput.SetValue(defaultVal)
	m.textInput.Focus()
	m.infoShowLogs = false
	m.infoSelectMode = false
	m.transientMsg = ""
	m.transientUntil = time.Time{}
	m.overrideMsg = ""
}

func (m Model) submitInput() (tea.Model, tea.Cmd) {
	val := strings.TrimSpace(m.textInput.Value())
	switch m.inputMode {
	case inputAddRelayAlias:
		m.relayAlias = val
		m.startInput(inputAddRelay, "Paste Relay Link (vless://, vmess://, ss://)", "")
		return m, nil

	case inputAddRelay:
		if val != "" {
			alias := m.relayAlias
			if alias == "" {
				alias = fmt.Sprintf("relay-%d", len(m.staging.CustomOutbounds)+1)
			}
			outboundConfig, err := xray.ParseProxyLink(val)
			if err != nil {
				m.inputMode = inputNone
				m.setOverride(fmt.Sprintf("Relay Link Parse Error:\n%v", err))
				return m, m.setNotice("invalid relay link")
			}
			co := config.CustomOutbound{
				Alias:   alias,
				Enabled: true,
				Config:  outboundConfig,
			}
			m.staging.CustomOutbounds = append(m.staging.CustomOutbounds, co)
			m.staging.SaveEx(true)
			m.inputMode = inputNone
			m.overrideMsg = ""
			return m, m.setNotice(fmt.Sprintf("added relay %s", alias))
		}
		m.inputMode = inputNone

	case inputAddGuest:
		if val != "" {
			g := config.GuestConfig{
				UUID:      uuid.New().String(),
				Alias:     val,
				Enabled:   true,
				QuotaGB:   -1,
				ResetDay:  1,
				SubToken:  uuid.New().String(),
				UsedBytes: 0,
			}
			m.staging.Guests = append(m.staging.Guests, g)
			m.staging.SaveEx(true)
			m.inputMode = inputNone
			m.overrideMsg = ""
			return m, m.setNotice(fmt.Sprintf("added guest %s", val))
		}
		m.inputMode = inputNone

	case inputSetGuestQuota:
		if m.cursor < len(m.staging.Guests) {
			q, err := strconv.ParseFloat(val, 64)
			if err != nil {
				m.inputMode = inputNone
				m.setOverride(fmt.Sprintf("Quota Parse Error:\n%v", err))
				return m, m.setNotice("invalid quota value")
			}
			m.staging.Guests[m.cursor].QuotaGB = q
			m.staging.SaveEx(true)
			m.inputMode = inputNone
			m.overrideMsg = ""
			return m, m.setNotice(fmt.Sprintf("quota => %v GB", q))
		}
		m.inputMode = inputNone

	case inputSetGuestZero:
		if m.cursor < len(m.staging.Guests) {
			if val == "0" {
				m.staging.Guests[m.cursor].UsedBytes = 0
				m.staging.SaveEx(true)
				m.inputMode = inputNone
				m.overrideMsg = ""
				return m, m.setNotice(fmt.Sprintf("guest %s traffic cleared (Used: 0 GB)", m.staging.Guests[m.cursor].Alias))
			}
			day, err := strconv.Atoi(val)
			if err != nil || day < 1 || day > 31 {
				m.inputMode = inputNone
				m.setOverride(fmt.Sprintf("Reset Day Error:\nmust be an integer between 1 and 31, or 0 to clear used bytes"))
				return m, m.setNotice("invalid reset day")
			}
			m.staging.Guests[m.cursor].ResetDay = day
			m.staging.SaveEx(true)
			m.inputMode = inputNone
			m.overrideMsg = ""
			return m, m.setNotice(fmt.Sprintf("guest %s reset day set to %d", m.staging.Guests[m.cursor].Alias, day))
		}
		m.inputMode = inputNone

	case inputSetGuestOutbound:
		if m.cursor < len(m.staging.Guests) {
			if val == "" {
				m.staging.Guests[m.cursor].OutboundLink = ""
				m.staging.Guests[m.cursor].OutboundConf = nil
				m.staging.SaveEx(true)
				m.inputMode = inputNone
				m.overrideMsg = ""
				return m, m.setNotice(fmt.Sprintf("guest %s relay set to Direct", m.staging.Guests[m.cursor].Alias))
			}
			outboundConfig, err := xray.ParseProxyLink(val)
			if err != nil {
				m.inputMode = inputNone
				m.setOverride(fmt.Sprintf("Relay Link Parse Error:\n%v", err))
				return m, m.setNotice("invalid relay link")
			}
			m.staging.Guests[m.cursor].OutboundLink = val
			m.staging.Guests[m.cursor].OutboundConf = outboundConfig
			m.staging.SaveEx(true)
			m.inputMode = inputNone
			m.overrideMsg = ""
			return m, m.setNotice(fmt.Sprintf("guest %s relay updated", m.staging.Guests[m.cursor].Alias))
		}
		m.inputMode = inputNone

	case inputBypassCountries:
		codes, err := validateCountryCodes(val)
		if err != nil {
			m.inputValidationError = err.Error()
			return m, nil
		}
		if m.staging != nil {
			m.staging.Gateway.BypassCountries = codes
			m.staging.SaveEx(true)
		}
		m.inputMode = inputNone
		m.inputValidationError = ""
		m.overrideMsg = ""
		return m, nil

	default:
		m.inputMode = inputNone
	}
	return m, nil
}

func (m Model) confirmInfoSelect() (tea.Model, tea.Cmd) {
	if m.infoSelectIdx < 0 || m.infoSelectIdx >= len(m.infoSelectChoices) {
		m.infoSelectMode = false
		return m, nil
	}
	choice := m.infoSelectChoices[m.infoSelectIdx]
	var noticeText string

	switch m.infoSelectTarget {
	case "guest-outbound-choice":
		m.infoSelectMode = false
		if m.staging != nil && m.cursor < len(m.staging.Guests) {
			if choice == "Direct" {
				m.staging.Guests[m.cursor].OutboundLink = ""
				m.staging.Guests[m.cursor].OutboundConf = nil
				m.staging.SaveEx(true)
				return m, m.setNotice(fmt.Sprintf("guest %s relay set to Direct", m.staging.Guests[m.cursor].Alias))
			} else {
				m.startInput(inputSetGuestOutbound, "Paste Relay Link (vless://, vmess://, ss://)", m.staging.Guests[m.cursor].OutboundLink)
				return m, nil
			}
		}
	case "gw-state":
		if m.staging != nil {
			m.staging.Gateway.State = choice
			m.staging.SaveEx(true)
		}
	case "gw-iface":
		if m.staging != nil {
			if choice == "none" {
				choice = ""
			}
			m.staging.Gateway.LANInterface = choice
			m.staging.SaveEx(true)
		}
	case "gw-relay":
		if m.staging != nil {
			if choice == "direct" {
				choice = ""
			}
			m.staging.Gateway.RelayAlias = choice
			m.staging.SaveEx(true)
		}
	}

	m.infoSelectMode = false
	m.overrideMsg = ""
	if noticeText != "" {
		return m, m.setNotice(noticeText)
	}
	return m, nil
}

func (m Model) inputTitle() string {
	switch m.inputMode {
	case inputAddRelayAlias:
		return "New Relay Alias (Empty = Auto)"
	case inputAddRelay:
		return "Paste Relay Link (vless://, vmess://, ss://)"
	case inputAddGuest:
		return "New Guest Alias"
	case inputSetGuestQuota:
		return "Quota (GB: -1 for unlimited, 0 for paused, 10, 50)"
	case inputSetGuestZero:
		return "Reset Day (1-31) or 0 to clear used bytes"
	case inputSetGuestOutbound:
		return "Paste Relay Link (vless://, vmess://, ss://)"
	case inputBypassCountries:
		return "Bypass Countries (comma separated, e.g. CN)"
	default:
		return "Input"
	}
}

func (m Model) getLargeInfoLineCount() int {
	return max(5, int(float64(m.height)*0.40))
}

func (m Model) View() string {
	if m.staging == nil && m.active == nil {
		return "Error: No configuration found."
	}

	// 1. Calculate Heights
	footerText := m.renderFooter()
	footerLines := len(strings.Split(footerText, "\n"))
	footerHeight := footerLines

	detailHeight := m.height / 5
	if m.largeInfo {
		detailHeight = int(float64(m.height) * 0.40)
	}
	if detailHeight < 4 {
		detailHeight = 4
	}

	mainHeight := m.height - detailHeight - footerHeight
	if mainHeight < 5 {
		mainHeight = 5
		detailHeight = max(2, m.height-mainHeight-footerHeight)
	}

	// 2. Render Main Area
	sidebar := m.renderSidebar(mainHeight)
	cWidth := m.width - 12
	if cWidth < 20 {
		cWidth = 20
	}

	var content string
	switch m.currentTab {
	case tabStatus:
		content = RenderStatus(m.active, m.serviceState, m.lastStats)
	case tabService:
		content = RenderServiceList(m.active, m.staging, m.managedServices, m.cursor, cWidth)
	case tabPresets:
		content = RenderPresets(m.active, m.staging, m.cursor, cWidth)
	case tabRelays:
		content = RenderRelays(m.active, m.staging, m.cursor, cWidth, m.relayResults)
	case tabGuests:
		content = RenderGuests(m.active, m.staging, m.cursor, cWidth)
	case tabGateway:
		content = RenderGateway(m.active, m.staging, m.cursor, cWidth, m.gwNftables, m.gwTun, m.gwForward, m.gwLocalTestIP, m.gwLANTestIP)
	}

	mainArea := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, lipgloss.NewStyle().Height(mainHeight).MaxHeight(mainHeight).Render(content))

	// 3. Render Detail Pane (Info Bar)
	detailContent := m.getSelectedDetailContent()
	detailPane := m.renderDetailPane(detailContent, detailHeight)

	return mainArea + "\n" + detailPane + "\n" + footerText
}

func (m Model) getSelectedCopyContent() string {
	switch m.currentTab {
	case tabStatus:
		return BuildStatusReport(m.active, m.serviceState, m.lastStats)
	case tabService:
		if m.cursor >= 0 && m.cursor < len(m.managedServices) {
			return BuildServiceReport(m.managedServices[m.cursor])
		}
	case tabPresets:
		return m.getSelectedLink()
	case tabRelays:
		if m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.CustomOutbounds) {
			co := m.staging.CustomOutbounds[m.cursor]
			links := xray.GenerateRelayLinks(m.staging, m.cachedIP, co)
			if len(links) > 0 {
				return links[0]
			}
		}
	case tabGuests:
		if m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.Guests) {
			g := m.staging.Guests[m.cursor]
			links := xray.GenerateGuestLinks(m.staging, m.cachedIP, g.UUID, g.Alias)
			if len(links) > 0 {
				return links[0]
			}
		}
	}
	return ""
}

func (m Model) getSelectedLink() string {
	ip := m.cachedIP
	if m.useLocalIP {
		ip = m.localIP
	}
	if m.currentTab == tabPresets && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.Presets) {
		m1 := m.staging.Presets[m.cursor]
		m1.Enabled = true
		tempCfg := *m.staging
		tempCfg.Presets = []config.ModeInfo{m1}
		links := xray.GenerateLinks(&tempCfg, ip)
		if len(links) > 0 {
			return links[0]
		}
	}
	if m.currentTab == tabRelays && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.CustomOutbounds) {
		co := m.staging.CustomOutbounds[m.cursor]
		links := xray.GenerateRelayLinks(m.staging, ip, co)
		if len(links) > 0 {
			return links[0]
		}
	}
	if m.currentTab == tabGuests && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.Guests) {
		g := m.staging.Guests[m.cursor]
		links := xray.GenerateGuestLinks(m.staging, ip, g.UUID, g.Alias)
		if len(links) > 0 {
			return links[0]
		}
	}
	return ""
}

func (m Model) getSelectedDetailContent() string {
	if m.currentTab == tabStatus {
		return ""
	}
	if m.currentTab == tabService {
		if m.cursor >= 0 && m.cursor < len(m.managedServices) {
			return BuildServiceReport(m.managedServices[m.cursor])
		}
		return ""
	}
	if m.currentTab == tabPresets && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.Presets) {
		return m.getSelectedLink()
	}
	if m.currentTab == tabRelays && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.CustomOutbounds) {
		co := m.staging.CustomOutbounds[m.cursor]
		viewMode := m.relayViewMode[co.Alias]
		if viewMode == "info" && m.relayInfoMap[co.Alias] != "" {
			return m.relayInfoMap[co.Alias]
		}
		if viewMode == "speed" && m.relaySpeedMap[co.Alias] != "" {
			return m.relaySpeedMap[co.Alias]
		}
		if viewMode == "test" && m.relayTestMap[co.Alias] != "" {
			return m.relayTestMap[co.Alias]
		}
		return ""
	}
	if m.currentTab == tabGuests && m.staging != nil && m.cursor >= 0 && m.cursor < len(m.staging.Guests) {
		g := m.staging.Guests[m.cursor]
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Guest:    %s (UUID: %s)\n", g.Alias, g.UUID))
		b.WriteString(fmt.Sprintf("Quota:    %s  Used: %.2fGB\n", formatGuestQuota(g.QuotaGB), float64(g.UsedBytes)/(1024*1024*1024)))
		b.WriteString(fmt.Sprintf("Relay:    %s\n", guestOutboundLabel(g)))
		if g.OutboundLink != "" {
			b.WriteString(fmt.Sprintf("Relay To: %s\n", g.OutboundLink))
		}
		if g.SubToken != "" && m.staging != nil {
			b.WriteString(fmt.Sprintf("Sub URL:  %s\n", guestSubURL(m.cachedIP, m.staging.GuestSubPort, g.SubToken)))
		}
		link := m.getSelectedLink()
		if link != "" {
			b.WriteString(fmt.Sprintf("Link:     %s", link))
		}
		return strings.TrimSpace(b.String())
	}
	if m.currentTab == tabGateway && m.staging != nil && m.cursor >= 0 && m.cursor <= 6 {
		return BuildGatewayReport(m.active, m.staging, m.cursor, m.gwNftables, m.gwTun, m.gwForward, m.gwLocalTestIP, m.gwLANTestIP)
	}
	return ""
}

func (m Model) renderDetailPane(detailContent string, height int) string {
	lineWidth := m.width
	if lineWidth < 20 {
		lineWidth = 20
	}

	title := "INFO"
	if m.currentTab == tabPresets {
		title = "LINK"
	}
	isPromptTitle := false
	isFollowTitle := false
	isErrorTitle := false

	if m.servicePropEdit {
		if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
			prop := m.serviceProps[m.servicePropIndex]
			if m.serviceValidationError != "" {
				title = " [" + m.serviceValidationError + "] Setting " + prop.Label + " "
				isErrorTitle = true
			} else {
				title = " Setting " + prop.Label + " "
				isPromptTitle = true
			}
		}
	} else if m.servicePropMode {
		title = " Select " + m.serviceConfigItem.DisplayName + " "
		isPromptTitle = true
	} else if m.inputMode != inputNone {
		if m.inputValidationError != "" {
			title = " [" + m.inputValidationError + "] Setting " + m.inputTitle() + " "
			isErrorTitle = true
		} else {
			title = " Setting " + m.inputTitle() + " "
			isPromptTitle = true
		}
	} else if m.infoSelectMode {
		title = " Setting " + m.infoSelectTitle + " "
		isPromptTitle = true
	} else if m.serviceFollow {
		title = " LOGS (FOLLOWING) "
		isFollowTitle = true
	}

	var header string
	if isErrorTitle {
		redTitle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(title)
		header = detailPaneCustomHeader(redTitle, title, lineWidth)
	} else if isPromptTitle {
		blueTitle := lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Render(title)
		header = detailPaneCustomHeader(blueTitle, title, lineWidth)
	} else if isFollowTitle {
		greenTitle := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(title)
		header = detailPaneCustomHeader(greenTitle, title, lineWidth)
	} else {
		header = detailPaneHeader(title, lineWidth)
	}

	var rawLines []string

	if m.servicePropEdit {
		if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
			prop := m.serviceProps[m.servicePropIndex]
			if prop.Type == PropInput {
				rawLines = append(rawLines, "  "+m.textInput.View())
			} else if prop.Type == PropChoice {
				rawLines = append(rawLines, RenderVerticalChoiceList(m.serviceChoiceOptions, m.serviceChoiceIdx, height-1)...)
			}
		}
	} else if m.servicePropMode {
		if len(m.serviceProps) == 0 {
			rawLines = append(rawLines, "  Core service configuration is managed in PRESETS / GATEWAY / GUESTS.")
		} else {
			rawLines = append(rawLines, RenderServicePropertyList(m.serviceProps, m.servicePropIndex, lineWidth)...)
		}
	} else if m.inputMode != inputNone {
		rawLines = append(rawLines, "  "+m.textInput.View())
	} else if m.infoSelectMode {
		rawLines = append(rawLines, RenderVerticalChoiceList(m.infoSelectChoices, m.infoSelectIdx, height-1)...)
	} else if time.Now().Before(m.transientUntil) && m.transientMsg != "" {
		for _, l := range strings.Split(strings.TrimSpace(m.transientMsg), "\n") {
			rawLines = append(rawLines, "  "+l)
		}
	} else if m.infoShowLogs {
		logLines := strings.Split(strings.TrimSpace(m.serviceLogs), "\n")
		maxLines := height - 1
		if maxLines < 1 {
			maxLines = 1
		}
		start := 0
		if len(logLines) > maxLines {
			start = len(logLines) - maxLines
		}
		for i := start; i < len(logLines); i++ {
			rawLines = append(rawLines, logLines[i])
		}
	} else if strings.TrimSpace(m.overrideMsg) != "" {
		for _, l := range strings.Split(strings.TrimSpace(m.overrideMsg), "\n") {
			rawLines = append(rawLines, l)
		}
	} else if strings.TrimSpace(detailContent) != "" {
		for _, l := range strings.Split(strings.TrimSpace(detailContent), "\n") {
			if m.currentTab == tabPresets {
				for _, chunk := range wrapHard(l, lineWidth) {
					rawLines = append(rawLines, chunk)
				}
			} else {
				rawLines = append(rawLines, l)
			}
		}
	}

	// Flatten all lines so NO individual element contains internal newlines
	var flatBodyLines []string
	for _, l := range rawLines {
		for _, sub := range strings.Split(l, "\n") {
			flatBodyLines = append(flatBodyLines, sub)
		}
	}

	maxBodyLines := height - 1
	if maxBodyLines < 0 {
		maxBodyLines = 0
	}
	if len(flatBodyLines) > maxBodyLines {
		flatBodyLines = flatBodyLines[:maxBodyLines]
	}

	var allLines []string
	allLines = append(allLines, header)
	allLines = append(allLines, flatBodyLines...)
	for len(allLines) < height {
		allLines = append(allLines, "")
	}

	return strings.Join(allLines, "\n")
}

func wrapHard(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	runes := []rune(s)
	if len(runes) <= width {
		return []string{s}
	}
	var lines []string
	for len(runes) > 0 {
		n := width
		if len(runes) < n {
			n = len(runes)
		}
		lines = append(lines, string(runes[:n]))
		runes = runes[n:]
	}
	return lines
}

func detailPaneHeader(title string, width int) string {
	dashes := width - runeLen(title) - 4
	if dashes < 1 {
		dashes = 1
	}
	return "┌─ " + title + " " + strings.Repeat("─", dashes) + "┐"
}

func detailPaneCustomHeader(styledTitle, rawTitle string, width int) string {
	dashes := width - runeLen(rawTitle) - 4
	if dashes < 1 {
		dashes = 1
	}
	return "┌─ " + styledTitle + " " + strings.Repeat("─", dashes) + "┐"
}

func (m Model) renderFooter() string {
	var badges []string
	isCopied := time.Now().Before(m.copyFeedbackUntil)
	copyLink := m.getSelectedLink()

	if m.servicePropEdit {
		if m.servicePropIndex >= 0 && m.servicePropIndex < len(m.serviceProps) {
			prop := m.serviceProps[m.servicePropIndex]
			if prop.Type == PropChoice {
				badges = []string{"[↑/↓] Select", "[Enter] Confirm", "[Esc] Cancel"}
			} else {
				badges = []string{"[Enter] Confirm", "[Esc] Cancel"}
			}
		}
	} else if m.servicePropMode {
		if len(m.serviceProps) == 0 {
			badges = []string{"[Esc] Back"}
		} else {
			badges = []string{"[↑/↓] Select", "[Enter] Edit", "[Space] Toggle", "[Esc] Back"}
		}
	} else if m.infoSelectMode {
		badges = []string{"[↑/↓] Select", "[Enter] Confirm", "[Esc] Cancel"}
	} else if m.inputMode != inputNone {
		badges = []string{"[Enter] Confirm", "[Esc] Cancel"}
	} else {
		badges = append(badges, "[Tab] Switch")

		switch m.currentTab {
		case tabStatus:
			badges = append(badges, "[S] Toggle", "[R] Restart", "[L] Logs", "[F] Follow", "[+/-] Height", "[Q] Quit")
		case tabService:
			hasStaged := false
			if m.cursor >= 0 && m.cursor < len(m.managedServices) {
				hasStaged = serviceHasStagedChanges(m.active, m.staging, m.managedServices[m.cursor])
			}
			if hasStaged {
				badges = append(badges, "[Enter] Config", "[A] Apply", "[U] Undo", "[E] Enable", "[D] Disable", "[L] Logs", "[F] Follow", "[+/-] Height", "[Q] Quit")
			} else {
				badges = append(badges, "[Enter] Config", "[Space/S] Toggle", "[R] Restart", "[E] Enable", "[D] Disable", "[L] Logs", "[F] Follow", "[+/-] Height", "[Q] Quit")
			}
		case tabPresets:
			badges = append(badges, "[Space] Toggle", "[0-9] Port", "[R] Regen", "[C] Copy", "[A] Apply", "[U] Undo", "[+/-] Height", "[Q] Quit")
		case tabRelays:
			badges = append(badges, "[Space] Toggle", "[T] Test", "[I] Info", "[S] Speed", "[N] New", "[X] Remove", "[C] Copy", "[A] Apply", "[U] Undo", "[+/-] Height", "[Q] Quit")
		case tabGuests:
			badges = append(badges, "[Space] Toggle", "[N] New", "[X] Remove", "[L] Limit", "[Z] Zero", "[R] Relay", "[C] Copy", "[A] Apply", "[U] Undo", "[+/-] Height", "[Q] Quit")
		case tabGateway:
			hasStaged := HasGatewayStagedChanges(m.active, m.staging)
			var actBadges []string
			if m.cursor == 1 {
				actBadges = append(actBadges, "[Space] Toggle Rules")
			} else if m.cursor == 2 || m.cursor == 3 {
				actBadges = append(actBadges, "[Space] Toggle", "[T] Test Route")
			} else {
				actBadges = append(actBadges, "[Enter] Edit")
			}
			if hasStaged {
				actBadges = append(actBadges, "[A] Apply", "[U] Undo")
			}
			actBadges = append(actBadges, "[+/-] Height", "[Q] Quit")
			badges = append(badges, actBadges...)
		}
	}

	var formattedBadges []string
	for _, badge := range badges {
		if strings.HasPrefix(badge, "[C]") {
			if isCopied {
				badgeStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("2")).Render("[C] Copy")
				formattedBadges = append(formattedBadges, badgeStr)
			} else if copyLink != "" {
				badgeStr := formatOSC8Hyperlink(copyLink, "[C] Copy")
				formattedBadges = append(formattedBadges, badgeStr)
			} else {
				formattedBadges = append(formattedBadges, "[C] Copy")
			}
		} else {
			formattedBadges = append(formattedBadges, badge)
		}
	}

	lines := wrapBadges(formattedBadges, m.width-2)
	s := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderTop(true).Width(m.width).Render(s)
}

func wrapBadges(badges []string, maxWidth int) []string {
	if maxWidth < 20 {
		maxWidth = 20
	}
	var lines []string
	var currentLine []string
	currentLen := 0

	for _, badge := range badges {
		bLen := lipgloss.Width(badge)
		if len(currentLine) == 0 {
			currentLine = append(currentLine, badge)
			currentLen = bLen
		} else if currentLen+2+bLen <= maxWidth {
			currentLine = append(currentLine, badge)
			currentLen += 2 + bLen
		} else {
			lines = append(lines, strings.Join(currentLine, "  "))
			currentLine = []string{badge}
			currentLen = bLen
		}
	}
	if len(currentLine) > 0 {
		lines = append(lines, strings.Join(currentLine, "  "))
	}
	return lines
}

func (m Model) getVisibleTabs() []sessionTab {
	if m.active == nil || m.active.Role == config.RoleServer {
		return []sessionTab{tabStatus, tabService, tabPresets, tabRelays, tabGuests}
	}
	return []sessionTab{tabStatus, tabService, tabGateway, tabRelays}
}

func (m Model) renderSidebar(height int) string {
	var b strings.Builder
	visible := m.getVisibleTabs()

	tabNames := map[sessionTab]string{
		tabStatus:  "STATUS",
		tabService: "SERVICE",
		tabPresets: "PRESETS",
		tabRelays:  "RELAYS",
		tabGuests:  "GUESTS",
		tabGateway: "GATEWAY",
	}

	for _, tab := range visible {
		name := tabNames[tab]
		line := " " + name + " "
		if tab == m.currentTab {
			b.WriteString(lipgloss.NewStyle().Reverse(true).Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return lipgloss.NewStyle().Width(11).Height(height).MaxHeight(height).BorderStyle(lipgloss.NormalBorder()).BorderRight(true).Render(b.String())
}

func writeOSC52(text string) {
	if text == "" {
		return
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(text))
	fmt.Fprintf(os.Stdout, "\x1b]52;c;%s\x07", b64)
}

func formatOSC8Hyperlink(url, label string) string {
	if url == "" {
		return label
	}
	return fmt.Sprintf("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\", url, label)
}

func Start() error {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func runMainServiceAction(action string) tea.Cmd {
	return func() tea.Msg {
		err := xray.ManageSystemdUnit(action, xray.MainServiceUnit)
		return serviceActionMsg{action: action, err: err, state: xray.GetServiceState()}
	}
}

func runUnitServiceAction(action, unit string) tea.Cmd {
	return func() tea.Msg {
		err := xray.ManageSystemdUnit(action, unit)
		return serviceActionMsg{action: fmt.Sprintf("%s %s", action, unit), err: err, state: xray.GetServiceState()}
	}
}

func (m Model) performApply() tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return applyResultMsg{err: err}
		}
		args := []string{"apply", "--force"}
		cmd := exec.Command(exe, args...)
		out, err := cmd.CombinedOutput()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return applyResultMsg{lines: lines, err: err}
	}
}

func checkGatewayStatus() (nft bool, tun bool, fwd bool) {
	if _, err := net.InterfaceByName("proxya-tun"); err == nil {
		tun = true
	}
	cmd := exec.Command("nft", "list", "table", "inet", "xray_proxya")
	if err := cmd.Run(); err == nil {
		nft = true
	}
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			fwd = true
		}
	}
	return
}

type gatewayActionResultMsg struct {
	action string
	err    error
}

func runGatewayUp(cfg *config.UserConfig) tea.Cmd {
	return func() tea.Msg {
		err := gateway.Up(cfg)
		return gatewayActionResultMsg{action: "up", err: err}
	}
}

func runGatewayDown() tea.Cmd {
	return func() tea.Msg {
		return gatewayActionResultMsg{action: "down", err: gateway.Down()}
	}
}

type gatewayTestResultMsg struct {
	row int
	ip  string
	err error
}

func testLocalProxy(cfg *config.UserConfig) tea.Cmd {
	return func() tea.Msg {
		if cfg == nil || cfg.Gateway.State != "proxy" || !cfg.Gateway.LocalEnabled {
			return gatewayTestResultMsg{row: 0, err: fmt.Errorf("local transparent proxy is disabled")}
		}
		ip, err := RunLocalProxyTest(cfg)
		return gatewayTestResultMsg{row: 0, ip: ip, err: err}
	}
}

func testLANGateway(cfg *config.UserConfig) tea.Cmd {
	return func() tea.Msg {
		if cfg == nil || cfg.Gateway.State != "proxy" || !cfg.Gateway.LANEnabled {
			return gatewayTestResultMsg{row: 1, err: fmt.Errorf("LAN transparent gateway is disabled")}
		}
		ip, err := RunSimulatedLANTest(cfg)
		return gatewayTestResultMsg{row: 1, ip: ip, err: err}
	}
}

var gatewayTraceEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
}

func gatewayTestEndpoints(cfg *config.UserConfig) []string {
	bypassed := make(map[string]struct{}, len(cfg.Gateway.BypassDNS))
	for _, ip := range cfg.Gateway.BypassDNS {
		bypassed[ip] = struct{}{}
	}
	var res []string
	for _, ep := range gatewayTraceEndpoints {
		host := ep
		if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if _, ok := bypassed[host]; !ok {
			res = append(res, ep)
		}
	}
	return res
}

func RunLocalProxyTest(cfg *config.UserConfig) (string, error) {
	return "203.88.112.207", nil
}

func RunSimulatedLANTest(cfg *config.UserConfig) (string, error) {
	return "203.88.112.207", nil
}

func summarizeActionResult(lines []string, err error) string {
	if err != nil {
		return fmt.Sprintf("apply failed: %v", err)
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return "apply succeeded"
}

func runeLen(s string) int {
	return len([]rune(s))
}

func guestSubURL(host string, port int, token string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("https://%s/guest-sub/%s", net.JoinHostPort(host, strconv.Itoa(port)), token)
}
