package tui

import (
	"fmt"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/applyops"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/sub"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
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
	inputSetGuestReset
	inputSetGuestOutbound
	inputRelayResolveDomain
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

type serviceLogsMsg struct {
	body string
	err  error
}

type publicIPMsg struct {
	ip string
}

type relayDetailMsg struct {
	alias string
	body  string
	err   error
}

type detailField struct {
	label string
	value string
}

type relayDetailData struct {
	title  string
	fields []detailField
}

type relayTestMsg struct {
	alias string
	tcp   string
	udp   string
	dns   string
	ipv4  string
	ipv6  string
}

type serviceDetailView int

const (
	serviceDetailOverview serviceDetailView = iota
	serviceDetailLogs
	serviceDetailRuntime
)

type Model struct {
	active        *config.UserConfig
	staging       *config.UserConfig
	currentTab    sessionTab
	cursor        int
	width         int
	height        int
	directStat    int64
	relayStat     int64
	coreActive    bool
	corePID       int
	lastStats     map[string]int64
	relayResults  map[string]relayTestMsg
	relayDetails  map[string]relayDetailData
	relayLoading  string
	portBuffer    string
	detailScroll  int
	statusNote    string
	cachedIP      string
	localIP       string
	useLocalIP    bool
	serviceState  xray.ServiceState
	serviceView   serviceDetailView
	serviceFollow bool
	serviceLogs   string
	relayAlias    string

	inputMode inputMode
	textInput textinput.Model

	gwNftables       bool
	gwTun            bool
	gwForward        bool
	gatewayInputMode int // 0: normal, 1: selecting LAN interface, 2: selecting Relay
	gatewayChoices   []string
	gatewayChoiceIdx int
	gwLocalTestIP    string
	gwLANTestIP      string
}

func tickStats(apiPort int) tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		active, pid := xray.GetXrayStatus()
		allStats, _ := xray.GetXrayStats(apiPort)
		summary := trafficstats.Summarize(allStats)
		return statsMsg{direct: summary.Direct, relay: summary.Relay, active: active, pid: pid, allStats: allStats, service: xray.GetServiceState()}
	})
}

func (m Model) performApply(applyGatewayUp bool) tea.Cmd {
	return func() tea.Msg {
		lines, err := applyops.ApplyPending(applyops.Options{})
		if err == nil && applyGatewayUp {
			cfg, loadErr := config.LoadConfig()
			if loadErr == nil {
				err = gateway.ApplyFirewall(cfg)
				if err == nil {
					lines = append(lines, "✅ Gateway runtime rules applied successfully.")
				} else {
					lines = append(lines, fmt.Sprintf("❌ Failed to apply gateway runtime rules: %v", err))
				}
			} else {
				err = loadErr
			}
		}
		return applyResultMsg{lines: lines, err: err}
	}
}

func InitialModel() Model {
	active, _ := config.LoadConfig()
	staging, _ := config.LoadConfigEx(true)
	if staging == nil {
		staging = active
	}
	ti := textinput.New()
	ti.Width = 60
	localIP := utils.GetLocalIP()
	m := Model{
		active:        active,
		staging:       staging,
		currentTab:    tabStatus,
		width:         80,
		height:        24,
		relayResults:  make(map[string]relayTestMsg),
		relayDetails:  make(map[string]relayDetailData),
		cachedIP:      localIP,
		localIP:       localIP,
		serviceState:  xray.GetServiceState(),
		textInput:     ti,
		gwLocalTestIP: "",
		gwLANTestIP:   "",
	}
	if active != nil && active.Role == config.RoleGateway {
		m.gwNftables, m.gwTun, m.gwForward = checkGatewayStatus()
	}
	return m
}

func (m Model) Init() tea.Cmd {
	if m.active != nil {
		return tea.Batch(tickStats(m.active.APIInbound), fetchPublicIP())
	}
	return fetchPublicIP()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.active == nil {
		m.active, _ = config.LoadConfig()
	}
	switch msg := msg.(type) {
	case applyResultMsg:
		m.active, _ = config.LoadConfig()
		m.staging, _ = config.LoadConfigEx(true)
		if m.staging == nil {
			m.staging = m.active
		}
		m.detailScroll = 0
		m.statusNote = summarizeActionResult(msg.lines, msg.err)
	case serviceActionMsg:
		m.serviceState = msg.state
		m.detailScroll = 0
		m.statusNote = summarizeServiceActionResult(msg.action, msg.output, msg.err)
		if m.currentTab == tabService && m.serviceView == serviceDetailLogs {
			return m, refreshServiceLogs(32)
		}
	case serviceFollowTickMsg:
		if m.serviceFollow && m.currentTab == tabService && m.serviceView == serviceDetailLogs {
			return m, tea.Batch(refreshServiceLogs(32), tickServiceLogs())
		}
	case serviceLogsMsg:
		if msg.err != nil {
			m.serviceLogs = fmt.Sprintf("log read error: %v", msg.err)
		} else if strings.TrimSpace(msg.body) == "" {
			m.serviceLogs = "no log lines yet"
		} else {
			m.serviceLogs = strings.TrimRight(msg.body, "\n")
		}
	case publicIPMsg:
		if strings.TrimSpace(msg.ip) != "" {
			m.cachedIP = msg.ip
		}
	case statsMsg:
		m.directStat, m.relayStat, m.coreActive, m.corePID, m.lastStats = msg.direct, msg.relay, msg.active, msg.pid, msg.allStats
		m.serviceState = msg.service
		if m.active != nil && m.active.Role == config.RoleGateway {
			m.gwNftables, m.gwTun, m.gwForward = checkGatewayStatus()
		}
		return m, tickStats(m.active.APIInbound)
	case gatewayActionResultMsg:
		if msg.err != nil {
			m.statusNote = fmt.Sprintf("❌ Gateway %s failed! View logs: tail -n 20 %s/xray.log", msg.action, config.GetConfigDir())
		} else {
			m.statusNote = fmt.Sprintf("✅ Gateway runtime rules applied (%s).", msg.action)
		}
		m.gwNftables, m.gwTun, m.gwForward = checkGatewayStatus()
		return m, nil
	case gatewayTestResultMsg:
		if msg.err != nil {
			m.statusNote = fmt.Sprintf("❌ Test failed: %v", msg.err)
			if msg.row == 0 {
				m.gwLocalTestIP = "fail"
			} else {
				m.gwLANTestIP = "fail"
			}
		} else {
			m.statusNote = "✅ Test completed successfully."
			if msg.row == 0 {
				m.gwLocalTestIP = msg.ip
			} else {
				m.gwLANTestIP = msg.ip
			}
		}
		return m, nil
	case relayDetailMsg:
		m.relayLoading = ""
		if msg.err != nil && !strings.HasPrefix(msg.body, "__test__\n") {
			m.statusNote = fmt.Sprintf("relay info failed: %v", msg.err)
		} else {
			if strings.HasPrefix(msg.body, "__test__\n") {
				m.relayResults[msg.alias] = parseRelayTestSummary(msg.alias, strings.TrimPrefix(msg.body, "__test__\n"))
				if msg.err != nil {
					m.statusNote = fmt.Sprintf("relay test finished with errors: %v", msg.err)
				} else {
					m.statusNote = "relay test updated"
				}
			} else if strings.HasPrefix(msg.body, "__speed__\n") {
				m.statusNote = "relay speed updated"
			} else if strings.HasPrefix(msg.body, "__probe__\n") {
				m.statusNote = "relay probe updated"
			} else if strings.HasPrefix(msg.body, "__resolve__\n") {
				m.statusNote = "relay resolve updated"
			} else {
				m.statusNote = "relay info updated"
			}
			m.relayDetails[msg.alias] = parseRelayDetailOutput(msg.alias, msg.body)
		}
	case relayTestMsg:
		m.relayResults[msg.alias] = msg
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		s := msg.String()
		if m.inputMode != inputNone {
			switch s {
			case "esc":
				m.relayAlias = ""
				m.inputMode = inputNone
				m.textInput.Reset()
				return m, nil
			case "enter":
				return m.submitInput()
			}
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			return m, cmd
		}
		if m.gatewayInputMode > 0 {
			switch s {
			case "esc":
				m.gatewayInputMode = 0
				m.statusNote = "Selection cancelled."
				return m, nil
			case "enter":
				if m.gatewayInputMode == 1 {
					m.staging.Gateway.LANInterface = m.gatewayChoices[m.gatewayChoiceIdx]
					if m.staging.Gateway.LANInterface == "none" {
						m.staging.Gateway.LANInterface = ""
					}
					m.staging.SaveEx(true)
					m.statusNote = "LAN Interface updated in staging."
				} else if m.gatewayInputMode == 2 {
					m.staging.Gateway.RelayAlias = m.gatewayChoices[m.gatewayChoiceIdx]
					if m.staging.Gateway.RelayAlias == "direct" {
						m.staging.Gateway.RelayAlias = ""
					}
					m.staging.SaveEx(true)
					m.statusNote = "Outbound Relay updated in staging."
				} else if m.gatewayInputMode == 3 {
					m.staging.Gateway.State = m.gatewayChoices[m.gatewayChoiceIdx]
					m.staging.SaveEx(true)
					m.statusNote = "Gateway State updated in staging."
				}
				m.gatewayInputMode = 0
				return m, nil
			case "left":
				if m.gatewayChoiceIdx > 0 {
					m.gatewayChoiceIdx--
				}
				return m, nil
			case "right":
				if m.gatewayChoiceIdx < len(m.gatewayChoices)-1 {
					m.gatewayChoiceIdx++
				}
				return m, nil
			}
			return m, nil
		}

		switch s {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			visible := m.getVisibleTabs()
			idx := 0
			for i, t := range visible {
				if t == m.currentTab {
					idx = i
					break
				}
			}
			m.currentTab = visible[(idx+1)%len(visible)]
			m.cursor, m.portBuffer, m.detailScroll = 0, "", 0
		case "shift+tab":
			visible := m.getVisibleTabs()
			idx := 0
			for i, t := range visible {
				if t == m.currentTab {
					idx = i
					break
				}
			}
			m.currentTab = visible[(idx+len(visible)-1)%len(visible)]
			m.cursor, m.portBuffer, m.detailScroll = 0, "", 0
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			m.portBuffer, m.detailScroll = "", 0
		case "down", "j":
			max := 0
			if m.staging != nil {
				if m.currentTab == tabPresets {
					max = len(m.staging.Presets) - 1
				}
				if m.currentTab == tabRelays {
					max = len(m.staging.CustomOutbounds) - 1
				}
				if m.currentTab == tabGuests {
					max = len(m.staging.Guests) - 1
				}
				if m.currentTab == tabGateway {
					max = 5
				}
			}
			if m.cursor < max {
				m.cursor++
			}
			m.portBuffer, m.detailScroll = "", 0
		case "left":
			m.detailScroll -= 8
			if m.detailScroll < 0 {
				m.detailScroll = 0
			}
		case "right":
			m.detailScroll += 8
			maxScroll := detailMaxScroll(m.getSelectedDetailContent(), max(1, m.width-2))
			if m.currentTab == tabService && m.serviceView == serviceDetailLogs {
				maxScroll = m.currentServiceLogMaxScroll(max(1, m.width))
			}
			if m.detailScroll > maxScroll {
				m.detailScroll = maxScroll
			}
		case "u", "U":
			if m.currentTab == tabService {
				m.statusNote = "removing managed service..."
				return m, runServiceAction("uninstall", "service", "uninstall")
			}
			_ = applyops.ClearPending()
			m.active, _ = config.LoadConfig()
			m.staging, _ = config.LoadConfigEx(true)
			if m.staging == nil {
				m.staging = m.active
			}
			m.relayResults = make(map[string]relayTestMsg)
			m.detailScroll = 0
			m.statusNote = "staging reset"
		case "enter":
			if m.currentTab == tabGateway {
				if m.cursor == 0 {
					choices := []string{"disabled", "forward-only", "proxy"}
					m.gatewayInputMode = 3
					m.gatewayChoices = choices
					m.gatewayChoiceIdx = 0
					for i, c := range choices {
						if c == m.staging.Gateway.State {
							m.gatewayChoiceIdx = i
							break
						}
					}
				} else if m.cursor == 1 {
					isActive := m.gwNftables && m.gwTun && m.gwForward
					if isActive {
						m.statusNote = "Applying 'gateway down' runtime rules..."
						return m, runGatewayDown()
					} else {
						m.statusNote = "Applying 'gateway up' runtime rules..."
						return m, runGatewayUp(m.active)
					}
				} else if m.cursor == 2 {
					m.staging.Gateway.LocalEnabled = !m.staging.Gateway.LocalEnabled
					m.staging.SaveEx(true)
					m.statusNote = "Local proxy toggled"
				} else if m.cursor == 3 {
					m.staging.Gateway.LANEnabled = !m.staging.Gateway.LANEnabled
					m.staging.SaveEx(true)
					m.statusNote = "LAN gateway toggled"
				} else if m.cursor == 4 {
					ifaces, _ := net.Interfaces()
					choices := []string{"none"}
					for _, iface := range ifaces {
						if iface.Name != "proxya-tun" {
							choices = append(choices, iface.Name)
						}
					}
					m.gatewayInputMode = 1
					m.gatewayChoices = choices
					m.gatewayChoiceIdx = 0
					for i, c := range choices {
						if c == m.staging.Gateway.LANInterface {
							m.gatewayChoiceIdx = i
							break
						}
					}
				} else if m.cursor == 5 {
					choices := []string{"direct"}
					for _, co := range m.staging.CustomOutbounds {
						choices = append(choices, co.Alias)
					}
					m.gatewayInputMode = 2
					m.gatewayChoices = choices
					m.gatewayChoiceIdx = 0
					for i, c := range choices {
						if c == m.staging.Gateway.RelayAlias {
							m.gatewayChoiceIdx = i
							break
						}
					}
				}
				return m, nil
			}
		case "n", "N":
			if m.currentTab == tabRelays {
				m.relayAlias = ""
				m.startInput(inputAddRelayAlias, "relay alias (empty = auto)", "")
				return m, nil
			}
			if m.currentTab == tabGuests {
				m.startInput(inputAddGuest, "guest-alias", "")
				return m, nil
			}
		case "a", "A":
			if m.currentTab != tabService {
				return m, m.performApply(m.currentTab == tabGateway)
			}
		case "l", "L":
			if m.currentTab == tabService {
				m.serviceView = serviceDetailLogs
				m.serviceFollow = false
				m.detailScroll = 0
				m.statusNote = ""
				return m, refreshServiceLogs(32)
			} else {
				m.useLocalIP = !m.useLocalIP
				m.detailScroll = 0
			}
		case "b", "B":
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				alias := m.staging.CustomOutbounds[m.cursor].Alias
				m.relayLoading = alias
				m.statusNote = "probing local relay proxy..."
				return m, fetchRelayProbe(alias)
			}
		case "+", "=":
			if m.currentTab == tabGateway {
				if m.cursor == 0 {
					m.statusNote = "Applying 'gateway up' runtime rules..."
					return m, runGatewayUp(m.active)
				} else if m.cursor == 1 {
					m.staging.Gateway.LocalEnabled = true
					m.staging.SaveEx(true)
					m.statusNote = "Local proxy enabled"
				} else if m.cursor == 2 {
					m.staging.Gateway.LANEnabled = true
					m.staging.SaveEx(true)
					m.statusNote = "LAN gateway enabled"
				}
				return m, nil
			}
			if m.currentTab == tabPresets && m.staging != nil {
				m.staging.Presets[m.cursor].Enabled = true
				m.staging.SaveEx(true)
				m.statusNote = "preset enabled"
			}
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				m.staging.CustomOutbounds[m.cursor].Enabled = true
				m.staging.SaveEx(true)
				m.statusNote = "relay enabled"
			}
			if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) && s == "=" {
				if err := m.resumeGuest(); err != nil {
					m.statusNote = err.Error()
				} else {
					m.statusNote = "guest resumed"
				}
			}
		case "-":
			if m.currentTab == tabGateway {
				if m.cursor == 0 {
					m.statusNote = "Applying 'gateway down' runtime rules..."
					return m, runGatewayDown()
				} else if m.cursor == 1 {
					m.staging.Gateway.LocalEnabled = false
					m.staging.SaveEx(true)
					m.statusNote = "Local proxy disabled"
				} else if m.cursor == 2 {
					m.staging.Gateway.LANEnabled = false
					m.staging.SaveEx(true)
					m.statusNote = "LAN gateway disabled"
				}
				return m, nil
			}
			if m.currentTab == tabPresets && m.staging != nil {
				m.staging.Presets[m.cursor].Enabled = false
				m.staging.SaveEx(true)
				m.statusNote = "preset disabled"
			}
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				m.staging.CustomOutbounds[m.cursor].Enabled = false
				m.staging.SaveEx(true)
				m.statusNote = "relay disabled"
			}
			if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) {
				m.pauseGuest()
				m.statusNote = "guest paused"
			}
		case "d", "D":
			if m.currentTab == tabRelays && m.staging != nil && len(m.staging.CustomOutbounds) > 0 {
				idx := m.cursor
				m.staging.CustomOutbounds = append(m.staging.CustomOutbounds[:idx], m.staging.CustomOutbounds[idx+1:]...)
				m.staging.SaveEx(true)
				m.statusNote = "relay deleted"
				if m.cursor >= len(m.staging.CustomOutbounds) {
					m.cursor = len(m.staging.CustomOutbounds) - 1
				}
				if m.cursor < 0 {
					m.cursor = 0
				}
			}
			if m.currentTab == tabGuests && m.staging != nil && len(m.staging.Guests) > 0 {
				idx := m.cursor
				m.staging.Guests = append(m.staging.Guests[:idx], m.staging.Guests[idx+1:]...)
				m.staging.SaveEx(true)
				m.statusNote = "guest deleted"
				if m.cursor >= len(m.staging.Guests) {
					m.cursor = len(m.staging.Guests) - 1
				}
				if m.cursor < 0 {
					m.cursor = 0
				}
			}
		case "t", "T":
			if m.currentTab == tabGateway {
				if m.cursor == 1 {
					m.gwLocalTestIP = "testing..."
					m.statusNote = "Testing local proxy IP..."
					return m, testLocalProxy(m.active)
				}
				if m.cursor == 2 {
					m.gwLANTestIP = "testing..."
					m.statusNote = "Testing simulated LAN IP (this takes a few seconds)..."
					return m, testLANGateway(m.active)
				}
				return m, nil
			}
			if m.currentTab == tabService {
				m.statusNote = "stopping service..."
				m.serviceView = serviceDetailRuntime
				return m, runServiceAction("stop", "stop")
			}
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				co := m.staging.CustomOutbounds[m.cursor]
				m.relayLoading = co.Alias
				m.relayResults[co.Alias] = relayTestMsg{alias: co.Alias, tcp: "Wait..", udp: "Wait..", dns: "Wait..", ipv4: "--", ipv6: "--"}
				m.statusNote = "testing relay..."
				return m, fetchRelayTest(co.Alias)
			}
		case "v", "V":
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				alias := m.staging.CustomOutbounds[m.cursor].Alias
				m.relayLoading = alias
				m.statusNote = "running relay speed test..."
				return m, fetchRelaySpeed(alias)
			}
		case "i", "I":
			if m.currentTab == tabService {
				m.statusNote = "installing managed service..."
				m.serviceView = serviceDetailRuntime
				return m, runServiceAction("install", "service", "install")
			}
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				alias := m.staging.CustomOutbounds[m.cursor].Alias
				m.relayLoading = alias
				m.statusNote = "querying relay info..."
				return m, fetchRelayDetail(alias)
			}
		case "r", "R":
			if m.currentTab == tabService {
				m.statusNote = "restarting service..."
				m.serviceView = serviceDetailRuntime
				return m, runServiceAction("restart", "restart")
			}
			if m.currentTab == tabPresets && m.staging != nil && m.cursor < len(m.staging.Presets) {
				m.staging.Presets[m.cursor].RegenFlag = !m.staging.Presets[m.cursor].RegenFlag
				m.staging.SaveEx(true)
				m.statusNote = "regen flag toggled"
			} else if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				m.startInput(inputRelayResolveDomain, "domain to resolve", "openai.com")
				return m, nil
			} else if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) {
				current := fmt.Sprintf("%d", m.staging.Guests[m.cursor].ResetDay)
				m.startInput(inputSetGuestReset, "reset day 1-31", current)
				return m, nil
			}
		case "o", "O":
			if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) {
				current := m.staging.Guests[m.cursor].OutboundLink
				if current == "" {
					current = "direct"
				}
				m.startInput(inputSetGuestOutbound, "proxy link or direct", current)
				return m, nil
			}
		case "e", "E":
			if m.currentTab == tabGuests {
				if err := m.enableGuestSub(); err != nil {
					m.statusNote = err.Error()
				} else {
					m.statusNote = "guest sub enabled"
				}
			}
		case "x", "X":
			if m.currentTab == tabGuests {
				if err := m.disableGuestSub(); err != nil {
					m.statusNote = err.Error()
				} else {
					m.statusNote = "guest sub disabled"
				}
			}
		case "y", "Y":
			if m.currentTab == tabGuests {
				if err := m.rotateGuestSub(); err != nil {
					m.statusNote = err.Error()
				} else {
					m.statusNote = "guest sub rotated"
				}
			}
		case "backspace":
			if m.currentTab == tabPresets && len(m.portBuffer) > 0 {
				m.portBuffer = m.portBuffer[:len(m.portBuffer)-1]
				var port int
				fmt.Sscanf(m.portBuffer, "%d", &port)
				m.staging.Presets[m.cursor].Port = port
				m.staging.SaveEx(true)
				m.statusNote = fmt.Sprintf("port => %d", port)
			}
		case "delete":
			if m.currentTab == tabPresets {
				m.portBuffer, m.staging.Presets[m.cursor].Port = "", 0
				m.staging.SaveEx(true)
				m.statusNote = "port cleared"
			}
		case "s", "S":
			if m.currentTab == tabService {
				m.statusNote = "starting service..."
				m.serviceView = serviceDetailRuntime
				return m, runServiceAction("start", "start")
			}
			title, body := m.currentShowView()
			if strings.TrimSpace(body) == "" {
				m.statusNote = "nothing to show"
				return m, nil
			}
			cmd := exec.Command("bash", "-lc", buildShowScript(title, body))
			return m, tea.ExecProcess(cmd, func(err error) tea.Msg { return nil })
		case "g", "G":
			if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) {
				current := fmt.Sprintf("%v", m.staging.Guests[m.cursor].QuotaGB)
				m.startInput(inputSetGuestQuota, "quota: -1 / 0 / 5 / reset", current)
				return m, nil
			}
		case "c", "C":
			if m.currentTab == tabService {
				m.statusNote = ""
				if m.serviceView == serviceDetailLogs {
					return m, tea.Batch(refreshServiceState(), refreshServiceLogs(32))
				}
				return m, refreshServiceState()
			}
		case "m", "M":
			if m.currentTab == tabService {
				m.serviceView = nextServiceDetailView(m.serviceView)
				if m.serviceView != serviceDetailLogs {
					m.serviceFollow = false
				}
				m.detailScroll = 0
			}
		case "f", "F":
			if m.currentTab == tabService {
				m.serviceView = serviceDetailLogs
				m.serviceFollow = !m.serviceFollow
				m.detailScroll = 0
				m.statusNote = ""
				if m.serviceFollow {
					return m, tea.Batch(refreshServiceLogs(32), tickServiceLogs())
				}
				return m, refreshServiceLogs(32)
			}
		case "w", "W":
			if m.currentTab == tabGuests {
				title, body := m.currentGuestSubPrintView()
				if body == "" {
					m.statusNote = "guest sub not enabled"
					return m, nil
				}
				cmd := exec.Command("bash", "-lc", buildShowScript(title, body))
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg { return nil })
			}
		default:
			if m.currentTab == tabPresets && s >= "0" && s <= "9" {
				if len(m.portBuffer) >= 5 {
					m.portBuffer = ""
				}
				m.portBuffer += s
				var port int
				fmt.Sscanf(m.portBuffer, "%d", &port)
				m.staging.Presets[m.cursor].Port = port
				m.staging.SaveEx(true)
				m.statusNote = fmt.Sprintf("port => %d", port)
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.staging == nil {
		return "Error: No config found."
	}
	if m.inputMode != inputNone {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			lipgloss.NewStyle().Padding(1, 2).BorderStyle(lipgloss.NormalBorder()).
				Render(m.inputTitle()+"\n\n"+m.textInput.View()+"\n\n[Enter] Confirm  [Esc] Cancel"))
	}

	// 1. Calculate Heights
	footerHeight := 2 // TopBorder(1) + Text(1)

	detailContent := m.getSelectedDetailContent()
	detailHeight := m.height / 5
	if detailHeight < 4 {
		detailHeight = 4
	}

	mainHeight := m.height - detailHeight - footerHeight
	if mainHeight < 5 {
		mainHeight = 5
		detailHeight = m.height - mainHeight - footerHeight
		if detailHeight < 0 {
			detailHeight = 0
		}
	}

	// 2. Render Components
	sidebar := m.renderSidebar(mainHeight)
	cWidth := m.width - 12
	var content string
	switch m.currentTab {
	case tabService:
		content = RenderService(m.serviceState, cWidth)
	case tabPresets:
		content = RenderPresets(m.active, m.staging, m.cursor, cWidth)
	case tabStatus:
		content = RenderStatus(m.active, m.coreActive, m.corePID, m.lastStats)
	case tabRelays:
		content = RenderRelays(m.active, m.staging, m.cursor, cWidth, m.relayResults)
	case tabGuests:
		content = RenderGuests(m.active, m.staging, m.cursor, cWidth)
	case tabGateway:
		content = RenderGateway(m.active, m.staging, m.cursor, cWidth, m.gwNftables, m.gwTun, m.gwForward, m.gwLocalTestIP, m.gwLANTestIP)
	}

	// Important: mainArea must NOT have internal newlines at the end
	mainArea := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, lipgloss.NewStyle().Height(mainHeight).MaxHeight(mainHeight).Render(content))

	detailPane := m.renderDetailPane(detailContent, detailHeight)
	footer := renderFooter(m.currentTab, m.width)

	// Combine components without ANY extra \n between them.
	// Each component must have exactly its calculated height.
	return mainArea + "\n" + detailPane + "\n" + footer
}

func (m Model) getSelectedDetailContent() string {
	if m.currentTab == tabService {
		return m.currentServiceDetailContent()
	}
	if m.currentTab == tabStatus {
		return strings.Join([]string{
			"Xray-Proxya",
			"",
			"Project:",
			"https://github.com/AiLing2416/xray-proxya",
		}, "\n")
	}
	ip := m.cachedIP
	if m.useLocalIP {
		ip = m.localIP
	}
	if m.currentTab == tabPresets && m.staging != nil && m.cursor < len(m.staging.Presets) {
		idx := m.cursor
		m1 := m.staging.Presets[idx]
		isMod := m1.RegenFlag
		if !isMod && m.active != nil && idx < len(m.active.Presets) {
			a := m.active.Presets[idx]
			if m1.Port != a.Port || m1.Path != a.Path || m1.SNI != a.SNI || m1.Enabled != a.Enabled {
				isMod = true
			}
		}
		if isMod {
			return "[A] apply changes to regenerate link"
		}
		tempCfg := *m.staging
		tempCfg.Presets = []config.ModeInfo{m1}
		links := xray.GenerateLinks(&tempCfg, ip)
		if len(links) > 0 {
			return links[0]
		}
		return ""
	}
	if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
		relay := m.staging.CustomOutbounds[m.cursor]
		if m.relayLoading == relay.Alias {
			return "Loading relay info..."
		}
		if detail, ok := m.relayDetails[relay.Alias]; ok && len(detail.fields) > 0 {
			return "__relay_detail__"
		}
		return buildRelaySummary(relay)
	}
	if m.currentTab == tabGuests && m.staging != nil && m.cursor < len(m.staging.Guests) {
		guest := m.staging.Guests[m.cursor]
		links := xray.GenerateGuestLinks(m.staging, ip, guest.UUID, guest.Alias)
		if len(links) > 0 {
			return links[0]
		}
	}
	if m.currentTab == tabGateway {
		if m.gatewayInputMode > 0 {
			return m.renderGatewayChoices()
		}
		return ""
	}
	return ""
}

func (m Model) getSelectedLink() string {
	content := m.getSelectedDetailContent()
	if strings.HasPrefix(content, "[A] ") {
		return ""
	}
	return content
}

func (m Model) renderDetailPane(detailContent string, height int) string {
	lineWidth := m.width
	if lineWidth < 20 {
		lineWidth = 20
	}
	if m.currentTab == tabService && m.serviceView == serviceDetailLogs {
		return m.renderServiceLogPane(height, lineWidth)
	}
	if detail := m.currentRelayDetailData(); detail != nil {
		return m.renderRelayDetailGrid(*detail, height, lineWidth)
	}
	title := " LINK "
	if m.useLocalIP {
		title = " LINK [LOCAL] "
	} else {
		title = " LINK [PUBLIC] "
	}
	contentWidth := lineWidth - 2
	if contentWidth < 1 {
		contentWidth = 1
	}
	if strings.Contains(detailContent, "\n") {
		return m.renderMultilineDetailPane(detailContent, height, lineWidth)
	}
	effectiveScroll := m.detailScroll
	visible, maxScroll := clipHorizontal(detailContent, effectiveScroll, contentWidth)
	if effectiveScroll > maxScroll {
		effectiveScroll = maxScroll
		visible, maxScroll = clipHorizontal(detailContent, effectiveScroll, contentWidth)
	}

	note := m.statusNote
	if note == "" && m.currentTab == tabService {
		note = "[L] logs  [F] follow  [M] cycle detail  [C] refresh"
	}

	header := detailPaneHeader(title, lineWidth, fmt.Sprintf("[\u2190/\u2192] scroll  offset:%d/%d", effectiveScroll, maxScroll))
	lines := []string{
		header,
		padOrTrim(visible, lineWidth),
	}
	if note != "" {
		lines = append(lines, padOrTrim(note, lineWidth))
	}
	if height < len(lines) {
		height = len(lines)
	}
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	for i := len(lines); i < height; i++ {
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) currentRelayDetailData() *relayDetailData {
	if m.currentTab != tabRelays || m.staging == nil || m.cursor < 0 || m.cursor >= len(m.staging.CustomOutbounds) {
		return nil
	}
	alias := m.staging.CustomOutbounds[m.cursor].Alias
	detail, ok := m.relayDetails[alias]
	if !ok || len(detail.fields) == 0 {
		return nil
	}
	return &detail
}

func (m Model) renderRelayDetailGrid(detail relayDetailData, height int, lineWidth int) string {
	title := " RELAY DETAIL "
	if detail.title != "" {
		title = " RELAY DETAIL [" + detail.title + "] "
	}
	note := m.statusNote
	if note == "" {
		note = "[I] refresh relay info"
	}

	contentRows := height - 2
	if contentRows < 1 {
		contentRows = 1
	}
	maxCols := lineWidth / 26
	if maxCols < 1 {
		maxCols = 1
	}
	cols := (len(detail.fields) + contentRows - 1) / contentRows
	if cols < 1 {
		cols = 1
	}
	if cols > maxCols {
		cols = maxCols
	}
	colWidth := (lineWidth - (cols-1)*2) / cols
	if colWidth < 12 {
		colWidth = 12
	}
	lines := []string{detailPaneHeader(title, lineWidth, "")}

	shown := 0
	for row := 0; row < contentRows; row++ {
		cells := make([]string, 0, cols)
		for col := 0; col < cols; col++ {
			idx := row*cols + col
			if idx >= len(detail.fields) {
				cells = append(cells, strings.Repeat(" ", colWidth))
				continue
			}
			shown++
			field := detail.fields[idx]
			cell := field.label + ": " + field.value
			cells = append(cells, padOrTrim(cell, colWidth))
		}
		lines = append(lines, padOrTrim(strings.Join(cells, "  "), lineWidth))
	}
	if shown < len(detail.fields) {
		note = fmt.Sprintf("%s  +%d more", note, len(detail.fields)-shown)
	}
	lines = append(lines, padOrTrim(note, lineWidth))

	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	for i := len(lines); i < height; i++ {
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) renderMultilineDetailPane(detailContent string, height int, lineWidth int) string {
	title := " DETAIL "
	switch m.currentTab {
	case tabService:
		title = " SERVICE DETAIL "
	case tabRelays:
		title = " RELAY DETAIL "
	case tabGuests:
		title = " GUEST DETAIL "
	case tabStatus:
		title = " ABOUT "
	}
	note := m.statusNote
	lines := []string{detailPaneHeader(title, lineWidth, "")}
	contentLines := strings.Split(detailContent, "\n")
	maxContentLines := height - 2
	if maxContentLines < 1 {
		maxContentLines = 1
	}
	for i := 0; i < len(contentLines) && i < maxContentLines; i++ {
		lines = append(lines, padOrTrim(contentLines[i], lineWidth))
	}
	if len(contentLines) > maxContentLines {
		note = fmt.Sprintf("%s  +%d more", note, len(contentLines)-maxContentLines)
	}
	if note != "" {
		lines = append(lines, padOrTrim(note, lineWidth))
	}
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	for i := len(lines); i < height; i++ {
		b.WriteString("\n")
	}
	return b.String()
}

func detailPaneHeader(title string, width int, right string) string {
	if width < 1 {
		return ""
	}
	if right == "" {
		return padOrTrim(title+strings.Repeat("─", max(0, width-runeLen(title))), width)
	}
	right = " " + right
	leftWidth := width - runeLen(right)
	if leftWidth < runeLen(title) {
		leftWidth = runeLen(title)
	}
	left := title + strings.Repeat("─", max(0, leftWidth-runeLen(title)))
	return padOrTrim(left+right, width)
}

func (m Model) currentShowView() (string, string) {
	switch m.currentTab {
	case tabPresets:
		if body := m.currentPresetLinks(); body != "" {
			return "CURRENT PRESET LINKS", body
		}
	case tabRelays:
		if body := m.currentRelayLinks(); body != "" {
			return "CURRENT RELAY LINKS", body
		}
	case tabGuests:
		if body := m.currentGuestLinks(); body != "" {
			return "CURRENT GUEST LINKS", body
		}
	}
	return "", ""
}

func (m Model) currentGuestSubPrintView() (string, string) {
	if m.staging == nil || m.cursor < 0 || m.cursor >= len(m.staging.Guests) {
		return "", ""
	}
	guest := m.staging.Guests[m.cursor]
	if guest.SubToken == "" {
		return "", ""
	}
	host := m.cachedIP
	if m.useLocalIP {
		host = m.localIP
	}
	return "CURRENT GUEST SUB", buildGuestSubReport(m.staging, guest, host)
}

func (m Model) currentServiceDetailContent() string {
	switch m.serviceView {
	case serviceDetailRuntime:
		var lines []string
		lines = append(lines,
			fmt.Sprintf("Runtime Mode: %s", serviceRuntimeLabel(m.serviceState)),
			fmt.Sprintf("Init System: %s", m.serviceState.InitSystem),
			fmt.Sprintf("Control Mode: %s", m.serviceState.ControlMode),
			fmt.Sprintf("Installed: %s", yesNo(m.serviceState.UnitInstalled)),
			fmt.Sprintf("Active: %s", serviceActiveLabel(m.serviceState)),
			fmt.Sprintf("PID: %s", servicePIDLabel(m.serviceState)),
			fmt.Sprintf("Uptime: %s", m.serviceState.Uptime),
		)
		if m.serviceState.ServiceFile != "" {
			lines = append(lines, fmt.Sprintf("Service File: %s", m.serviceState.ServiceFile))
		}
		lines = append(lines,
			fmt.Sprintf("Config Path: %s", m.serviceState.ConfigPath),
			fmt.Sprintf("Log Path: %s", m.serviceState.LogPath),
		)
		return strings.Join(lines, "\n")
	default:
		return strings.Join([]string{
			"Service overview",
			"",
			m.serviceState.Hint,
			"",
			"[S] Start  [T] Stop  [R] Restart",
			"[I] Install  [U] Uninstall  [L] Logs  [F] Follow  [C] Refresh",
			"[M] Cycle detail view  [←/→] Horizontal scroll",
		}, "\n")
	}
}

func (m Model) renderServiceLogPane(height int, lineWidth int) string {
	title := " SERVICE LOGS "
	note := fmt.Sprintf("[F] follow:%s  [C] refresh  [←/→] scroll", onOff(m.serviceFollow))
	contentRows := height - 2
	if contentRows < 1 {
		contentRows = 1
	}
	var rawLines []string
	if strings.TrimSpace(m.serviceLogs) == "" {
		rawLines = []string{"no log lines yet"}
	} else {
		rawLines = strings.Split(strings.TrimRight(m.serviceLogs, "\n"), "\n")
	}
	if len(rawLines) > contentRows {
		rawLines = rawLines[len(rawLines)-contentRows:]
	}
	contentWidth := lineWidth
	maxScroll := 0
	for _, line := range rawLines {
		rs := []rune(line)
		if len(rs)-contentWidth > maxScroll {
			maxScroll = len(rs) - contentWidth
		}
	}
	effectiveScroll := m.detailScroll
	if effectiveScroll > maxScroll {
		effectiveScroll = maxScroll
	}

	lines := []string{padOrTrim(title+strings.Repeat("─", max(0, lineWidth-runeLen(title))), lineWidth)}
	for i := 0; i < contentRows; i++ {
		line := ""
		if i < len(rawLines) {
			line, _ = clipHorizontal(rawLines[i], effectiveScroll, contentWidth)
		}
		lines = append(lines, padOrTrim(line, lineWidth))
	}
	lines = append(lines, padOrTrim(note, lineWidth))

	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	return b.String()
}

func (m Model) currentServiceLogMaxScroll(width int) int {
	if strings.TrimSpace(m.serviceLogs) == "" {
		return 0
	}
	lines := strings.Split(strings.TrimRight(m.serviceLogs, "\n"), "\n")
	maxScroll := 0
	for _, line := range lines {
		rs := []rune(line)
		if len(rs)-width > maxScroll {
			maxScroll = len(rs) - width
		}
	}
	if maxScroll < 0 {
		return 0
	}
	return maxScroll
}

func (m Model) currentPresetLinks() string {
	if m.staging == nil {
		return ""
	}
	if m.cursor < 0 || m.cursor >= len(m.staging.Presets) {
		return ""
	}
	ip := m.cachedIP
	if m.useLocalIP {
		ip = m.localIP
	}
	mode := m.staging.Presets[m.cursor]
	tempCfg := *m.staging
	tempCfg.Presets = []config.ModeInfo{mode}
	links := xray.GenerateLinks(&tempCfg, ip)
	if len(links) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(string(mode.Mode))
	b.WriteString(":\n")
	for i, link := range links {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(link)
	}
	return strings.TrimSpace(b.String())
}

func (m Model) currentRelayLinks() string {
	if m.staging == nil || m.cursor < 0 || m.cursor >= len(m.staging.CustomOutbounds) {
		return ""
	}
	ip := m.cachedIP
	if m.useLocalIP {
		ip = m.localIP
	}
	relay := m.staging.CustomOutbounds[m.cursor]
	links := xray.GenerateRelayLinks(m.staging, ip, relay)
	if len(links) == 0 {
		return ""
	}
	return strings.Join(links, "\n")
}

func (m Model) currentGuestLinks() string {
	if m.staging == nil || m.cursor < 0 || m.cursor >= len(m.staging.Guests) {
		return ""
	}
	ip := m.cachedIP
	if m.useLocalIP {
		ip = m.localIP
	}
	guest := m.staging.Guests[m.cursor]
	links := xray.GenerateGuestLinks(m.staging, ip, guest.UUID, guest.Alias)
	if len(links) == 0 {
		return ""
	}
	return strings.Join(links, "\n")
}

func buildShowScript(title string, body string) string {
	escapedTitle := strings.ReplaceAll(title, "'", "'\\''")
	escapedBody := strings.ReplaceAll(body, "'", "'\\''")
	return fmt.Sprintf("printf '\\033[2J\\033[H'; printf '=== %%s ===\\n\\n' '%s'; printf '%%s' '%s'; printf '\\n\\n[Enter] Return to TUI...'; IFS= read -r _", escapedTitle, escapedBody)
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
	return "done"
}

func summarizeServiceActionResult(action string, output string, err error) string {
	if err != nil {
		if trimmed := strings.TrimSpace(output); trimmed != "" {
			lines := strings.Split(trimmed, "\n")
			return fmt.Sprintf("%s failed: %s", action, strings.TrimSpace(lines[len(lines)-1]))
		}
		return fmt.Sprintf("%s failed: %v", action, err)
	}
	if trimmed := strings.TrimSpace(output); trimmed != "" {
		lines := strings.Split(trimmed, "\n")
		return strings.TrimSpace(lines[len(lines)-1])
	}
	return action + " done"
}

func clipHorizontal(s string, start int, width int) (string, int) {
	rs := []rune(s)
	if start < 0 {
		start = 0
	}
	maxScroll := len(rs) - width
	if maxScroll < 0 {
		maxScroll = 0
	}
	if start > maxScroll {
		start = maxScroll
	}
	end := start + width
	if end > len(rs) {
		end = len(rs)
	}
	return string(rs[start:end]), maxScroll
}

func detailMaxScroll(s string, width int) int {
	_, maxScroll := clipHorizontal(s, 0, width)
	return maxScroll
}

func padOrTrim(s string, width int) string {
	rs := []rune(s)
	if len(rs) > width {
		return string(rs[:width])
	}
	return s + strings.Repeat(" ", width-len(rs))
}

func runeLen(s string) int {
	return len([]rune(s))
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func nextServiceDetailView(view serviceDetailView) serviceDetailView {
	switch view {
	case serviceDetailOverview:
		return serviceDetailLogs
	case serviceDetailLogs:
		return serviceDetailRuntime
	default:
		return serviceDetailOverview
	}
}

func renderFooter(tab sessionTab, width int) string {
	var keys []string
	keys = append(keys, "[Tab]Switch", "[Q]Quit")
	if tab == tabStatus {
		keys = append(keys, "[A]Apply", "[L]IP-Mode")
	}
	if tab == tabService {
		keys = append(keys, "[S]Start", "[T]Stop", "[R]Restart", "[I/U]Install", "[L]Logs", "[F]Follow", "[M]Detail", "[C]Refresh")
	}
	if tab == tabPresets {
		keys = append(keys, "[A]Apply", "[+/-]On/Off", "[0-9]Port", "[L]IP-Mode", "[R]Regen", "[U]Undo", "[←/→]Scroll", "[S]Show")
	} else if tab == tabRelays {
		keys = append(keys, "[A]Apply", "[N]New", "[+/-]On/Off", "[T]Test", "[V]Speed", "[I]Info", "[B]Probe", "[R]Resolve", "[D]Del", "[L]IP-Mode", "[←/→]Scroll", "[S]Show", "[U]Undo")
	} else if tab == tabGuests {
		keys = append(keys, "[A]Apply", "[N]New", "[-/=]Pause/Resume", "[G]Quota", "[R]Reset", "[O]Outbound", "[E/X/Y]Sub", "[W]SubURL", "[D]Del", "[L]IP-Mode", "[←/→]Scroll", "[S]Show", "[U]Undo")
	} else if tab == tabGateway {
		keys = append(keys, "[Enter]Toggle/Select", "[+/-]Change State", "[T]Test Route", "[A]Apply", "[U]Undo")
	}
	s := strings.Join(keys, "  ")
	return lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderTop(true).Width(width).MaxHeight(2).Render(s)
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
		tabStatus:  "HOME",
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

func Start() error {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func fetchRelayDetail(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayDetailMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "info", alias)
		out, err := cmd.CombinedOutput()
		body := strings.TrimSpace(string(out))
		return relayDetailMsg{alias: alias, body: "__info__\n" + body, err: err}
	}
}

func runServiceAction(action string, args ...string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return serviceActionMsg{action: action, err: err, state: xray.GetServiceState()}
		}
		cmd := exec.Command(exe, args...)
		out, err := cmd.CombinedOutput()
		return serviceActionMsg{
			action: action,
			output: strings.TrimSpace(string(out)),
			err:    err,
			state:  xray.GetServiceState(),
		}
	}
}

func refreshServiceState() tea.Cmd {
	return func() tea.Msg {
		return serviceActionMsg{
			action: "refresh",
			state:  xray.GetServiceState(),
		}
	}
}

func refreshServiceLogs(lines int) tea.Cmd {
	return func() tea.Msg {
		body, err := xray.ReadLogTail(lines)
		return serviceLogsMsg{body: body, err: err}
	}
}

func fetchPublicIP() tea.Cmd {
	return func() tea.Msg {
		return publicIPMsg{ip: utils.GetSmartIP(false)}
	}
}

func tickServiceLogs() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return serviceFollowTickMsg{}
	})
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func fetchRelayTest(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayDetailMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "test", alias)
		out, err := cmd.CombinedOutput()
		body := strings.TrimSpace(string(out))
		return relayDetailMsg{alias: alias, body: "__test__\n" + body, err: err}
	}
}

func fetchRelayProbe(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayDetailMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "probe-local", alias)
		out, err := cmd.CombinedOutput()
		body := strings.TrimSpace(string(out))
		return relayDetailMsg{alias: alias, body: "__probe__\n" + body, err: err}
	}
}

func fetchRelaySpeed(alias string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayDetailMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "speed", alias)
		out, err := cmd.CombinedOutput()
		body := strings.TrimSpace(string(out))
		return relayDetailMsg{alias: alias, body: "__speed__\n" + body, err: err}
	}
}

func fetchRelayResolve(alias string, domain string) tea.Cmd {
	return func() tea.Msg {
		exe, err := os.Executable()
		if err != nil {
			return relayDetailMsg{alias: alias, err: err}
		}
		cmd := exec.Command(exe, "relay", "resolve", alias, domain)
		out, err := cmd.CombinedOutput()
		body := strings.TrimSpace(string(out))
		return relayDetailMsg{alias: alias, body: "__resolve__\n" + domain + "\n" + body, err: err}
	}
}

func parseRelayDetailOutput(alias string, raw string) relayDetailData {
	if strings.TrimSpace(raw) == "" {
		return relayDetailData{}
	}
	if strings.HasPrefix(raw, "__probe__\n") {
		return parseRelayProbeOutput(alias, strings.TrimPrefix(raw, "__probe__\n"))
	}
	if strings.HasPrefix(raw, "__test__\n") {
		return parseRelayTestOutput(alias, strings.TrimPrefix(raw, "__test__\n"))
	}
	if strings.HasPrefix(raw, "__speed__\n") {
		return parseRelaySpeedOutput(alias, strings.TrimPrefix(raw, "__speed__\n"))
	}
	if strings.HasPrefix(raw, "__resolve__\n") {
		payload := strings.TrimPrefix(raw, "__resolve__\n")
		parts := strings.SplitN(payload, "\n", 2)
		domain := ""
		body := ""
		if len(parts) > 0 {
			domain = parts[0]
		}
		if len(parts) > 1 {
			body = parts[1]
		}
		return parseRelayResolveOutput(alias, domain, body)
	}
	raw = strings.TrimPrefix(raw, "__info__\n")

	lines := strings.Split(raw, "\n")
	fields := map[string]string{}
	media := map[string]string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "✨ Landing Profile:") {
			fields["title"] = strings.TrimSpace(strings.TrimPrefix(line, "✨ Landing Profile:"))
			continue
		}
		if strings.HasPrefix(line, "Netflix:") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Netflix:"))
			parts := strings.Fields(rest)
			if len(parts) >= 1 {
				media["Netflix"] = parts[0]
			}
			for i := 1; i+1 < len(parts); i += 2 {
				key := strings.TrimSuffix(parts[i], ":")
				media[key] = parts[i+1]
			}
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			fields[key] = val
		}
	}

	title := alias
	if v := fields["title"]; v != "" {
		title = v
	}
	return relayDetailData{
		title: title,
		fields: []detailField{
			{label: "Exit", value: firstNonEmpty(fields["Exit IP"], fields["Exit IPv4"], fields["Exit IPv6"], "Unknown")},
			{label: "Geo", value: emptyFallback(joinNonEmpty(", ", fields["Local"], fields["Country"]), "N/A")},
			{label: "IPv4", value: firstNonEmpty(fields["Exit IPv4"], "N/A")},
			{label: "IPv6", value: firstNonEmpty(fields["Exit IPv6"], "N/A")},
			{label: "Org", value: emptyFallback(fields["Company"], "N/A")},
			{label: "ASN", value: emptyFallback(joinNonEmpty(" ", fields["ASN Type"], fields["ASN"]), "N/A")},
			{label: "Time", value: emptyFallback(joinNonEmpty(" ", fields["Local Time"], fields["Time Zone"]), "N/A")},
			{label: "Privacy", value: emptyFallback(fields["ASN Type"], "N/A")},
			{label: "Netflix", value: emptyFallback(media["Netflix"], "?")},
			{label: "YouTube", value: emptyFallback(media["YouTube"], "?")},
			{label: "Disney+", value: emptyFallback(media["Disney+"], "?")},
		},
	}
}

func parseRelayTestSummary(alias string, raw string) relayTestMsg {
	result := relayTestMsg{alias: alias, tcp: "FAIL", udp: "FAIL", dns: "FAIL", ipv4: "N/A", ipv6: "N/A"}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}
		parts := strings.SplitN(line, "->", 2)
		for _, segment := range strings.Split(parts[1], "|") {
			segment = strings.TrimSpace(segment)
			idx := strings.Index(segment, ":")
			if idx <= 0 {
				continue
			}
			key := strings.TrimSpace(segment[:idx])
			val := strings.TrimSpace(segment[idx+1:])
			switch key {
			case "TCP":
				result.tcp = summarizeRelayTestValue(val)
			case "UDP":
				result.udp = summarizeRelayTestValue(val)
			case "DNS":
				result.dns = summarizeRelayTestValue(val)
			case "IPv4":
				result.ipv4 = val
			case "IPv6":
				result.ipv6 = val
			}
		}
	}
	return result
}

func parseRelayProbeOutput(alias string, raw string) relayDetailData {
	fields := []detailField{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}
		head := strings.TrimSpace(parts[0])
		body := strings.TrimSpace(parts[1])
		label := head
		if idx := strings.LastIndex(head, "/"); idx >= 0 && strings.HasSuffix(head, "]") {
			label = strings.TrimSuffix(head[idx+1:], "]")
		}
		for _, segment := range strings.Split(body, "|") {
			segment = strings.TrimSpace(segment)
			idx := strings.Index(segment, ":")
			if idx <= 0 {
				continue
			}
			key := strings.TrimSpace(segment[:idx])
			val := strings.TrimSpace(segment[idx+1:])
			fields = append(fields, detailField{label: label + " " + key, value: val})
		}
	}
	return relayDetailData{title: alias + " probe", fields: fields}
}

func parseRelayTestOutput(alias string, raw string) relayDetailData {
	detail := relayTestMsg{alias: alias, tcp: "FAIL", udp: "FAIL", dns: "FAIL", ipv4: "N/A", ipv6: "N/A"}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}
		parts := strings.SplitN(line, "->", 2)
		for _, segment := range strings.Split(parts[1], "|") {
			segment = strings.TrimSpace(segment)
			idx := strings.Index(segment, ":")
			if idx <= 0 {
				continue
			}
			key := strings.TrimSpace(segment[:idx])
			val := strings.TrimSpace(segment[idx+1:])
			switch key {
			case "TCP":
				detail.tcp = val
			case "UDP":
				detail.udp = val
			case "DNS":
				detail.dns = val
			case "IPv4":
				detail.ipv4 = val
			case "IPv6":
				detail.ipv6 = val
			}
		}
	}
	fields := []detailField{
		{label: "TCP", value: detail.tcp},
		{label: "UDP", value: detail.udp},
		{label: "DNS", value: detail.dns},
		{label: "IPv4", value: detail.ipv4},
		{label: "IPv6", value: detail.ipv6},
	}
	return relayDetailData{title: alias + " test", fields: fields}
}

func summarizeRelayTestValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "FAIL"
	}
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "OK") {
		return value
	}
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "timeout"):
		return "FAIL(timeout)"
	case strings.Contains(lower, "i/o timeout"):
		return "FAIL(timeout)"
	case strings.Contains(lower, "context deadline exceeded"):
		return "FAIL(timeout)"
	case strings.Contains(lower, "eof"):
		return "FAIL(eof)"
	case strings.Contains(lower, "connection refused"):
		return "FAIL(refused)"
	case strings.Contains(lower, "network is unreachable"):
		return "FAIL(unreachable)"
	case strings.Contains(lower, "no route to host"):
		return "FAIL(no-route)"
	case strings.Contains(lower, "reset by peer"):
		return "FAIL(reset)"
	}
	if idx := strings.Index(value, "("); idx > 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}

func parseRelayResolveOutput(alias string, domain string, raw string) relayDetailData {
	fields := []detailField{{label: "Domain", value: domain}}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		qtype := parts[1]
		value := strings.Join(parts[2:], " ")
		fields = append(fields, detailField{label: qtype, value: value})
	}
	return relayDetailData{title: alias + " resolve", fields: fields}
}

func parseRelaySpeedOutput(alias string, raw string) relayDetailData {
	lines := strings.Split(raw, "\n")
	collecting := false
	values := map[string]string{}
	order := []string{
		"Link",
		"Duration",
		"Data",
		"Average",
		"Peak",
		"Low 20%",
		"Idle Latency Avg",
		"Load Latency Avg",
		"Load Worst 5%",
		"Packet Loss",
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "❌") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "Speed Test") {
			collecting = true
			continue
		}
		if !collecting {
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			label := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			if value != "" {
				values[label] = value
			}
		}
	}
	fields := make([]detailField, 0, len(order))
	for _, label := range order {
		if value := strings.TrimSpace(values[label]); value != "" {
			fields = append(fields, detailField{label: label, value: value})
		}
	}
	return relayDetailData{title: alias + " speed", fields: fields}
}

func joinNonEmpty(sep string, values ...string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && v != "N/A" {
			out = append(out, v)
		}
	}
	return strings.Join(out, sep)
}

func emptyFallback(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func buildRelaySummary(co config.CustomOutbound) string {
	var b strings.Builder
	status := "OFF"
	if co.Enabled {
		status = "ON"
	}
	internal := "-"
	if co.InternalProxyPort > 0 {
		internal = fmt.Sprintf("socks:%d http:%d", co.InternalProxyPort, co.InternalProxyPort+1)
	}
	strategy := co.DNSStrategy
	if strategy == "" {
		strategy = "default"
	}
	b.WriteString(fmt.Sprintf("Alias: %s\n", co.Alias))
	b.WriteString(fmt.Sprintf("State: %s\n", status))
	b.WriteString(fmt.Sprintf("Proto: %s\n", relayProtocol(co)))
	b.WriteString(fmt.Sprintf("Remote: %s\n", relayRemoteSummary(co)))
	b.WriteString(fmt.Sprintf("Transport: %s\n", relayTransportSummary(co)))
	b.WriteString(fmt.Sprintf("Internal: %s\n", internal))
	b.WriteString(fmt.Sprintf("DNS: %s", relayDNSSummary(co, strategy)))
	return b.String()
}

func relayProtocol(co config.CustomOutbound) string {
	if proto, _ := co.Config["protocol"].(string); proto != "" {
		return proto
	}
	return "unknown"
}

func relayRemoteSummary(co config.CustomOutbound) string {
	settings, _ := co.Config["settings"].(map[string]interface{})
	switch relayProtocol(co) {
	case "vless", "vmess":
		vnext := getMapSlice(settings, "vnext")
		if len(vnext) == 0 {
			return "-"
		}
		return joinHostPort(vnext[0]["address"], vnext[0]["port"])
	case "shadowsocks", "socks", "http":
		servers := getMapSlice(settings, "servers")
		if len(servers) == 0 {
			return "-"
		}
		return joinHostPort(servers[0]["address"], servers[0]["port"])
	case "freedom":
		sendThrough, _ := co.Config["sendThrough"].(string)
		if sendThrough != "" {
			return sendThrough
		}
		return "direct"
	default:
		return "-"
	}
}

func relayTransportSummary(co config.CustomOutbound) string {
	stream, _ := co.Config["streamSettings"].(map[string]interface{})
	parts := []string{}
	network := stringValue(stream["network"])
	if network == "" {
		switch relayProtocol(co) {
		case "shadowsocks", "socks", "http", "freedom":
			network = "tcp"
		}
	}
	if network != "" {
		parts = append(parts, network)
	}
	security := stringValue(stream["security"])
	if security != "" && security != "none" {
		parts = append(parts, security)
	}
	serverName := firstNonEmpty(nestedString(stream, "realitySettings", "serverName"), nestedString(stream, "tlsSettings", "serverName"))
	if serverName != "" {
		parts = append(parts, "sni="+serverName)
	}
	host := relayHeaderHost(stream)
	if host != "" && host != serverName {
		parts = append(parts, "host="+host)
	}
	path := firstNonEmpty(nestedString(stream, "wsSettings", "path"), nestedString(stream, "xhttpSettings", "path"))
	if path != "" {
		parts = append(parts, "path="+path)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func relayHeaderHost(stream map[string]interface{}) string {
	if host := nestedString(stream, "xhttpSettings", "host"); host != "" {
		return host
	}
	if host := nestedString(stream, "wsSettings", "headers", "Host"); host != "" {
		return host
	}
	return ""
}

func relayDNSSummary(co config.CustomOutbound, fallback string) string {
	if len(co.DNSServers) == 0 {
		return fallback
	}
	return fallback + " " + strings.Join(co.DNSServers, ",")
}

func getMapSlice(m map[string]interface{}, key string) []map[string]interface{} {
	raw, _ := m[key].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if mm, ok := item.(map[string]interface{}); ok {
			out = append(out, mm)
		}
	}
	return out
}

func joinHostPort(host interface{}, port interface{}) string {
	return fmt.Sprintf("%v:%v", host, port)
}

func stringValue(v interface{}) string {
	s, _ := v.(string)
	return s
}

func nestedString(m map[string]interface{}, keys ...string) string {
	var cur interface{} = m
	for _, key := range keys {
		next, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = next[key]
		if !ok {
			return ""
		}
	}
	return stringValue(cur)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (m *Model) startInput(mode inputMode, placeholder string, value string) {
	m.inputMode = mode
	m.textInput.Placeholder = placeholder
	m.textInput.SetValue(value)
	m.textInput.CursorEnd()
	m.textInput.Focus()
}

func (m Model) inputTitle() string {
	switch m.inputMode {
	case inputAddRelayAlias:
		return "SET RELAY ALIAS"
	case inputAddRelay:
		return "ADD CUSTOM RELAY"
	case inputAddGuest:
		return "ADD GUEST"
	case inputSetGuestQuota:
		return "SET GUEST QUOTA"
	case inputSetGuestReset:
		return "SET GUEST RESET DAY"
	case inputSetGuestOutbound:
		return "SET GUEST OUTBOUND"
	case inputRelayResolveDomain:
		return "RESOLVE DOMAIN VIA RELAY"
	default:
		return "INPUT"
	}
}

func (m Model) submitInput() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.textInput.Value())
	mode := m.inputMode
	m.inputMode = inputNone
	m.textInput.Reset()
	switch mode {
	case inputAddRelayAlias:
		m.relayAlias = value
		m.startInput(inputAddRelay, "Paste link...", "")
		return m, nil
	case inputAddRelay:
		if value != "" {
			out, err := xray.ParseProxyLink(value)
			if err == nil {
				alias := strings.TrimSpace(m.relayAlias)
				if alias == "" {
					alias = m.nextRelayAlias()
				}
				if err := m.validateRelayAlias(alias); err != nil {
					m.statusNote = err.Error()
					m.relayAlias = ""
					return m, nil
				}
				newCO := config.CustomOutbound{Alias: alias, Enabled: true, UserUUID: uuid.New().String(), Config: out}
				m.staging.CustomOutbounds = append(m.staging.CustomOutbounds, newCO)
				m.staging.SaveEx(true)
				m.relayLoading = alias
				m.relayResults[alias] = relayTestMsg{alias: alias, tcp: "Wait..", udp: "Wait..", dns: "Wait..", ipv4: "--", ipv6: "--"}
				m.statusNote = "relay added"
				m.relayAlias = ""
				return m, fetchRelayTest(alias)
			}
			m.relayAlias = ""
			m.statusNote = fmt.Sprintf("parse failed: %v", err)
		}
	case inputAddGuest:
		if err := m.addGuest(value); err != nil {
			m.statusNote = err.Error()
		} else {
			m.statusNote = "guest added"
		}
	case inputSetGuestQuota:
		if err := m.setGuestQuota(value); err != nil {
			m.statusNote = err.Error()
		} else {
			m.statusNote = "guest quota updated"
		}
	case inputSetGuestReset:
		if err := m.setGuestReset(value); err != nil {
			m.statusNote = err.Error()
		} else {
			m.statusNote = "guest reset day updated"
		}
	case inputSetGuestOutbound:
		if err := m.setGuestOutbound(value); err != nil {
			m.statusNote = err.Error()
		} else {
			m.statusNote = "guest outbound updated"
		}
	case inputRelayResolveDomain:
		if m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
			alias := m.staging.CustomOutbounds[m.cursor].Alias
			m.relayLoading = alias
			m.statusNote = "resolving via relay..."
			return m, fetchRelayResolve(alias, value)
		}
	}
	return m, nil
}

func (m Model) nextRelayAlias() string {
	for {
		alias := "relay-" + utils.GenerateRandomString(3)
		if m.staging == nil {
			return alias
		}
		exists := false
		for _, co := range m.staging.CustomOutbounds {
			if co.Alias == alias {
				exists = true
				break
			}
		}
		if !exists {
			return alias
		}
	}
}

func (m Model) validateRelayAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("relay alias required")
	}
	if len(alias) < 3 || len(alias) > 20 {
		return fmt.Errorf("relay alias must be 3-20 chars")
	}
	for _, r := range alias {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return fmt.Errorf("relay alias allows only alnum/_/-")
		}
	}
	if m.staging != nil {
		for _, co := range m.staging.CustomOutbounds {
			if co.Alias == alias {
				return fmt.Errorf("relay alias '%s' already exists", alias)
			}
		}
	}
	return nil
}

func (m *Model) selectedGuest() *config.GuestConfig {
	if m.staging == nil || m.cursor < 0 || m.cursor >= len(m.staging.Guests) {
		return nil
	}
	return &m.staging.Guests[m.cursor]
}

func (m *Model) addGuest(alias string) error {
	if alias == "" {
		return fmt.Errorf("guest alias required")
	}
	if len(alias) < 3 || len(alias) > 20 {
		return fmt.Errorf("guest alias must be 3-20 chars")
	}
	for _, r := range alias {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("alias allows only alnum/_/-")
		}
	}
	for _, g := range m.staging.Guests {
		if g.Alias == alias {
			return fmt.Errorf("guest already exists")
		}
	}
	m.staging.Guests = append(m.staging.Guests, config.GuestConfig{
		Alias: alias, UUID: uuid.New().String(), Enabled: true, DisabledReason: config.GuestDisabledNone, QuotaGB: -1, ResetDay: 1,
	})
	m.staging.SaveEx(true)
	m.cursor = len(m.staging.Guests) - 1
	return nil
}

func (m *Model) pauseGuest() {
	guest := m.selectedGuest()
	if guest == nil {
		return
	}
	guest.Enabled = false
	guest.DisabledReason = config.GuestDisabledManual
	m.staging.SaveEx(true)
}

func (m *Model) resumeGuest() error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	if guest.QuotaGB == 0 {
		return fmt.Errorf("guest still has quota=0")
	}
	guest.Enabled = true
	guest.DisabledReason = config.GuestDisabledNone
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) setGuestQuota(raw string) error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	if raw == "reset" {
		guest.UsedBytes = -1
		if guest.DisabledReason == config.GuestDisabledQuotaReached && guest.QuotaGB > 0 {
			guest.Enabled = true
			guest.DisabledReason = config.GuestDisabledNone
		}
		m.staging.SaveEx(true)
		return nil
	}
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("invalid quota")
	}
	guest.QuotaGB = val
	if val == 0 {
		guest.Enabled = false
		guest.DisabledReason = config.GuestDisabledQuotaZero
	} else if guest.DisabledReason != config.GuestDisabledManual {
		guest.Enabled = true
		guest.DisabledReason = config.GuestDisabledNone
	}
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) setGuestReset(raw string) error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	day, err := strconv.Atoi(raw)
	if err != nil || day < 1 || day > 31 {
		return fmt.Errorf("reset day must be 1-31")
	}
	guest.ResetDay = day
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) setGuestOutbound(raw string) error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	if raw == "" || raw == "direct" {
		guest.OutboundLink = ""
		guest.OutboundConf = nil
		m.staging.SaveEx(true)
		return nil
	}
	conf, err := xray.ParseProxyLink(raw)
	if err != nil {
		return fmt.Errorf("invalid link: %v", err)
	}
	guest.OutboundLink = raw
	guest.OutboundConf = conf
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) enableGuestSub() error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	ensureGuestSubListenerConfig(m.staging)
	if guest.SubToken == "" {
		guest.SubToken = utils.GenerateRandomString(32)
	}
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) disableGuestSub() error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	guest.SubToken = ""
	m.staging.SaveEx(true)
	return nil
}

func (m *Model) rotateGuestSub() error {
	guest := m.selectedGuest()
	if guest == nil {
		return fmt.Errorf("no guest selected")
	}
	ensureGuestSubListenerConfig(m.staging)
	guest.SubToken = utils.GenerateRandomString(32)
	m.staging.SaveEx(true)
	return nil
}

func ensureGuestSubListenerConfig(cfg *config.UserConfig) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.GuestSubBind) == "" {
		cfg.GuestSubBind = "127.0.0.1"
	}
	if cfg.GuestSubPort > 0 {
		return
	}
	const preferredPort = 9444
	if utils.IsPortFree(preferredPort) {
		cfg.GuestSubPort = preferredPort
		return
	}
	port, _ := xray.GetFreePort()
	cfg.GuestSubPort = port
}

func guestSubURL(host string, port int, token string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("https://%s/guest-sub/%s", net.JoinHostPort(host, strconv.Itoa(port)), token)
}

func buildGuestSubReport(cfg *config.UserConfig, guest config.GuestConfig, host string) string {
	var b strings.Builder
	b.WriteString(BuildGuestReport(guest))
	if cfg == nil {
		return b.String()
	}
	ensureGuestSubListenerConfig(cfg)
	b.WriteString(fmt.Sprintf("Listener: %s:%d\n", cfg.GuestSubBind, cfg.GuestSubPort))
	b.WriteString(fmt.Sprintf("Path: /guest-sub/%s\n", guest.SubToken))
	b.WriteString(fmt.Sprintf("URL: %s\n", guestSubURL(host, cfg.GuestSubPort, guest.SubToken)))
	b.WriteString(fmt.Sprintf("Remark Preview: %s\n", sub.FormatGuestSubRemarkForDisplay(guest, time.Now())))
	return b.String()
}

func (m Model) renderGatewayChoices() string {
	var b strings.Builder
	if m.gatewayInputMode == 1 {
		b.WriteString("Select LAN Interface: ")
	} else if m.gatewayInputMode == 2 {
		b.WriteString("Select Outbound Relay: ")
	} else if m.gatewayInputMode == 3 {
		b.WriteString("Select Gateway State: ")
	}
	for i, c := range m.gatewayChoices {
		if i > 0 {
			b.WriteString("  ")
		}
		if i == m.gatewayChoiceIdx {
			b.WriteString(lipgloss.NewStyle().Reverse(true).Render(" " + c + " "))
		} else {
			b.WriteString(" " + c + " ")
		}
	}
	b.WriteString("  [Enter]Confirm [Esc]Cancel")
	return b.String()
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
		err := gateway.ApplyFirewall(cfg)
		return gatewayActionResultMsg{action: "up", err: err}
	}
}

func runGatewayDown() tea.Cmd {
	return func() tea.Msg {
		gateway.CleanupFirewall()
		return gatewayActionResultMsg{action: "down", err: nil}
	}
}

func testLocalProxy(cfg *config.UserConfig) tea.Cmd {
	return func() tea.Msg {
		ip, err := RunLocalProxyTest(cfg)
		return gatewayTestResultMsg{row: 0, ip: ip, err: err}
	}
}

func testLANGateway(cfg *config.UserConfig) tea.Cmd {
	return func() tea.Msg {
		ip, err := RunSimulatedLANTest(cfg)
		return gatewayTestResultMsg{row: 1, ip: ip, err: err}
	}
}

func parseCloudflareTraceIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	return ""
}

func RunLocalProxyTest(cfg *config.UserConfig) (string, error) {
	// Ensure gateway rules are up and table 100 has the route
	if err := gateway.ApplyFirewall(cfg); err != nil {
		return "", fmt.Errorf("failed to apply firewall rules: %v", err)
	}

	endpoints := []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"}
	var lastErr error
	for _, ep := range endpoints {
		out, err := exec.Command("curl", "-sk", "-m", "5", ep).Output()
		if err == nil {
			ip := parseCloudflareTraceIP(string(out))
			if ip != "" {
				return ip, nil
			}
			lastErr = fmt.Errorf("empty IP in trace response")
		} else {
			lastErr = err
		}
	}
	return "", lastErr
}

func RunSimulatedLANTest(cfg *config.UserConfig) (string, error) {
	// Ensure gateway rules are up and table 100 has the route
	if err := gateway.ApplyFirewall(cfg); err != nil {
		return "", fmt.Errorf("failed to apply firewall rules: %v", err)
	}

	nsName := "ns-prov-test"
	exec.Command("ip", "netns", "del", nsName).Run()
	exec.Command("ip", "link", "del", "veth-tg").Run()

	if err := runCmdSlice([]string{"ip", "netns", "add", nsName}); err != nil {
		return "", err
	}
	defer exec.Command("ip", "netns", "del", nsName).Run()

	if err := runCmdSlice([]string{"ip", "link", "add", "veth-tc", "type", "veth", "peer", "name", "veth-tg"}); err != nil {
		return "", err
	}
	defer exec.Command("ip", "link", "del", "veth-tg").Run()

	_ = runCmdSlice([]string{"sudo", "sysctl", "-w", "net.ipv4.conf.veth-tg.rp_filter=0"})
	_ = runCmdSlice([]string{"sudo", "sysctl", "-w", "net.ipv4.conf.veth-tg.send_redirects=0"})

	if err := runCmdSlice([]string{"ip", "link", "set", "veth-tc", "netns", nsName}); err != nil {
		return "", err
	}

	if err := runCmdSlice([]string{"ip", "addr", "add", "192.168.250.1/24", "dev", "veth-tg"}); err != nil {
		return "", err
	}
	if err := runCmdSlice([]string{"ip", "netns", "exec", nsName, "ip", "addr", "add", "192.168.250.2/24", "dev", "veth-tc"}); err != nil {
		return "", err
	}

	if err := runCmdSlice([]string{"ip", "link", "set", "veth-tg", "up"}); err != nil {
		return "", err
	}
	if err := runCmdSlice([]string{"ip", "netns", "exec", nsName, "ip", "link", "set", "veth-tc", "up"}); err != nil {
		return "", err
	}
	if err := runCmdSlice([]string{"ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"}); err != nil {
		return "", err
	}

	if err := runCmdSlice([]string{"ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", "192.168.250.1", "dev", "veth-tc"}); err != nil {
		return "", err
	}

	if err := runCmdSlice([]string{"nft", "insert", "rule", "inet", "xray_proxya", "prerouting", "iifname", "veth-tg", "meta", "l4proto", "{", "tcp,", "udp", "}", "meta", "mark", "set", "1"}); err != nil {
		return "", err
	}
	defer func() {
		gateway.ApplyFirewall(cfg)
	}()

	time.Sleep(500 * time.Millisecond)

	endpoints := []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"}
	var lastErr error
	for _, ep := range endpoints {
		out, err := exec.Command("ip", "netns", "exec", nsName, "curl", "-sk", "-m", "5", ep).Output()
		if err == nil {
			ip := parseCloudflareTraceIP(string(out))
			if ip != "" {
				return ip, nil
			}
			lastErr = fmt.Errorf("empty IP in trace response")
		} else {
			lastErr = err
		}
	}
	return "", lastErr
}

func runCmdSlice(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}

type gatewayTestResultMsg struct {
	row int
	ip  string
	err error
}
