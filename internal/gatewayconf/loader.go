package gatewayconf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"xray-proxya/internal/config"
)

func init() {
	config.GatewayConfigGenerator = GenerateFromUserConfig
	config.GatewayConfigLoader = func(staging bool, userCfg *config.UserConfig) (*config.GatewayConfig, error) {
		var confPath string
		if staging {
			confPath = config.GetGatewayConfPath()
			if _, err := os.Stat(confPath); os.IsNotExist(err) && config.GatewayActiveConfExists() {
				confPath = config.GetGatewayActiveConfPath()
			}
		} else {
			if !config.GatewayActiveConfExists() {
				return &config.GatewayConfig{Mode: "tproxy"}, nil
			}
			confPath = config.GetGatewayActiveConfPath()
		}

		if _, err := os.Stat(confPath); os.IsNotExist(err) {
			return nil, nil
		}

		data, err := os.ReadFile(confPath)
		if err != nil {
			return nil, err
		}

		ast, err := Parse(string(data))
		if err != nil {
			return nil, err
		}

		return Compile(ast, WithUserConfig(userCfg))
	}

	config.GatewayConfigSaver = func(gw *config.GatewayConfig, staging bool) error {
		if gw == nil {
			return nil
		}
		var confPath string
		if staging {
			confPath = config.GetGatewayConfPath()
		} else {
			confPath = config.GetGatewayActiveConfPath()
		}

		if _, err := os.Stat(confPath); err == nil {
			return InPlaceUpdateFile(confPath, func(content string) string {
				if gw.State != "" {
					content = UpdateSet(content, "state", gw.State)
				} else {
					content = DeleteSet(content, "state")
				}
				if gw.Mode != "" {
					content = UpdateSet(content, "mode", gw.Mode)
				}
				if gw.TUNEnabled {
					content = UpdateSet(content, "tun", "true")
				} else {
					content = UpdateSet(content, "tun", "false")
				}
				if gw.LocalEnabled {
					content = UpdateSet(content, "local", "true")
				} else {
					content = UpdateSet(content, "local", "false")
				}
				if gw.LANEnabled {
					content = UpdateSet(content, "lan", "true")
				} else {
					content = UpdateSet(content, "lan", "false")
				}
				if gw.NATDisabled {
					content = UpdateSet(content, "nat", "false")
				} else {
					content = UpdateSet(content, "nat", "true")
				}
				if gw.RelayAlias != "" {
					content = UpdateSet(content, "relay", gw.RelayAlias)
				} else {
					content = DeleteSet(content, "relay")
				}
				if gw.WANInterface != "" {
					content = UpdateSet(content, "wan", gw.WANInterface)
				} else {
					content = DeleteSet(content, "wan")
				}
				if len(gw.LANInterfaces) > 0 {
					content = UpdateSet(content, "lan_interfaces", strings.Join(gw.LANInterfaces, ","))
				} else if gw.LANInterface != "" {
					content = UpdateSet(content, "lan_interfaces", gw.LANInterface)
				} else {
					content = DeleteSet(content, "lan_interfaces")
				}
				if len(gw.BypassCountries) > 0 {
					content = UpdateSet(content, "bypass_countries", strings.Join(gw.BypassCountries, ","))
				} else {
					content = DeleteSet(content, "bypass_countries")
				}
				if len(gw.BypassDNS) > 0 {
					content = UpdateSet(content, "bypass_dns", strings.Join(gw.BypassDNS, ","))
				} else {
					content = DeleteSet(content, "bypass_dns")
				}
				if gw.DNSListen != "" {
					content = UpdateSet(content, "dns_listen", gw.DNSListen)
				} else {
					content = DeleteSet(content, "dns_listen")
				}
				if gw.DNSStrategy != "" {
					content = UpdateSet(content, "dns_strategy", gw.DNSStrategy)
				} else {
					content = DeleteSet(content, "dns_strategy")
				}
				if len(gw.DNSServers) > 0 {
					content = UpdateSet(content, "dns_servers", strings.Join(gw.DNSServers, ", "))
				} else {
					content = DeleteSet(content, "dns_servers")
				}

				// Rules and DNS records are declarative and edited in gateway.conf
				// directly. The compiled GatewayConfig expands them (device/group ->
				// mac rules), so writing them back unconditionally would duplicate
				// lines. Only rewrite them when the caller actually changed them.
				curRules, curDNS := compiledRulesAndDNS(content)
				if !reflect.DeepEqual(curRules, gw.Rules) {
					content = ClearRules(content)
					for _, r := range gw.Rules {
						content = UpdateRule(content, r)
					}
				}
				if !reflect.DeepEqual(curDNS, gw.DNSRecords) {
					content = ClearDNSRecords(content)
					for d, ips := range gw.DNSRecords {
						content = UpdateDNSRecord(content, d, ips)
					}
				}

				return content
			})
		}

		content := Generate(gw)
		if err := os.MkdirAll(filepath.Dir(confPath), 0700); err != nil {
			return err
		}
		return os.WriteFile(confPath, []byte(content), 0600)
	}
}

// compiledRulesAndDNS compiles content and returns its effective rules and DNS
// records. On any error it returns nils, which makes callers treat the content
// as changed.
func compiledRulesAndDNS(content string) ([]config.GatewayRule, map[string][]string) {
	ast, err := Parse(content)
	if err != nil {
		return nil, nil
	}
	gw, err := Compile(ast)
	if err != nil || gw == nil {
		return nil, nil
	}
	return gw.Rules, gw.DNSRecords
}
