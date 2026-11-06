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
			confPath = config.GetGatewayConfPathEx(true)
			if _, err := os.Stat(confPath); os.IsNotExist(err) {
				confPath = config.GetGatewayConfPathEx(false)
			}
		} else {
			confPath = config.GetGatewayConfPathEx(false)
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
		confPath := config.GetGatewayConfPathEx(staging)
		if _, err := os.Stat(confPath); err == nil {
			return InPlaceUpdateFile(confPath, func(content string) string {
				if gw.State != "" {
					content = UpdateSetIfExists(content, "state", gw.State)
				}
				if gw.Mode != "" {
					content = UpdateSetIfExists(content, "mode", gw.Mode)
				}
				if gw.TUNEnabled {
					content = UpdateSetIfExists(content, "tun", "true")
				} else {
					content = UpdateSetIfExists(content, "tun", "false")
				}
				if gw.LocalEnabled {
					content = UpdateSetIfExists(content, "local", "true")
				} else {
					content = UpdateSetIfExists(content, "local", "false")
				}
				if gw.LANEnabled {
					content = UpdateSetIfExists(content, "lan", "true")
				} else {
					content = UpdateSetIfExists(content, "lan", "false")
				}
				if gw.NATDisabled {
					content = UpdateSetIfExists(content, "nat", "false")
				} else {
					content = UpdateSetIfExists(content, "nat", "true")
				}
				if gw.RelayAlias != "" {
					content = UpdateSetIfExists(content, "relay", gw.RelayAlias)
				}
				if gw.WANInterface != "" {
					content = UpdateSetIfExists(content, "wan", gw.WANInterface)
				}
				if len(gw.LANInterfaces) > 0 {
					content = UpdateSetIfExists(content, "lan_interfaces", strings.Join(gw.LANInterfaces, ","))
				} else if gw.LANInterface != "" {
					content = UpdateSetIfExists(content, "lan_interfaces", gw.LANInterface)
				}
				if len(gw.BypassCountries) > 0 {
					content = UpdateSetIfExists(content, "bypass_countries", strings.Join(gw.BypassCountries, ","))
				}
				if len(gw.BypassDNS) > 0 {
					content = UpdateSetIfExists(content, "bypass_dns", strings.Join(gw.BypassDNS, ","))
				}
				if gw.DNSListen != "" {
					content = UpdateSetIfExists(content, "dns_listen", gw.DNSListen)
				}
				if gw.DNSStrategy != "" {
					content = UpdateSetIfExists(content, "dns_strategy", gw.DNSStrategy)
				}
				if len(gw.DNSServers) > 0 {
					content = UpdateSetIfExists(content, "dns_servers", strings.Join(gw.DNSServers, ", "))
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
