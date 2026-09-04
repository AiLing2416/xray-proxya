package main

import (
	"fmt"
	"strings"
	"time"
	"xray-proxya/internal/certmanager"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var (
	certEmail   string
	certSkipDNS bool
	certForce   bool
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage domains and TLS certificates for Web skins and REALITY",
}

var certAddCmd = &cobra.Command{
	Use:   "add [domain]",
	Short: "Add a domain, issue Let's Encrypt TLS certificate, and register 7-day auto-renewal",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[0])), ".")
		if domain == "" {
			return fmt.Errorf("domain cannot be empty")
		}

		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("load staging config: %w", err)
		}

		if !certSkipDNS {
			fmt.Printf("🔍 Checking DNS resolution for %s...\n", domain)
			resolvedIP, err := certmanager.VerifyDNS(domain)
			if err != nil {
				fmt.Printf("⚠️  Warning: DNS check warning: %v\n", err)
				fmt.Printf("   (Resolved to: %s; proceeding with ACME challenge...)\n", resolvedIP)
			} else {
				fmt.Printf("✅ DNS verified (points to %s).\n", resolvedIP)
			}
		}

		fmt.Printf("🔐 Requesting TLS certificate for %s via Let's Encrypt (HTTP-01)...\n", domain)
		cert, err := certmanager.IssueCertificate(domain, certEmail)
		if err != nil {
			return fmt.Errorf("certificate issuance failed: %w", err)
		}

		cfg.AddCert(*cert)
		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		fmt.Println("✅ Certificate issued and registered successfully [STAGING]!")
		fmt.Printf("   -> Domain:     %s\n", cert.Domain)
		fmt.Printf("   -> Issuer:     %s\n", cert.Issuer)
		fmt.Printf("   -> Issued:     %s\n", cert.IssuedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("   -> Expires:    %s (approx %d days)\n", cert.ExpiresAt.Format("2006-01-02 15:04:05"), int(time.Until(cert.ExpiresAt).Hours()/24))
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "List managed domains and their certificate issuance & expiration dates",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if len(cfg.Certs) == 0 {
			fmt.Println("No managed domains/certificates found. Use 'xray-proxya cert add <domain>' to add one.")
			return nil
		}

		fmt.Printf("\n%-25s | %-16s | %-19s | %-19s | %-s\n",
			"DOMAIN", "ISSUER", "ISSUED AT", "EXPIRES AT", "ATTACHED PRESET")
		fmt.Println("---------------------------------------------------------------------------------------------------------")

		for _, c := range cfg.Certs {
			issuer := c.Issuer
			if issuer == "" {
				issuer = "Let's Encrypt"
			}
			issuedStr := "-"
			if !c.IssuedAt.IsZero() {
				issuedStr = c.IssuedAt.Format("2006-01-02 15:04:05")
			}
			expiresStr := "-"
			if !c.ExpiresAt.IsZero() {
				expiresStr = c.ExpiresAt.Format("2006-01-02 15:04:05")
			}

			// Check attached presets
			var attached []string
			for i, p := range cfg.Presets {
				if strings.EqualFold(p.SkinDomain, c.Domain) || (p.Skin != "" && strings.EqualFold(p.SNI, c.Domain)) {
					attached = append(attached, fmt.Sprintf("#%d (%s)", i+1, p.Mode))
				}
			}
			attachedDesc := "-"
			if len(attached) > 0 {
				attachedDesc = strings.Join(attached, ", ")
			}

			fmt.Printf("%-25s | %-16s | %-19s | %-19s | %-s\n",
				c.Domain, issuer, issuedStr, expiresStr, attachedDesc)
		}
		fmt.Println()
		return nil
	},
}

var certRemoveCmd = &cobra.Command{
	Use:   "remove [domain]",
	Short: "Remove a managed domain & certificate, automatically disabling any dependent presets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[0])), ".")
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		disabled, err := certmanager.RemoveCertificate(cfg, domain)
		if err != nil {
			return err
		}

		if len(disabled) > 0 {
			for _, id := range disabled {
				fmt.Printf("⚠️  Preset #%d was automatically DISABLED because domain %s was removed.\n", id, domain)
			}
		}

		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		fmt.Printf("✅ Domain %s and its certificate files have been removed [STAGING].\n", domain)
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

var certRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Check and renew certificates expiring within 7 days (or force with --force)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if len(cfg.Certs) == 0 {
			fmt.Println("No certificates to renew.")
			return nil
		}

		renewed, expiredFailed, err := certmanager.CheckAndRenewCerts(cfg, certForce)
		if err != nil {
			return err
		}

		for _, d := range renewed {
			fmt.Printf("✅ Successfully renewed certificate for %s.\n", d)
		}
		for _, d := range expiredFailed {
			fmt.Printf("🚨 Alert: Certificate for %s expired and renewal failed. Dependent presets have been disabled.\n", d)
		}

		if len(renewed) == 0 && len(expiredFailed) == 0 {
			fmt.Println("All certificates are healthy (no renewals required).")
			return nil
		}

		if err := cfg.SaveEx(true); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		fmt.Println("🚀 Run 'apply' to commit changes.")
		return nil
	},
}

func init() {
	certAddCmd.Flags().StringVar(&certEmail, "email", "", "Contact email for ACME account registration")
	certAddCmd.Flags().BoolVar(&certSkipDNS, "skip-dns", false, "Skip DNS pre-validation check")
	certRenewCmd.Flags().BoolVarP(&certForce, "force", "f", false, "Force renewal regardless of expiration date")

	certCmd.AddCommand(certAddCmd, certListCmd, certRemoveCmd, certRenewCmd)
	rootCmd.AddCommand(certCmd)
}
