# Authentic Skin v3: High-Fidelity Decoy Camouflage & Active Probing Defense

## 1. Background & Core Design Principles

In modern network environments, censorship systems and active probing tools have evolved far beyond analyzing single SNI strings or plain HTTP 404 status codes. Traditional camouflage approaches suffer from notable vulnerabilities:

1. **Pure SNI Camouflage**: Susceptible to follow-up probes detecting IP-to-certificate fingerprint mismatches, leading directly to blocking.
2. **Static Error Pages or Crude Proxies**: Easily identified by deep HTTP path crawlers, API endpoint scanners, and form-submission probes.
3. **Timing Discrepancies**: Fake sites handling credential validation (e.g. random login attempts) lack real password hashing computation (such as bcrypt or Argon2) and often respond with 401/403 errors within a few milliseconds. In contrast, genuine enterprise cloud instances typically require hundreds of milliseconds to evaluate credentials. Probing systems exploit this distinct timing window to flag decoy endpoints with high confidence.

The core philosophy of **Authentic Skin v3** is: **Fully interactive, pixel-perfect replication, indistinguishable behavior, and timing-attack defense**. The system embeds high-fidelity web replicas of mainstream private cloud and file management software directly into the Go binary, with an integrated automated Let's Encrypt certificate issuance and renewal lifecycle.

---

## 2. Supported Decoy Applications

Authentic Skin v3 delivers pixel-perfect replicas of three widely deployed self-hosted cloud storage systems:

| Skin Identifier | Target System & Version | Signature Endpoints & High-Fidelity Support |
| :--- | :--- | :--- |
| **`nextcloud`** | **Nextcloud Hub (v34)** | • Dynamic CSRF token generation and cookie rotation<br>• `/login/flow` handshake and genuine `status.php` outputs<br>• Capabilities API (`/ocs/v2.php/cloud/capabilities`) responses<br>• Complete Material Design / Vue frontend assets and theme stylesheets |
| **`filebrowser`** | **File Browser (v2.63)** | • Authentic bundled frontend static assets and webfonts<br>• API probing whitelist enforcement and `/api/login` authentication flows<br>• Exact alignment with official redirects and HTTP security headers |
| **`seafile`** | **Seafile Community (v11)** | • Complete Seahub login form and CSRF verification<br>• Genuine 404 fallback page and `/accounts/password/reset/` password reset view<br>• Full FontAwesome icon sets and media assets |

All static assets are bundled directly into the executable binary via Go 1.16+ `embed.FS`, eliminating any runtime dependencies on external HTML/CSS asset directories on the host.

---

## 3. Security Defenses & Core Mechanisms

### 3.1 Timing-Attack Defense
To protect against active probing based on response latency analysis, Authentic Skin v3 incorporates a **realistic delay simulation engine** on all credential authentication and submission endpoints (such as POST requests):
* Whenever an invalid or probing credential is submitted, the request handler simulates authentic password hashing processing time by injecting a **400ms – 700ms normal randomized delay**.
* Once the delay elapses, the engine returns authentic error notices, redirection headers, or JSON payloads matching genuine applications. Both manual inspectors and automated probing scanners are prevented from distinguishing decoy services from real instances in the time domain.

### 3.2 Port Roles & ACME Challenge Delegation
When operating alongside underlying Xray REALITY / Inbound configurations, the system uses distinct port responsibilities:
1. **Port 80 (HTTP)**:
   * Runs an integrated HTTP redirector and ACME challenge host.
   * Standard web requests receive a `301 Moved Permanently` redirect to the corresponding HTTPS domain.
   * When Let's Encrypt triggers an ACME HTTP-01 validation, the server intercepts `/.well-known/acme-challenge/*` in-memory and serves the appropriate challenge token, **enabling automated, seamless certificate renewals**.
2. **Port 443 (Public Inbound)**:
   * The Xray core listens on public port 443, handling incoming REALITY / TLS handshakes.
   * Authorized proxy clients establish tunnels using configured private keys and UUIDs.
   * Unauthorized crawlers, scanners, or active probing connections are directed by REALITY's `dest` fallback rule to the local camouflage reverse proxy.
3. **Port 9443 (Local Camouflage Reverse Proxy)**:
   * Bound exclusively to `127.0.0.1:9443` and inaccessible externally.
   * Terminates TLS using valid domain certificates and routes requests to the corresponding high-fidelity decoy web instance.

### 3.3 Expiration Safety Fuse
* Inbound presets enabling camouflage (`--skin`) must be explicitly bound to a domain possessing a valid managed certificate (`--skin-domain`).
* The system continuously runs certificate health checks in the background. If a bound certificate is manually deregistered (`cert remove`) or expires without successful auto-renewal, the system activates an **automatic safety fuse**, shutting down the dependent preset inbound to prevent exposing bare, unauthenticated connections.

---

## 4. Quick Configuration Guide

> **Prerequisites**: Ensure you have a domain pointing to your server's public IP address, with TCP ports 80 and 443 opened in your firewall and cloud security groups.

### Step 1: Issue a Let's Encrypt Certificate (Root Shell)
Execute certificate issuance from a direct root shell:
```bash
# Automatically complete HTTP-01 challenge on port 80 and issue a TLS certificate
xray-proxya cert add sea.example.com
```
Inspect issued certificates and validity dates:
```bash
xray-proxya cert list
```

### Step 2: Bind Authentic Camouflage to a Preset
Configure a preset (e.g. Preset 1: VLESS Reality) on a Server role with Seafile camouflage and the certified domain:
```bash
# Configure skin and domain binding in STAGING
xray-proxya presets set 1 --skin seafile --skin-domain sea.example.com
```

Inspect the preset configuration status:
```bash
xray-proxya presets list
```
The `SKIN` column will clearly display `seafile (sea.example.com)`.

### Step 3: Apply and Activate
Validate and restart managed services via `apply`:
```bash
xray-proxya apply
```
Once applied, visiting `https://sea.example.com` in a web browser displays the genuine Seafile login interface. Submitting invalid credentials triggers a realistic verification delay followed by authentic rejection notices, effectively thwarting active probing analysis.

---

## 5. Operations & Troubleshooting

* **Port 80 Collisions**: If third-party web servers such as Nginx, Caddy, or Apache are already listening on port 80, certificate issuance and background renewals will fail due to port binding errors. Stop conflicting services or reserve ports 80 and 443 exclusively for Xray-Proxya.
* **Health Diagnostics**: Run `xray-proxya doctor check` to perform automated host inspection, scanning for port collisions, UDP reachability, and clock synchronization skew.
