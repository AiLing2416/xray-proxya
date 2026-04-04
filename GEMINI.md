# Xray-Proxya Development Guidelines

This file contains foundational mandates for the AI Assistant working on this project. These instructions take absolute precedence over general workflows.

## Core Directives

1.  **Architecture:** The project is migrating from Bash to Go. Follow standard Go project layouts and idiomatic Go practices.
2.  **Architecture Compatibility:**
    *   Development environment is primarily **Arm64** (Linux).
    *   The compiled binaries must be compatible with both **Amd64** and **Arm64** architectures.
    *   Builds must use **pure static linking** (e.g., `CGO_ENABLED=0`) to ensure they can run on any system without glibc/musl dependency issues.
3.  **Rootless Execution:**
    *   The application must be designed to run **rootless** (without root/sudo privileges).
    *   Default paths for configuration and data should be placed in user-space directories (e.g., `~/.config/xray-proxya`, `~/.local/share/xray-proxya`) rather than system-wide paths like `/etc` or `/var`.
    *   Assume port bindings will be > 1024 by default to avoid permission issues.
4.  **Xray Compatibility:**
    *   Only support the **latest Xray features and formats**.
    *   Do NOT maintain backward compatibility for older V2Ray/Xray formats or deprecated transport protocols.
5.  **Reality Domain Strategy:**
    *   Use a **domain table mechanism** to select SNI domains.
    *   Explicitly **exclude** Apple and Microsoft related domains (e.g., apple.com, microsoft.com, windows.com).
    *   Prefer high-traffic, neutral domains (e.g., cloudflare.com, amazon.com, etc.).
6.  **Cleanup & Modernization:**
    *   Remove legacy features such as "High Performance Mode" and other redundant Bash-era variables.
7.  **CLI & Preset Strategy:**
    *   Prioritize **Preset Modes** (pre-defined protocol combinations) for ease of use.
    *   Implement "Composite Modes" (parameterized protocol values) as an advanced feature later.
8.  **Validation & Safety:**
    *   Any configuration change must be validated by spawning a temporary Xray process with a temporary config file.
    *   If validation fails, the application must return an error and not apply the changes.
9.  **Testing Environment:**
    *   If cross-system testing is required, the AI is authorized to create user-mode QEMU virtual machines (via creating a Skill) to validate builds and execution on different architectures or basic OS environments.

