# Privileged Capabilities

AdByG0d includes several capabilities that introduce significant operational risk when enabled. They are disabled by default and require explicit opt-in through environment variables. This document describes what each capability does, what attack surface it opens, and the minimum controls required before enabling it.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

> These capabilities are designed for authorized engagements in isolated lab environments under direct operator control. Enabling them in an uncontrolled or shared environment is a serious security risk.

---

## Overview

| Flag | What it enables | Risk level |
|---|---|---|
| `ENABLE_COMMAND_EXECUTION` | AD command catalog execution from the web UI | High |
| `ENABLE_AI_ARBITRARY_SHELL` | AI operator shell tool — arbitrary shell execution | Critical |
| `ENABLE_CHAIN_BUILDER` | Multi-step automated operation chains | High |
| `ENABLE_TUNNEL_MANAGEMENT` | Chisel / ligolo-proxy tunnel lifecycle | High |

All flags default to `false`. Setting any of them to `true` must be a deliberate, documented decision with explicit justification for the specific engagement or lab environment.

---

## `ENABLE_COMMAND_EXECUTION`

### What it does

Enables the `/api/ad-commands/execute` family of endpoints. These endpoints accept a technique ID and target parameters, build the corresponding command from the AD command catalog, and execute it on the assessment host using the configured execution backend.

The command catalog covers tools including BloodHound, Impacket, Certipy, Rubeus, CrackMapExec, Netexec, and native LDAP queries. Output is streamed in real time to the web interface.

### Attack surface

- Any authenticated user can trigger command execution if this flag is set. Role-based limits apply (analyst role required), but a compromised analyst account can run any catalog command.
- The execution host network access determines the blast radius. If the assessment host can reach production domain controllers, so can every command triggered through this interface.
- Command injection is mitigated through parameterized catalog entries, but the techniques themselves perform active AD operations — Kerberoasting, AS-REP roasting, coercion, relay — against the target domain.

### Required controls before enabling

- The deployment must be on an isolated assessment host with network access limited to the authorized target domain only
- All users with analyst access must be the authorized assessment team only
- Enable only during active assessment windows, not persistently
- Audit log must be reviewed for all execution events after the engagement

---

## `ENABLE_AI_ARBITRARY_SHELL`

### What it does

Enables the `shell` tool in the AI operator tool set. This allows the AI to execute arbitrary shell commands on the assessment host — not just catalog commands, but any command the AI decides to run based on its reasoning.

Requires `ENABLE_COMMAND_EXECUTION=true` to also be set.

Each shell invocation is surfaced in the web interface with the command and output visible. The AI does not execute commands silently — every invocation is shown to the operator in real time. Human review of each suggested command is expected before execution in agentic mode.

### Attack surface

- This is the highest-risk capability in the platform. The AI can be prompted by assessment findings or user input to execute commands that reach beyond the intended target scope.
- Prompt injection via crafted AD object names or GPO descriptions could influence AI reasoning if imported evidence is not sanitized — although the API sanitizes field values, defense in depth requires the operator to review every AI-proposed action.
- A compromised AI provider API key combined with this flag could allow a third party to execute arbitrary commands on the assessment host if the session is active.

### Required controls before enabling

- The assessment host must be fully isolated — no production network access, no shared credentials
- Do not enable persistent agentic auto-run mode without a human in the review loop
- Rotate provider API keys after each engagement
- Review the AI operator audit trail in full after each session
- Enable only when an operator is actively monitoring the session

---

## `ENABLE_CHAIN_BUILDER`

### What it does

Enables the operation chain builder, which sequences multiple technique executions into an automated workflow. A chain can include credential harvesting steps, relay triggers, hash cracking submission, and lateral movement probes, executed in order with conditional branching.

Chains are stored and can be replayed. A saved chain can execute a complete multi-phase operation against the target domain from a single trigger.

### Attack surface

- Chains automate what would otherwise require individual manual triggers, increasing the speed and scope of operations against the target
- A stored chain triggered accidentally or by a wrong-environment deployment could cause rapid unintended impact on the target domain
- Chains that include persistence or modification steps — account creation, GPO edits — require careful scoping review before use

### Required controls before enabling

- Review every step of a chain before executing it, especially in environments with real user accounts
- Tag chains with the engagement scope and do not import chains across engagements
- Disable after the engagement — do not leave chains in a persistent deployment

---

## `ENABLE_TUNNEL_MANAGEMENT`

### What it does

Enables the tunnel management endpoints that control Chisel and ligolo-proxy processes on the assessment host. The API can start, stop, and query tunnel sessions, and configure routing through established tunnels.

Tunnels allow the assessment tooling to reach network segments that are not directly accessible from the assessment host — internal subnets, jump hosts, and isolated VLAN targets.

### Attack surface

- An established tunnel represents a persistent network path from the assessment host into the target environment. If the assessment host is compromised while a tunnel is active, the attacker gains the same network access.
- Tunnel profiles are stored in the database. A leaked database backup with active tunnel credentials enables replay attacks.
- ligolo-proxy route commands modify the assessment host's routing table. Misconfigured routes can cause traffic from the assessment host to traverse unintended paths.

### Required controls before enabling

- Tear down all tunnels at the end of each assessment session — do not leave tunnels running overnight or unattended
- Use dedicated tunnel credentials per engagement — never reuse tunnel server keys
- Review the assessment host's routing table after stopping tunnels to confirm no residual routes remain
- Store tunnel profiles only in encrypted storage

---

## General guidance for all privileged capabilities

1. **Default to off.** If you are not actively using a capability right now, the flag should be `false`. Remove it from the environment between assessments.

2. **Isolate the deployment.** Assessment deployments with any of these flags enabled should not share infrastructure with non-assessment workloads. Use dedicated VMs or containers.

3. **Monitor the audit log.** All write operations and execution events are logged. Review `GET /api/audit` regularly during active engagements.

4. **Scope by role.** Only the minimum required analyst accounts should have access to the deployment. Remove access when the engagement ends.

5. **Separate credentials.** Use dedicated service accounts, API keys, and credentials for each engagement. Do not reuse credentials across engagements or environments.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
