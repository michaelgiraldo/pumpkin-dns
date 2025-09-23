# DNSSEC Health Check

Author: Michael Giraldo  \
Copyright © Michael Giraldo. Licensed under the MIT License.

`dnssec_health_check.sh` is a battle-tested DNS posture inspector designed to give operators a concise, trustworthy view of their domain’s delegation, DNSSEC, resolver validation, and email-related records. The script reflects decades of operating DNS infrastructure and focuses on clean CLI ergonomics, accurate parsing, and human-friendly output.

---

## Highlights

- **Delegation validation** – compares TLD (registry) and zone NS sets, and shows what differs when they don’t match.
- **Authoritative snapshots** – queries each authoritative nameserver for DNSKEY/SOA/NS/A/AAAA/MX/SPF/DMARC/DKIM, marking what is present or missing.
- **Resolver health** – checks multiple public resolvers (Google, Cloudflare, Quad9, Neustar, OpenDNS) for DS/DNSKEY visibility and authenticated (`ad`) responses.
- **MX discovery** – lists the MX host/priority set it actually finds and verifies their A/AAAA targets from both authoritative and recursive views.
- **Email TXT overview** – surfaces SPF, DMARC, and DKIM contents to accelerate troubleshooting.
- **Watch mode** – optional repeated runs until DNSSEC validation succeeds, ideal during cutovers.

---

## Requirements

- macOS or Linux with `/bin/bash` (Bash 3.2+)
- `dig` (macOS ships one; otherwise install via package manager)

No other dependencies are required.

---

## Quick Start

```bash
chmod +x dnssec_health_check.sh
./dnssec_health_check.sh example.com
```

Frequent re-check (every five minutes):

```bash
./dnssec_health_check.sh example.com --watch 300
```

Include custom DKIM selectors:

```bash
./dnssec_health_check.sh example.com --dkim google,selector2
```

Override authoritative nameservers (skips auto-detection):

```bash
./dnssec_health_check.sh example.com --no-auto-ns --ns ns1.example.net,ns2.example.net
```

---

## CLI Reference

```text
dnssec_health_check.sh [domain] [options]

Options
  --domain <name>        Domain to inspect (positional domain also accepted)
  --watch <seconds>      Repeat checks at the given interval (0 runs once)
  --dkim s1,s2,...       Comma/space separated DKIM selectors to query
  --auto-ns              Auto-detect zone nameservers (default)
  --no-auto-ns           Skip auto detection; rely on --ns or env override
  --ns ns1,ns2,...       Explicit authoritative nameservers
  --version              Print version
  -h, --help             Show usage

Environment Variables mirror the flags: DOMAIN, INTERVAL, DKIM_SELECTORS,
AUTO_NS, AUTHORITATIVES.
```

---

## Output Cheatsheet

- **Summary** – quick badges for delegation, resolver DNSSEC (`ad` flag), MX presence, SPF, and DMARC.
- **Delegation** – parent vs child NS listings; highlights what only appears on one side.
- **Authoritative nameservers** – table per NS with ✅ (present), 🚫 (missing), ❌ (failure).
- **Parent DS / Child DNSKEY** – concise answer sections from `dig +dnssec`.
- **Resolver validation** – whether public resolvers see DS/DNSKEY and return authenticated answers.
- **MX records** – host/priority list and target resolution from authoritative and recursive perspectives.
- **Email TXT sanity** – SPF and DMARC status with raw values; DKIM selectors sampled.

---

## Exit Codes

- `0` – Script completed (warnings or missing records are surfaced in the report).
- `1` – Invalid usage (missing domain, unknown option, missing tools).

Operational issues (e.g., unreachable nameservers) are reported in-line rather than forcing a non-zero exit; this keeps the output readable for runbooks while still indicating problems in the summary.

---

## License

This project is released under the [MIT License](LICENSE). © Michael Giraldo.

