# RMM Abuse Map

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Map abused RMM / ScreenConnect installers to relay hosts and campaign clusters.**

Legitimate remote monitoring tools (ScreenConnect / ConnectWise Control, and friends) are heavily abused as phishing second stages. The relay host often sits in plain sight on the client command line (`h=…`) or in `/Bin/` installer URLs — but defenders lack a small, open tool to **parse → cluster → pivot**.

Built by [Cipher Cortex](https://ciphercortex.com) · Case methodology from [Intercept Cell](https://ciphercortex.com/research).

---

## Quick start

```bash
git clone https://github.com/CipherCortex/rmm-abuse-map.git
cd rmm-abuse-map
pip install -e .

# Parse sample command lines and cluster by relay
rmm-abuse-map parse -f fixtures/sample_cmdlines.txt --cluster
```

```bash
rmm-abuse-map parse -s 'ScreenConnect.Client.exe "?e=Access&h=evil.example&p=443"'
```

## What it extracts

| Field | Source |
|-------|--------|
| `relay_host` | `h=` query/cmdline param, or hostname of `/Bin/` MSI URL |
| `relay_port` | `p=` |
| `mode` | `e=` (Access / Support / Guest / …) |
| `urls` / `msi_names` | Embedded HTTP(S) and `.msi` names |
| `binary_hint` | `ScreenConnect.Client.exe` / Control client |

## Related tools

| Tool | Role |
|------|------|
| [hijacked-infra-hunt](https://github.com/CipherCortex/hijacked-infra-hunt) | Aged / compromised web infra hosting lures |
| [lure-lineage](https://github.com/CipherCortex/lure-lineage) | Fingerprint the HTML that drops the MSI |
| [evidence-pack](https://github.com/CipherCortex/evidence-pack) | Hash-verified capture of installers & pages |

## License

MIT © Cipher Cortex
