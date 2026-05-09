```
                    ...*#=..                    
                ..--:+..                    
                ..:*#...                    
                  .%+                       
                 .:%=                       
                ..-@-                       
                ..+@.                       
                ..*@.                       
             ....-**.....                   
             ....=#+....                    
           ..-=-=#%#......                  
             .:*%%##%%+:.                   
             ...-*#@:....                   
             ...:=%......                   
             ...-#+.....                    
             ...*##.....                    
             ..:#%%.....                    
             ...=%-                         
             ...*+.                         
             ..=**.                         
             ..+*#:                         
             ..+*%.                         
        .......++#.                         
        ......:+*+.                         
        ...=..-+#-.                         
       ....+..++#:.                         
       ..+*-..*+#..                         
       .:+:...**#..                         
       .:+...-***..                         
       .:+==:-*#+..                         
      ..:=+***+#+:......                    
      ..=+*+*#+#*.......                    
      ...*+*++#**-.-....                    
   .....=:++*+*+*::+.....                   
   ....-+:+++++==++=....                    
   ...:*++++*=++*+++*-..                    
 ......=**=++++++++++#:......               
...-*:=#+*+*#+-+++++*#*==+=....             
  ..*#%**=++==*+++****+#%*=#%...            
.=**+++=++=-++#*++*#==*#*#%=*+=:....        
..===***+=+=++====++=++*+++***###+=%@#-..   
  .-**-++=+++===++++==**=+**=**#**#:*.-*.   
.=+***==++:-=+==+==+=++***++=*+*#*=*#%@@@###*.....
.=##*+---=**+=++====+++++**#####+=++#%#++*%%%@%%#%%%#+.
.:###***+*+==-==+******+====+==+++++*##*==+#***+++*#%##*
.-%##*++*++==============-=====+++++++++=+*%#***#%%%@@@#
.+@%%####****+*****#**#####**#%%####*#%%%%%@@@@@@@@@@@@#
.:%@%%%%%####*********####%%%%%%%%%@@@@@@@@@@@@@@@@@@@%-
....:*%%%%%%############%%%%%%@@@@@@@@@@@@@@@@@@%#=.....
     .........:-=+**#%@@@@@@@@@@@#*+=-:............     

                  🔥  B O N F I R E
```

<div align="center">

![Version](https://img.shields.io/badge/version-0.1.0-orange?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-blue?style=flat-square)
![Kernel](https://img.shields.io/badge/kernel-5.8%2B-green?style=flat-square)
![eBPF](https://img.shields.io/badge/powered%20by-eBPF-cyan?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow?style=flat-square)

**A lightweight, passive Linux kernel behavior monitoring tool**
**that provides real-time syscall tracing and rule-based intrusion detection using eBPF.**

</div>

---

## Overview

Bonfire is a **passive security observer** — it hooks into the Linux kernel using eBPF, captures system calls in real time, evaluates them against a configurable rule engine, and surfaces alerts through a structured terminal interface.

> Observe everything. Interfere with nothing. Alert on what matters.

Bonfire is intentionally **read-only**. It never modifies, blocks, or interferes with kernel behavior. It acts like a security camera for your system — always watching, never touching.

---

## Features

- Real-time syscall monitoring via eBPF tracepoints (`execve`, `connect`)
- Rule-based intrusion detection with 11 built-in detection rules
- Sequence/correlation engine for multi-step attack chain detection
- Tiered structured logging — hot JSON logs, warm compressed archives, cold SQLite alert database
- Live terminal dashboard with event feed, alert panel, and system metrics
- Alert inspector with filtering by severity, rule, time range, process, and free text
- Rules viewer with per-rule hit counts and full condition breakdown
- Rule builder for adding custom detection rules from the terminal
- Minimal overhead — CPU footprint under 1% thanks to eBPF

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Linux kernel | 5.8 or higher |
| Python | 3.10 or higher |
| Architecture | x86_64 |

Dependencies are installed automatically by the installer. See `dependencies.json` for the full list.

---

## Installation

```bash
git clone https://github.com/yourname/bonfire.git
cd bonfire
sudo bash installer.sh
```

The installer will verify file integrity, install all dependencies, copy files to `/opt/bonfire/`, and register the `bonfire` command.

---

## Usage

```bash
sudo bonfire <command>
```

| Command | Description |
|---------|-------------|
| `dashboard` | Launch live terminal dashboard |
| `monitor` | Standalone terminal mode |
| `alerts` | Alert inspector with filters |
| `rules` | Rules viewer |
| `rules-add` | Add a new detection rule (root only) |
| `help` | Show usage information |

---

## Dashboard

```
┌─────────────────────────────────────────────────────────────────┐
│  🔥 BONFIRE  │  uptime: 00:07:32  │  2025-01-15  14:32:07 UTC  │
│  CPU: 0.3%  Threads:[0,1,0,1]  MEM:51%  DISK R:0KB  NET ↑↓    │
├──────────────────┬──────────────────────────┬───────────────────┤
│   ALERTS (20%)   │    SYSCALL FEED (55%)     │   METRICS (25%)   │
│                  │                           │                   │
│  ⚠ R001 CRIT    │  EXECVE  bash  /bin/ls    │  execve/min: 30   │
│  🔴 R102 SEQ    │  CONNECT curl  1.2.3.4    │  connect/min: 2   │
│                  │  ...                      │  total alerts: 3  │
└──────────────────┴──────────────────────────┴───────────────────┘
```

| Key | Action |
|-----|--------|
| `P` | Pause / resume event feed |
| `C` | Clear event feed |
| `Q` | Quit |

---

## Detection Rules

Bonfire ships with 11 built-in rules and supports custom rules via `bonfire rules-add`.

| Rule | Name | Event | Severity |
|------|------|-------|----------|
| R001 | Shell Spawned by Web Process | execve | CRITICAL |
| R002 | Outbound on Suspicious Port | connect | HIGH |
| R003 | Sensitive File Access | execve | HIGH |
| R004 | Privileged Process Execution | execve | HIGH |
| R005 | Outbound to Non-RFC1918 Address | connect | MEDIUM |
| R006 | Execution from Temporary Directory | execve | HIGH |
| R007 | Network Tool Execution | execve | MEDIUM |
| R008 | High Argument Count Execution | execve | MEDIUM |
| R009 | Suspicious Parent Chain | execve | HIGH |
| R010 | High Port Outbound Connection | connect | MEDIUM |
| R011 | Root Network Activity | connect | HIGH |

**Sequence rules** (multi-step detection):

| Rule | Name | Severity |
|------|------|----------|
| R100 | Reverse Shell Detected | CRITICAL |
| R101 | Webshell Activity | CRITICAL |
| R102 | Suspicious Execution Followed by Network | CRITICAL |

---

## Project Structure

```
bonfire/
├── scripts/
│   ├── main/
│   │   ├── monitor.py          # eBPF loader and event coordinator
│   │   ├── events.py           # Event dataclasses
│   │   ├── rules.py            # Rule engine
│   │   ├── correlator.py       # Sequence detection engine
│   │   ├── logger.py           # Storage coordinator
│   │   ├── metrics.py          # Hardware and event metrics
│   │   ├── cli.py              # Live terminal dashboard
│   │   ├── alerts_viewer.py    # Alert inspector UI
│   │   ├── alerts_query.py     # Alert database queries
│   │   ├── rules_viewer.py     # Rules viewer UI
│   │   ├── rules_query.py      # Rules data layer
│   │   ├── rule_add.py         # Rule builder entry point
│   │   ├── rule_form.py        # Rule builder UI
│   │   ├── rule_builder.py     # Rule builder logic
│   │   ├── ebpf/
│   │   │   ├── execve.c        # eBPF hook — process execution
│   │   │   └── connect.c       # eBPF hook — network connections
│   │   └── workers/
│   │       ├── hot.py          # Real-time JSON log writer
│   │       ├── cold.py         # SQLite alert storage
│   │       ├── dedup.py        # Log deduplication worker
│   │       └── warm.py         # Log compression and archiving
│   └── rules/
│       └── default.yaml        # Detection rule definitions
├── hash.json                 # File integrity manifest
├── dependencies.json           # Dependency definitions
├── installer.sh                # Automated installer
└── README.md
```

---

## Storage

Bonfire uses a three-tier storage system created automatically at runtime under `/opt/bonfire/scripts/storage/`:

| Layer | Path | Format | Retention |
|-------|------|--------|-----------|
| Hot | `hot/` | JSON newline-delimited | Until 50MB rotation |
| Warm | `warm/` | gzip compressed | 30 days |
| Cold | `cold/alerts.db` | SQLite | Indefinite |

---

## How It Works

```
Kernel Space                         User Space
────────────────────                 ──────────────────────────
Process calls execve()      →        monitor.py receives event
eBPF tracepoint fires       →        Converted to dataclass
Data sent via ring buffer   →        Rule engine evaluates
                                          ↓            ↓
                                     No match      Alert fired
                                     Log event     Log to SQLite
                                          ↓            ↓
                                     CLI dashboard — live display
```

---

## Disclaimer

Bonfire is designed for **defensive security monitoring** on systems you own or have explicit permission to monitor. It operates in observe-only mode and never modifies system behavior.

---

<div align="center">
<sub>Built with 🔥 on Linux using eBPF</sub>
</div>
