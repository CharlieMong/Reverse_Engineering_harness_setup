# Reverse_Engineering_harness_setup

How to use the Harness

You will need hexstrike-ai set up and working before following this guide. Their awesome tool can be found here on the github.

### On WSL
```
wsl python3 /mnt/c/Install/Location/hexstrike-ai/re_harness.py \
    /mnt/c/Install/Location/hexstrike-ai/BINARY.exe \
    --skip-ghidra \
    --outdir /tmp/BINARY_re
```

To get the report. 
```
wsl cp /tmp/BINARY_re/re_report.html /mnt/c/Username/Desktop/re_report.html
```
# What it does
## Overview

`re_harness.py` is an automated binary analysis framework that orchestrates multiple reverse engineering tools to produce a comprehensive HTML report detailing security posture, attack surface, and vulnerability indicators for executable binaries.

**Designed for:** authorized security assessments, CTF events, malware analysis, and binary security auditing.

---

## Quick Start

### Basic Usage

```bash
python3 re_harness.py /path/to/binary.exe
```

Output:

- HTML report: `<binary_name>_re_results/re_report.html`
- JSON data: `<binary_name>_re_results/re_data.json`

### Options

```bash
# Skip slow tools for quick triage
python3 re_harness.py binary.exe --skip-ghidra --skip-capa --skip-floss

# Custom Ghidra installation path
python3 re_harness.py binary.exe --ghidra-home /opt/ghidra_11.0

# Custom output directory
python3 re_harness.py binary.exe --outdir ./my_analysis

# Combine options
python3 re_harness.py binary.exe --skip-ghidra --skip-capa --outdir /tmp/output
```

---

## Architecture

### Phase 1: Binary Identification (Tool: `file`)

```
file /path/to/binary
```

Returns executable type, architecture, and basic metadata:

- PE32/PE32+, ELF, Mach-O
- Architecture (x86, x64, ARM, etc.)
- Stripped/unstripped status

### Phase 2: Static String Extraction (Tools: `strings`, `r2`)

**Standard strings** (`strings` command):

- Printable ASCII and Unicode strings
- Minimum length: 6 characters (configurable)
- Used for initial reconnaissance

**Radare2 strings** (`r2 iz`):

- Both dynamically and statically extracted strings
- Section-specific string identification
- Includes offset information

**FLOSS obfuscated strings** (`floss`):

- Decodes obfuscated strings (XOR, substitution, stack-built)
- Detects layered string encoding
- Useful for malware and packed binaries

### Phase 3: Security Mitigations (Tools: `checksec`, `r2`)

Checks for presence/absence of exploit mitigations:

|Mitigation|What it does|Detected by|
|---|---|---|
|**NX/DEP**|Prevents code execution in data sections (stack, heap)|checksec, r2|
|**PIE**|Position-independent executable — randomises code base|checksec, r2|
|**Stack Canary**|Detects stack smashing via stack cookie|checksec|
|**RELRO**|Prevents GOT (Global Offset Table) overwrite|checksec, r2|
|**ASLR**|OS-level address space randomisation|r2|

**Risk correlation:** Missing mitigations increase exploitability of memory corruption bugs.

### Phase 4: Radare2 Deep Analysis (Tool: `r2`)

Headless radare2 commands run in sequence:

```r2
iI              # Binary info (headers, entry point, etc.)
aaa; afl        # Auto-analysis + function list
ii              # Imports (DLL/SO dependencies)
iE              # Exports
iS entropy      # Section entropy (detects packing/encryption)
iz              # Strings
i~pic,canary... # Security flags summary
```

**Output includes:**

- Function names and entry points
- Imported functions and DLLs
- Exported symbols
- Section entropy (0–8 range; >7 indicates compression/encryption)

### Phase 5: Ghidra Headless Analysis (Optional, Tool: `Ghidra`)

Runs Ghidra's headless analyser:

```bash
analyzeHeadless <project> <name> -import <binary> -postScript PrintXRefsScript.java
```

**Limitations on Windows/WSL:**

- Slow (2–5 minutes for typical binaries)
- Requires JVM
- Often skipped in triage mode

**Output:**

- Cross-reference maps
- Call graphs (if available)
- Decompiled code snippets (via custom scripts)

### Phase 6: Capability Detection (Optional, Tool: `capa`)

Mandiant's `capa` tool detects high-level executable capabilities:

```bash
capa -j binary.exe
```

**Detects:**

- Credential access (keylogging, password scraping)
- Persistence mechanisms (registry modification, service creation)
- Command & control communication patterns
- Privilege escalation techniques
- File manipulation

Returns JSON with tactics/techniques and matching offsets.

### Phase 7: Packer Detection (Tool: `detect-it-easy`)

Identifies packers, protectors, and obfuscators:

```bash
diec binary.exe
```

**Detects:**

- UPX, MPRESS, PECompact, ASPack
- Custom packers
- Virtualisation-based protection
- Code signing and certificate info

### Phase 8-9: Analysis & Report Generation

Combines all tool outputs to:

1. **Flag dangerous imports** — matches against hardcoded list
2. **Flag suspicious strings** — regex pattern matching
3. **Calculate risk score** (0–100)
4. **Generate HTML report** with visualizations

---

## Analysis Techniques

### Dangerous Imports Matching

The harness maintains a registry of functions known to be security-relevant:

```python
DANGEROUS_IMPORTS = {
    "strcpy":           ("High",   "Buffer overflow (no bounds check)"),
    "system":           ("High",   "OS command execution"),
    "WriteProcessMemory": ("High", "Process injection"),
    "CreateRemoteThread": ("High", "Remote thread injection"),
    "LoadLibrary":      ("Medium", "Dynamic library loading (DLL injection risk)"),
    "memcpy":           ("Low",    "Memory copy (bounds checking required)"),
    ...
}
```

**Logic:**

1. Extract all imports from radare2 output
2. For each import, check against the registry
3. Group by severity (High/Medium/Low)
4. Generate findings with descriptions

**Why this matters:**

- `strcpy` + missing NX = reliable stack buffer overflow
- `CreateRemoteThread` + `WriteProcessMemory` = process injection capability
- `system`/`popen` without input validation = command injection risk

### Suspicious Strings Pattern Matching

Detects indicators of malicious intent via regex:

```python
SUSPICIOUS_STRINGS = {
    r"(cmd\.exe|/bin/sh|/bin/bash)":              ("High",   "Shell invocation string"),
    r"(powershell|pwsh)":                          ("High",   "PowerShell invocation"),
    r"(http[s]?://|ftp://)":                       ("Medium", "Network URL"),
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})":     ("Low",    "IP address"),
    r"(HKEY_|HKLM|HKCU)":                          ("Medium", "Registry key string"),
    r"(CreateMutex|Global\\\\)":                   ("Medium", "Mutex (C2 beacon indicator)"),
    r"(admin|password|passwd|secret|token)":      ("Medium", "Credential-related string"),
    r"(UPX|MPRESS|ASPACK)":                        ("Medium", "Packer signature string"),
    ...
}
```

**Examples:**

- Presence of `cmd.exe` + `system()` import = likely OS command execution
- Registry strings + `RegSetValue` import = registry modification capability
- URL + socket APIs = network communication capability
- Mutex name like `Global\WinlogonMutex` = single-instance or C2 beacon

### Risk Scoring Algorithm

Produces a 0–100 score reflecting exploitability and malicious intent:

```
base_score = 0

For each High severity finding:   base_score += 10
For each Medium severity finding: base_score += 5
For each Low severity finding:    base_score += 2

Mitigations (deductions):
  - NX/DEP enabled:      base_score -= 10
  - PIE enabled:         base_score -= 8
  - Stack canary:        base_score -= 8

final_score = min(100, max(0, base_score))
```

**Interpretation:**

- 0–19: LOW — few concerning indicators, good mitigations
- 20–39: MEDIUM — some exploit vectors, mitigations help
- 40–69: HIGH — multiple attack paths, likely exploitable
- 70–100: CRITICAL — severe vulnerabilities, missing defenses

---

## Tool Chain & Installation

### Required Tools (Linux/WSL)

|Tool|Purpose|Install|
|---|---|---|
|`strings`|String extraction|`binutils` (usually pre-installed)|
|`file`|File type detection|`file` package|
|`r2` / `radare2`|Disassembly & analysis|`sudo apt install radare2`|
|`checksec`|Mitigation detection|`sudo apt install checksec`|
|Python 3.6+|Runtime|`python3`|

### Optional Tools

|Tool|Purpose|Install|
|---|---|---|
|`capa`|Capability detection (Mandiant)|`pip3 install capa`|
|`floss`|Obfuscated string extraction (FireEye)|`pip3 install floss`|
|`Ghidra`|Deep static analysis|Download from [ghidra-sre.org](https://ghidra-sre.org/)|
|`detect-it-easy`|Packer detection|`sudo apt install detect-it-easy`|

### Setup on Windows (via WSL)

```bash
# Inside WSL Ubuntu terminal
wsl sudo apt update
wsl sudo apt install -y radare2 binutils file checksec
wsl pip3 install capa floss

# Download Ghidra (optional)
wsl wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
wsl unzip -q ghidra_11.0_PUBLIC_20231222.zip -d /opt/
```

---

## HTML Report Structure

The generated `re_report.html` contains:

### 1. Banner Section

- Binary filename, full path
- File type (PE32+, ELF, etc.)
- Generation timestamp

### 2. Risk Dashboard

- Visual risk bar (0–100) with color gradient
- Risk label (LOW/MEDIUM/HIGH/CRITICAL)
- Summary cards: count of High/Medium/Low findings

### 3. Security Mitigations Table

|Mitigation|Status|Notes|
|---|---|---|
|NX/DEP|✔ Enabled / ✘ Disabled|Prevents code execution in data sections|
|PIE|✔ Enabled / ~ Partial|Required for effective ASLR|
|Stack Canary|✔ Enabled / ✘ Disabled|Detects stack smashing|
|RELRO|✔ Enabled / ~ Partial|Prevents GOT overwrite|
|ASLR|? Unknown|OS-level (check system config)|

### 4. Dangerous Imports Section

Collapsible dropdowns grouped by severity:

```
▶ High Severity Imports (5)
  ▪ strcpy — Buffer overflow (no bounds check)
  ▪ system — OS command execution
  ▪ WriteProcessMemory — Process injection
  ...

▶ Medium Severity Imports (3)
  ...
```

Each import links to CVSS rating context.

### 5. Suspicious Strings Section

Grouped by pattern category:

```
▶ High — Shell invocation string (1)
  ▪ cmd.exe
  
▶ Medium — Registry key string (3)
  ▪ HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run
  ...
```

### 6. Attack Surface / Notable Findings

Automated synthesis of attack vectors:

```
High: Process injection indicators — WriteProcessMemory / CreateRemoteThread / 
      VirtualAlloc / VirtualProtect present

Medium: Missing mitigations: NX, PIE — memory corruption exploits are more reliable

Medium: Dynamic API resolution / LoadLibrary — possible DLL hijacking or evasion
```

### 7. Raw Tool Output Sections

Collapsible dropdowns for each tool:

```
▶ Radare2 — Function List (afl) [raw]
▶ Radare2 — Imports [raw]
▶ Radare2 — Exports [raw]
▶ Radare2 — Section Entropy [raw]
▶ capa Output [raw]
▶ FLOSS Output [raw]
▶ Checksec Output [raw]
```

---

## JSON Export

The harness also generates `re_data.json` with raw tool outputs and structured findings:

```json
{
  "timestamp": "2026-06-09 16:39:26",
  "file_type": "PE32+ executable (x86-64), dynamically linked, not stripped",
  "strings_out": "...",
  "checksec_out": "...",
  "r2": {
    "binary_info": "...",
    "functions": "...",
    "imports": "...",
    "entropy": "...",
    "security_flags": "..."
  },
  "ghidra_out": "[skipped]",
  "capa_out": "{...}",
  "floss_out": "...",
  "die_out": "...",
  "import_findings": [
    {"function": "strcpy", "severity": "High", "description": "Buffer overflow (no bounds check)"},
    ...
  ],
  "string_findings": [
    {"pattern": "cmd\\.exe", "severity": "High", "description": "Shell invocation string", "examples": ["cmd.exe"]},
    ...
  ],
  "mitigations": {
    "NX/DEP": true,
    "PIE": false,
    "Stack Canary": true,
    "RELRO": "partial",
    "ASLR": "unknown"
  },
  "risk_score": 25
}
```

---

## Workflow: From Binary to Report

### Step 1: Execute harness

```bash
python3 re_harness.py target.exe --skip-ghidra
```

### Step 2: Harness runs 9 phases in sequence

```
[1/9] Identifying binary...
[2/9] Extracting strings...
[3/9] Running checksec...
[4/9] Running radare2 analysis...
[5/9] Ghidra skipped.
[6/9] Running capa capability detection...
[7/9] Running FLOSS obfuscated string extraction...
[8/9] Running packer detection...
[9/9] Analysing findings...
```

### Step 3: Findings are cross-referenced

- Imports flagged against dangerous list
- Strings matched against suspicious patterns
- Mitigations checked for presence
- Attack paths synthesized from combinations

### Step 4: HTML and JSON generated

```
target_re_results/
  ├── re_report.html       (visual report with dropdowns)
  ├── re_data.json         (structured findings)
  └── (raw tool outputs embedded in HTML)
```

### Step 5: Open report in browser

```bash
open target_re_results/re_report.html
```

---

## Use Cases

### 1. Malware Triage

Quickly assess:

- Does it have command execution functions? (`system`, `ShellExecute`)
- Does it have persistence mechanisms? (`CreateService`, registry APIs)
- Does it have C2 indicators? (URLs, mutexes, sockets)
- Is it packed? (high entropy sections, packer signatures)

**Example:**

```
High: OS command execution functions present — potential for command injection
High: Service management APIs — persistence or privilege escalation mechanism
Medium: Network/download APIs — possible dropper or C2 communication
```

### 2. Vulnerability Assessment

For authorized binaries:

- Identify buffer overflow candidates (`strcpy`, missing NX)
- Find DLL hijacking vectors (`LoadLibrary` with relative paths)
- Spot use-after-free patterns (`malloc`/`free` without proper cleanup)
- Detect privilege escalation paths

### 3. CTF Binary Exploitation

Automates reconnaissance:

- Function list and call graph (Ghidra)
- Import analysis
- String hints (flags, user feedback strings)
- Mitigation checks (determines exploit technique)

---

## Customisation

### Add Custom Dangerous Imports

Edit `DANGEROUS_IMPORTS` dictionary:

```python
DANGEROUS_IMPORTS = {
    ...existing...
    "MyCustomFunc":  ("High", "Custom vulnerability description"),
}
```

### Add Custom String Patterns

Edit `SUSPICIOUS_STRINGS` dictionary:

```python
SUSPICIOUS_STRINGS = {
    ...existing...
    r"(your_pattern_here)": ("Severity", "Description"),
}
```

### Adjust Risk Scoring Weights

Modify `calculate_risk_score()` function:

```python
def calculate_risk_score(...):
    ...
    sev_weights = {"High": 10, "Medium": 5, "Low": 2}  # Adjust these
    ...
```

---

## Limitations & Known Issues

1. **Radare2 timeout**: Long-running binaries may exceed 300s timeout
    
    - Fix: Increase `TIMEOUT` variable or use `--skip-ghidra`
2. **Ghidra on Windows**: Headless analysis may fail
    
    - Workaround: Use WSL2 or skip with `--skip-ghidra`
3. **False positives**: String patterns may match legitimate code
    
    - Example: `cmd.exe` string in help text ≠ command injection
4. **Packer evasion**: Obfuscated imports may not be flagged
    
    - Mitigation: `floss` and `capa` tools help with obfuscated patterns
5. **Architecture-specific tools**: ARM binaries may have reduced analysis depth
    
    - Some tools (checksec, capa) work best on x86/x64

---

## Examples

### Example 1: Installer Binary (Low Risk)

```
File: setupapp.exe
Risk: 15/100 (LOW)

Findings:
  ✓ NX/DEP enabled
  ✓ PIE enabled
  ✓ Stack canary present

Imports: CreateFileA, ReadFile, WriteFile (normal installer functions)
Strings: %PROGRAMFILES%, .msi, license.txt (benign)

Verdict: Standard installer, no security concerns
```

### Example 2: Suspicious Dropper (Critical Risk)

```
File: update.exe
Risk: 87/100 (CRITICAL)

Findings:
  ✘ NX/DEP disabled
  ✘ PIE disabled
  ✘ No stack canary

Imports:
  • system, WinExec — OS command execution
  • WriteProcessMemory, CreateRemoteThread — Process injection
  • URLDownloadToFile — File download
  • CreateService — Persistence
  • SetWindowsHookEx — Keylogger
  
Strings:
  • cmd.exe /c
  • http://attacker.com/payload
  • HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run
  
Attack Paths:
  HIGH: Multiple process injection APIs present
  HIGH: Service creation capability — persistence mechanism
  MEDIUM: Network download + command execution = dropper pattern

Verdict: Confirmed malware with multiple persistence + injection vectors
```

---

## References

- **MITRE ATT&CK**: [Attack Techniques](https://attack.mitre.org/)
- **CWE**: [Common Weakness Enumeration](https://cwe.mitre.org/)
- **CVSS**: [Common Vulnerability Scoring System](https://www.first.org/cvss/)
- **Radare2**: [r2 Documentation](https://book.rada.re/)
- **Ghidra**: [Ghidra Project](https://ghidra-sre.org/)
- **capa**: [Mandiant capa](https://github.com/mandiant/capa)
- **FLOSS**: [FireEye FLOSS](https://github.com/fireeye/flare-floss)

---

## Author Notes

This harness was designed for **authorized security testing only**. Reverse engineering binaries without permission is illegal in most jurisdictions.

**Best practices:**

- Always obtain written authorization before analysing third-party binaries
- Document all findings in professional reports
- Coordinate with stakeholders on remediation timelines
- Use findings ethically and responsibly

---
