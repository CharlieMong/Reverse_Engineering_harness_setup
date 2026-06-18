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
