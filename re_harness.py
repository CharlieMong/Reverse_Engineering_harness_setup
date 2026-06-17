#!/usr/bin/env python3
"""
re_harness.py — Binary Reverse Engineering Harness

Runs a suite of RE tools against a target binary, then generates an
HTML report with findings, attack surface mapping, and potential
vulnerability indicators.

Tools used (install as needed):
  - Ghidra (headless analyser)   — function/string/import analysis
  - radare2 / r2                 — disassembly, function lists, entropy
  - strings / strings2           — static string extraction
  - file                         — binary type detection
  - objdump / readelf            — headers, imports, sections
  - checksec                     — security mitigations
  - floss (FireEye)              — obfuscated string extraction (optional)
  - capa (Mandiant)              — capability detection (optional)
  - die / detect-it-easy         — packer/protector detection (optional)

Usage:
    python3 re_harness.py <binary> [--ghidra-home /path/to/ghidra]
"""

import subprocess
import argparse
import json
import os
import sys
import shutil
import tempfile
import re
from datetime import datetime
from pathlib import Path

# ── Config ───────────────────────────────────────────────────────────
DEFAULT_GHIDRA_HOME = os.getenv("GHIDRA_HOME", "/opt/ghidra")
TIMEOUT = 300  # seconds per tool

# ── Helpers ──────────────────────────────────────────────────────────
def run(cmd, timeout=TIMEOUT, shell=False):
    """Run a command, return (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=shell, errors="replace"
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT after {timeout}s]", -1
    except FileNotFoundError:
        return "", f"[NOT FOUND: {cmd[0] if isinstance(cmd, list) else cmd}]", -1
    except Exception as e:
        return "", str(e), -1

def tool_available(name):
    return shutil.which(name) is not None

def html_escape(s):
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))

# ── Tool Runners ─────────────────────────────────────────────────────

def run_file(binary):
    out, _, _ = run(["file", binary])
    return out.strip()

def run_strings(binary, min_len=6):
    """Extract printable strings (ASCII + Unicode)."""
    out, _, _ = run(["strings", "-n", str(min_len), binary])
    return out

def run_checksec(binary):
    """Run checksec for mitigation flags (NX, PIE, RELRO, canary, etc.)."""
    if tool_available("checksec"):
        out, _, _ = run(["checksec", "--file", binary, "--format=json"])
        return out
    # Fallback: use checksec via bash wrapper
    out, _, rc = run(["checksec", "--file=" + binary], shell=False)
    return out if rc == 0 else "[checksec not available]"

def run_readelf(binary):
    out, _, _ = run(["readelf", "-a", binary])
    return out

def run_objdump(binary):
    out, _, _ = run(["objdump", "-d", "-M", "intel", binary])
    return out[:50000]  # cap large binaries

def run_r2_analysis(binary):
    """Use radare2 for function list, imports, entropy, anti-analysis checks."""
    results = {}

    # Basic info
    out, _, _ = run(["r2", "-q", "-c", "iI;quit", binary])
    results["binary_info"] = out

    # Function list
    out, _, _ = run(["r2", "-q", "-c", "aaa;afl;quit", binary], timeout=120)
    results["functions"] = out

    # Imports
    out, _, _ = run(["r2", "-q", "-c", "ii;quit", binary])
    results["imports"] = out

    # Exports
    out, _, _ = run(["r2", "-q", "-c", "iE;quit", binary])
    results["exports"] = out

    # Section entropy (high entropy = packed/encrypted sections)
    out, _, _ = run(["r2", "-q", "-c", "iS entropy;quit", binary])
    results["entropy"] = out

    # Strings from r2
    out, _, _ = run(["r2", "-q", "-c", "iz;quit", binary])
    results["strings_r2"] = out

    # Security checks (Ghidra not needed for this)
    out, _, _ = run(["r2", "-q", "-c", "i~pic,canary,nx,relro;quit", binary])
    results["security_flags"] = out

    return results

def run_ghidra_headless(binary, ghidra_home):
    """Run Ghidra headless analyser and extract function/call graph data."""
    analyser = Path(ghidra_home) / "support" / "analyzeHeadless"
    if not analyser.exists():
        return None, f"[Ghidra not found at {ghidra_home}]"

    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir) / "reproject"
        binary_name = Path(binary).stem

        # Run headless analysis
        cmd = [
            str(analyser), str(project), "REAnalysis",
            "-import", binary,
            "-postScript", "PrintXRefsScript.java",  # standard Ghidra script
            "-noanalysis" if not (analyser.parent.parent / "Ghidra" / "Features" / "Base").exists() else "",
        ]
        # Filter empty
        cmd = [c for c in cmd if c]
        out, err, rc = run(cmd, timeout=300)

        # Export function listing via alternate approach
        # Use a simpler command that works across Ghidra versions
        script_content = """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ExportFunctions extends GhidraScript {
    public void run() throws Exception {
        PrintWriter pw = new PrintWriter(new File(askString("Output", "path")));
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            pw.println(f.getEntryPoint() + "," + f.getName() + "," + f.getParameterCount());
        }
        pw.close();
    }
}
"""
        return out or "[Ghidra analysis complete]", err

def run_capa(binary):
    """Run Mandiant capa for capability detection (optional)."""
    if not tool_available("capa"):
        return "[capa not installed — skipping capability detection]"
    out, _, _ = run(["capa", "-j", binary], timeout=300)
    return out

def run_floss(binary):
    """Run FireEye FLOSS for obfuscated string extraction (optional)."""
    if not tool_available("floss"):
        return "[floss not installed — skipping obfuscated string extraction]"
    out, _, _ = run(["floss", "--no-static-strings", binary], timeout=120)
    return out

def run_die(binary):
    """Detect-It-Easy packer/protector detection (optional)."""
    for name in ["die", "diec"]:
        if tool_available(name):
            out, _, _ = run([name, binary])
            return out
    return "[detect-it-easy not installed — skipping packer detection]"

# ── Analysis & Pattern Matching ─────────────────────────────────────

DANGEROUS_IMPORTS = {
    "strcpy":           ("High",   "Buffer overflow (no bounds check)"),
    "strcat":           ("High",   "Buffer overflow (no bounds check)"),
    "gets":             ("High",   "Buffer overflow (unbounded input)"),
    "sprintf":          ("Medium", "Format string / buffer overflow"),
    "scanf":            ("Medium", "Buffer overflow if %s without width"),
    "printf":           ("Medium", "Potential format string vulnerability"),
    "system":           ("High",   "OS command execution"),
    "popen":            ("High",   "OS command execution"),
    "exec":             ("High",   "Process execution"),
    "execve":           ("High",   "Process execution"),
    "WinExec":          ("High",   "Windows command execution"),
    "ShellExecute":     ("High",   "Windows shell execution"),
    "CreateProcess":    ("Medium", "Windows process creation"),
    "LoadLibrary":      ("Medium", "Dynamic library loading (DLL injection risk)"),
    "GetProcAddress":   ("Low",    "Dynamic API resolution (evasion indicator)"),
    "VirtualAlloc":     ("Medium", "Memory allocation (shellcode indicator)"),
    "VirtualProtect":   ("Medium", "Memory permission change (shellcode indicator)"),
    "WriteProcessMemory": ("High", "Process injection"),
    "CreateRemoteThread": ("High", "Remote thread injection"),
    "RegOpenKey":       ("Low",    "Registry access"),
    "RegSetValue":      ("Medium", "Registry modification"),
    "InternetOpen":     ("Low",    "Network access (WinInet)"),
    "URLDownloadToFile":("Medium", "File download from internet"),
    "recv":             ("Low",    "Network receive"),
    "send":             ("Low",    "Network send"),
    "WSAStartup":       ("Low",    "Windows socket initialisation"),
    "OpenSCManager":    ("High",   "Service manager access"),
    "CreateService":    ("High",   "Service creation (persistence)"),
    "SetWindowsHookEx": ("High",   "Hook installation (keylogger indicator)"),
    "malloc":           ("Low",    "Heap allocation (use-after-free risk if paired with free)"),
    "free":             ("Low",    "Heap free (use-after-free risk)"),
    "memcpy":           ("Low",    "Memory copy (bounds checking required)"),
    "memmove":          ("Low",    "Memory move (bounds checking required)"),
}

SUSPICIOUS_STRINGS = {
    r"(cmd\.exe|/bin/sh|/bin/bash)":              ("High",   "Shell invocation string"),
    r"(powershell|pwsh)":                          ("High",   "PowerShell invocation"),
    r"(base64|B64)":                               ("Medium", "Base64 encoding indicator"),
    r"(http[s]?://|ftp://)":                       ("Medium", "Network URL"),
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})":     ("Low",    "IP address"),
    r"(HKEY_|HKLM|HKCU)":                          ("Medium", "Registry key string"),
    r"(CreateMutex|Global\\\\)":                   ("Medium", "Mutex (single-instance / C2 beacon indicator)"),
    r"(VirtualAlloc|shellcode|payload)":           ("High",   "Shellcode/payload string"),
    r"(wget|curl|nc |netcat)":                     ("High",   "Network tool string"),
    r"(admin|password|passwd|secret|token|apikey)":("Medium", "Credential-related string"),
    r"(UPX|MPRESS|ASPACK|PECompact)":             ("Medium", "Packer signature string"),
    r"(IsDebuggerPresent|CheckRemoteDebugger)":   ("Medium", "Anti-debug check"),
    r"(CreateThread|NtCreateThread)":             ("Medium", "Thread creation"),
}

def analyse_imports(import_text):
    """Match imports against dangerous function list."""
    findings = []
    for func, (sev, desc) in DANGEROUS_IMPORTS.items():
        if re.search(r'\b' + re.escape(func) + r'\b', import_text, re.IGNORECASE):
            findings.append({"function": func, "severity": sev, "description": desc})
    return findings

def analyse_strings(strings_text):
    """Flag suspicious string patterns."""
    findings = []
    for pattern, (sev, desc) in SUSPICIOUS_STRINGS.items():
        matches = re.findall(pattern, strings_text, re.IGNORECASE)
        if matches:
            unique = list(set([m if isinstance(m, str) else m[0] for m in matches]))[:5]
            findings.append({
                "pattern": pattern,
                "severity": sev,
                "description": desc,
                "examples": unique
            })
    return findings

def parse_security_mitigations(checksec_out, r2_flags):
    """Extract mitigation status from checksec / r2 output."""
    mitigations = {}
    combined = (checksec_out + r2_flags).lower()

    checks = {
        "NX/DEP":     [("nx enabled", True), ("nx disabled", False), ("nx: true", True), ("nx: false", False)],
        "PIE":        [("pie enabled", True), ("no pie", False), ("pic: true", True), ("pic: false", False)],
        "Stack Canary": [("canary found", True), ("no canary", False), ("canary: true", True), ("canary: false", False)],
        "RELRO":      [("full relro", True), ("partial relro", None), ("no relro", False)],
        "ASLR":       [("aslr", True)],
    }

    for name, patterns in checks.items():
        for pat, val in patterns:
            if pat in combined:
                mitigations[name] = val
                break
        if name not in mitigations:
            mitigations[name] = "unknown"

    return mitigations

def calculate_risk_score(import_findings, string_findings, mitigations):
    """Produce a rough numeric risk score 0-100."""
    score = 0
    sev_weights = {"High": 10, "Medium": 5, "Low": 2}

    for f in import_findings:
        score += sev_weights.get(f["severity"], 0)
    for f in string_findings:
        score += sev_weights.get(f["severity"], 0)

    # Deduct for present mitigations
    if mitigations.get("NX/DEP") is True:
        score = max(0, score - 10)
    if mitigations.get("PIE") is True:
        score = max(0, score - 8)
    if mitigations.get("Stack Canary") is True:
        score = max(0, score - 8)

    return min(100, score)

# ── HTML Report ──────────────────────────────────────────────────────

HTML_STYLE = """
<style>
:root {
  --bg:#0a0a0f;--surface:#111119;--border:#252530;
  --accent:#c62828;--text:#ddd;--dim:#666;
  --green:#4caf50;--yellow:#ffa726;--red:#ef5350;--blue:#42a5f5;--orange:#ff7043;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Consolas','Monaco',monospace;background:var(--bg);color:var(--text);
     padding:24px;line-height:1.6;max-width:1300px;margin:0 auto;}
.banner{border:1px solid var(--accent);border-radius:8px;padding:26px;margin-bottom:22px;
        background:linear-gradient(145deg,#111119 0%,#150808 100%);}
.banner h1{color:var(--accent);font-size:1.4em;margin-bottom:6px;}
.banner .sub{color:var(--dim);font-size:0.82em;} .banner .sub b{color:var(--text);}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:26px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:16px;text-align:center;}
.card .num{font-size:2em;font-weight:bold;}.card .lbl{font-size:0.7em;color:var(--dim);text-transform:uppercase;letter-spacing:1.5px;}
.num-r{color:var(--red);}.num-o{color:var(--orange);}.num-y{color:var(--yellow);}.num-g{color:var(--green);}.num-b{color:var(--blue);}
h2{color:var(--accent);font-size:0.75em;text-transform:uppercase;letter-spacing:2px;
   margin:26px 0 10px;padding-bottom:5px;border-bottom:1px solid var(--border);}
.mit-table,.ptable{width:100%;border-collapse:collapse;font-size:0.82em;margin-bottom:8px;}
.mit-table th,.ptable th{background:var(--accent);color:#fff;padding:7px 13px;text-align:left;font-size:0.88em;}
.mit-table td,.ptable td{padding:7px 13px;border-bottom:1px solid var(--border);}
.mit-table tr:hover td,.ptable tr:hover td{background:rgba(198,40,40,0.06);}
.sev-high{color:var(--red);font-weight:bold;}.sev-medium{color:var(--yellow);font-weight:bold;}
.sev-low{color:var(--blue);}.sev-info{color:var(--dim);}
.mit-yes{color:var(--green);}.mit-no{color:var(--red);font-weight:bold;}.mit-partial{color:var(--yellow);}.mit-unk{color:var(--dim);}
details{background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:8px;overflow:hidden;}
details[open]{border-color:var(--accent);}
summary{padding:12px 16px;cursor:pointer;font-weight:bold;font-size:0.88em;
        display:flex;align-items:center;gap:8px;user-select:none;}
summary:hover{background:rgba(198,40,40,0.07);}
summary::marker{content:'';}
.arr{transition:transform .2s;color:var(--accent);font-size:0.7em;}
details[open] .arr{transform:rotate(90deg);}
.cnt{margin-left:auto;padding:2px 9px;border-radius:10px;font-size:0.72em;font-weight:normal;}
.cnt-r{background:rgba(239,83,80,.15);color:var(--red);}
.cnt-y{background:rgba(255,167,38,.15);color:var(--yellow);}
.cnt-b{background:rgba(66,165,245,.15);color:var(--blue);}
.cnt-g{background:rgba(76,175,80,.15);color:var(--green);}
.dbody{padding:0 16px 14px;}
.finding{padding:8px 12px;margin:4px 0;border-radius:4px;font-size:0.8em;}
.f-high{background:rgba(239,83,80,.07);border-left:3px solid var(--red);}
.f-medium{background:rgba(255,167,38,.07);border-left:3px solid var(--yellow);}
.f-low{background:rgba(66,165,245,.06);border-left:3px solid var(--blue);}
.finding b{display:inline-block;min-width:160px;}
.examples{color:var(--dim);font-size:0.85em;margin-top:3px;}
.risk-bar-wrap{height:18px;background:var(--border);border-radius:9px;overflow:hidden;margin:6px 0;}
.risk-bar{height:100%;border-radius:9px;transition:width 0.5s;}
pre{background:#07070c;border:1px solid var(--border);border-radius:4px;padding:14px;
    overflow-x:auto;font-size:0.76em;line-height:1.5;white-space:pre-wrap;word-break:break-all;
    max-height:500px;overflow-y:auto;margin-top:6px;}
.footer{text-align:center;color:var(--dim);font-size:0.72em;margin-top:36px;
        padding-top:14px;border-top:1px solid var(--border);}
</style>
"""

def severity_css(s):
    return {"High": "f-high", "Medium": "f-medium", "Low": "f-low"}.get(s, "f-low")

def cnt_css(s):
    return {"High": "cnt-r", "Medium": "cnt-y", "Low": "cnt-b"}.get(s, "cnt-b")

def mit_css(v):
    if v is True:   return "mit-yes", "✔ Enabled"
    if v is False:  return "mit-no",  "✘ Disabled"
    if v is None:   return "mit-partial", "~ Partial"
    return "mit-unk", "? Unknown"

def generate_report(binary, data, outdir):
    report_path = Path(outdir) / "re_report.html"
    binary_name = Path(binary).name

    ri = data["import_findings"]
    rs = data["string_findings"]
    mit = data["mitigations"]
    score = data["risk_score"]
    ts = data["timestamp"]

    high_count   = sum(1 for f in ri + rs if f.get("severity") == "High")
    medium_count = sum(1 for f in ri + rs if f.get("severity") == "Medium")
    low_count    = sum(1 for f in ri + rs if f.get("severity") == "Low")

    if score >= 70:   risk_label, risk_col = "CRITICAL", "#ef5350"
    elif score >= 40: risk_label, risk_col = "HIGH",     "#ff7043"
    elif score >= 20: risk_label, risk_col = "MEDIUM",   "#ffa726"
    else:             risk_label, risk_col = "LOW",      "#4caf50"

    with open(report_path, "w") as f:
        def w(s): f.write(s + "\n")

        w("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
        w(f"<title>RE Report — {html_escape(binary_name)}</title>")
        w(HTML_STYLE)
        w("</head><body>")

        # Banner
        w(f"""<div class="banner">
  <h1>&#x1f50d; Binary RE Report &mdash; {html_escape(binary_name)}</h1>
  <div class="sub">
    Path: <b>{html_escape(str(Path(binary).resolve()))}</b> &bull;
    Type: <b>{html_escape(data['file_type'])}</b> &bull;
    Date: <b>{ts}</b>
  </div>
</div>""")

        # Risk bar
        w(f"""<h2>Risk Score</h2>
<div style="display:flex;align-items:center;gap:16px;">
  <div style="flex:1;"><div class="risk-bar-wrap">
    <div class="risk-bar" style="width:{score}%;background:{risk_col};"></div>
  </div></div>
  <div style="font-size:1.4em;font-weight:bold;color:{risk_col};">{score}/100</div>
  <div style="font-weight:bold;color:{risk_col};">{risk_label}</div>
</div>""")

        # Summary cards
        w(f"""<div class="cards">
  <div class="card"><div class="num num-r">{high_count}</div><div class="lbl">High Severity</div></div>
  <div class="card"><div class="num num-y">{medium_count}</div><div class="lbl">Medium Severity</div></div>
  <div class="card"><div class="num num-b">{low_count}</div><div class="lbl">Low Severity</div></div>
  <div class="card"><div class="num num-b">{len(ri)}</div><div class="lbl">Dangerous Imports</div></div>
  <div class="card"><div class="num num-y">{len(rs)}</div><div class="lbl">Suspicious Strings</div></div>
</div>""")

        # Mitigations table
        w('<h2>Security Mitigations</h2>')
        w('<table class="mit-table"><tr><th>Mitigation</th><th>Status</th><th>Notes</th></tr>')
        NOTES = {
            "NX/DEP":       "Prevents code execution in data sections",
            "PIE":          "Position-independent — required for effective ASLR",
            "Stack Canary":  "Detects stack smashing before return",
            "RELRO":        "Prevents GOT overwrite attacks",
            "ASLR":         "Randomises load addresses (OS-level)",
        }
        for name, val in mit.items():
            css, label = mit_css(val)
            note = NOTES.get(name, "")
            w(f"<tr><td><b>{name}</b></td><td class='{css}'>{label}</td><td style='color:var(--dim)'>{note}</td></tr>")
        w("</table>")

        # Dangerous imports dropdown
        w('<h2>Dangerous / Interesting Imports</h2>')
        if ri:
            by_sev = {"High": [], "Medium": [], "Low": []}
            for finding in ri:
                by_sev.get(finding["severity"], by_sev["Low"]).append(finding)
            for sev, items in by_sev.items():
                if not items: continue
                w(f"""<details>
  <summary><span class="arr">&#9654;</span> {sev} Severity Imports
    <span class="cnt {cnt_css(sev)}">{len(items)}</span></summary>
  <div class="dbody">""")
                for item in items:
                    w(f"""<div class="finding {severity_css(sev)}">
    <b>{html_escape(item['function'])}</b> — {html_escape(item['description'])}
  </div>""")
                w("</div></details>")
        else:
            w('<p style="color:var(--dim);padding:8px;">No dangerous imports detected.</p>')

        # Suspicious strings dropdown
        w('<h2>Suspicious Strings</h2>')
        if rs:
            by_sev = {"High": [], "Medium": [], "Low": []}
            for finding in rs:
                by_sev.get(finding["severity"], by_sev["Low"]).append(finding)
            for sev, items in by_sev.items():
                if not items: continue
                w(f"""<details>
  <summary><span class="arr">&#9654;</span> {sev} — {items[0]['description'] if len(items)==1 else f'{len(items)} categories'}
    <span class="cnt {cnt_css(sev)}">{len(items)}</span></summary>
  <div class="dbody">""")
                for item in items:
                    examples = ", ".join(html_escape(str(e)) for e in item.get("examples", []))
                    w(f"""<div class="finding {severity_css(sev)}">
    <b>{html_escape(item['description'])}</b>
    <div class="examples">Examples: {examples}</div>
  </div>""")
                w("</div></details>")
        else:
            w('<p style="color:var(--dim);padding:8px;">No suspicious strings detected.</p>')

        # Attack path summary
        w('<h2>Attack Surface / Notable Findings</h2>')
        attack_paths = []

        missing_mit = [k for k, v in mit.items() if v is False]
        if missing_mit:
            attack_paths.append(("Medium", f"Missing mitigations: {', '.join(missing_mit)} — memory corruption exploits are more reliable"))

        ri_funcs = {x["function"] for x in ri}
        if ri_funcs & {"WriteProcessMemory", "CreateRemoteThread", "VirtualAlloc", "VirtualProtect"}:
            attack_paths.append(("High", "Process injection indicators — WriteProcessMemory / CreateRemoteThread / VirtualAlloc / VirtualProtect present"))
        if ri_funcs & {"system", "popen", "WinExec", "ShellExecute"}:
            attack_paths.append(("High", "OS command execution functions present — potential for command injection if input is unsanitised"))
        if ri_funcs & {"strcpy", "gets", "strcat"}:
            attack_paths.append(("High", "Classic buffer-overflow functions (strcpy/gets/strcat) with no NX" if mit.get("NX/DEP") is False else "Classic buffer-overflow functions — verify input length validation"))
        if ri_funcs & {"LoadLibrary", "GetProcAddress"}:
            attack_paths.append(("Medium", "Dynamic API resolution / LoadLibrary — possible DLL hijacking or evasion via import obfuscation"))
        if ri_funcs & {"CreateService", "OpenSCManager"}:
            attack_paths.append(("High", "Service management APIs — persistence or privilege escalation mechanism"))
        if "SetWindowsHookEx" in ri_funcs:
            attack_paths.append(("High", "SetWindowsHookEx — keylogger / input capture indicator"))
        if ri_funcs & {"URLDownloadToFile", "InternetOpen"}:
            attack_paths.append(("Medium", "Network/download APIs — possible dropper or C2 communication"))
        if any(re.search(r'(IsDebuggerPresent|CheckRemoteDebugger)', e, re.I) for x in rs for e in x.get("examples", [])):
            attack_paths.append(("Medium", "Anti-debugging checks detected — binary may behave differently under analysis"))

        # Entropy-based finding
        if "entropy" in data.get("r2", {}):
            entropy_text = data["r2"]["entropy"]
            high_ent = re.findall(r'entropy\s+([6-9]\.[0-9]+)', entropy_text)
            if high_ent:
                attack_paths.append(("Medium", f"High entropy sections detected ({', '.join(high_ent)}) — possible packing, encryption, or embedded payload"))

        if attack_paths:
            for sev, desc in attack_paths:
                w(f'<div class="finding {severity_css(sev)}" style="margin-bottom:6px;"><b>{sev}:</b> {html_escape(desc)}</div>')
        else:
            w('<p style="color:var(--dim);padding:8px;">No automated attack paths identified.</p>')

        # Ghidra output
        w('<h2>Ghidra Analysis</h2>')
        w('<details><summary><span class="arr">&#9654;</span> Ghidra Headless Output <span class="cnt cnt-b">raw</span></summary><div class="dbody">')
        w(f'<pre>{html_escape(data.get("ghidra_out", "[not run]"))}</pre>')
        w('</div></details>')

        # r2 outputs
        w('<h2>Radare2 Analysis</h2>')
        r2d = data.get("r2", {})
        for section, label in [
            ("binary_info", "Binary Info"),
            ("functions",   "Function List (afl)"),
            ("imports",     "Imports"),
            ("exports",     "Exports"),
            ("entropy",     "Section Entropy"),
            ("security_flags", "Security Flags"),
        ]:
            content = r2d.get(section, "[not available]")
            w(f'<details><summary><span class="arr">&#9654;</span> {label} <span class="cnt cnt-b">r2</span></summary>')
            w(f'<div class="dbody"><pre>{html_escape(content)}</pre></div></details>')

        # Capability detection (capa)
        w('<h2>Capability Detection (capa)</h2>')
        w(f'<details><summary><span class="arr">&#9654;</span> capa Output <span class="cnt cnt-b">raw</span></summary>')
        w(f'<div class="dbody"><pre>{html_escape(data.get("capa_out", "[not run]"))}</pre></div></details>')

        # Obfuscated strings (floss)
        w('<h2>Obfuscated Strings (FLOSS)</h2>')
        w(f'<details><summary><span class="arr">&#9654;</span> FLOSS Output <span class="cnt cnt-b">raw</span></summary>')
        w(f'<div class="dbody"><pre>{html_escape(data.get("floss_out", "[not run]"))}</pre></div></details>')

        # Packer detection
        w('<h2>Packer / Protector Detection</h2>')
        w(f'<details><summary><span class="arr">&#9654;</span> Detect-It-Easy <span class="cnt cnt-b">raw</span></summary>')
        w(f'<div class="dbody"><pre>{html_escape(data.get("die_out", "[not run]"))}</pre></div></details>')

        # Raw strings
        w('<h2>Extracted Strings</h2>')
        w('<details><summary><span class="arr">&#9654;</span> strings output <span class="cnt cnt-b">raw</span></summary>')
        w(f'<div class="dbody"><pre>{html_escape(data.get("strings_out", "")[:20000])}</pre></div></details>')

        # checksec
        w('<h2>Checksec Output</h2>')
        w('<details><summary><span class="arr">&#9654;</span> checksec <span class="cnt cnt-b">raw</span></summary>')
        w(f'<div class="dbody"><pre>{html_escape(data.get("checksec_out", ""))}</pre></div></details>')

        # Footer
        w(f'<div class="footer">re_harness.py &mdash; {ts} &mdash; {html_escape(binary_name)}</div>')
        w("</body></html>")

    return report_path

# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Binary reverse engineering harness with HTML report"
    )
    parser.add_argument("binary", help="Path to the binary to analyse")
    parser.add_argument("--ghidra-home", default=DEFAULT_GHIDRA_HOME,
                        help=f"Path to Ghidra install (default: {DEFAULT_GHIDRA_HOME})")
    parser.add_argument("--outdir", default=None,
                        help="Output directory (default: <binary_name>_re_results)")
    parser.add_argument("--skip-ghidra", action="store_true",
                        help="Skip Ghidra headless analysis")
    parser.add_argument("--skip-capa", action="store_true",
                        help="Skip capa capability detection")
    parser.add_argument("--skip-floss", action="store_true",
                        help="Skip FLOSS obfuscated string extraction")
    args = parser.parse_args()

    binary = str(Path(args.binary).resolve())
    if not os.path.isfile(binary):
        print(f"[!] File not found: {binary}")
        sys.exit(1)

    outdir = args.outdir or f"{Path(binary).stem}_re_results"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n  Binary RE Harness")
    print(f"  Target : {binary}")
    print(f"  Output : {outdir}")
    print(f"  Started: {ts}\n")

    data = {"timestamp": ts}

    # File type
    print("[1/9] Identifying binary...")
    data["file_type"] = run_file(binary)
    print(f"      {data['file_type']}")

    # Strings
    print("[2/9] Extracting strings...")
    data["strings_out"] = run_strings(binary)

    # checksec
    print("[3/9] Running checksec...")
    data["checksec_out"] = run_checksec(binary)

    # radare2
    print("[4/9] Running radare2 analysis...")
    data["r2"] = run_r2_analysis(binary)

    # Ghidra
    if not args.skip_ghidra:
        print("[5/9] Running Ghidra headless analysis (may take a few minutes)...")
        out, err = run_ghidra_headless(binary, args.ghidra_home)
        data["ghidra_out"] = (out or "") + ("\n" + err if err else "")
    else:
        print("[5/9] Ghidra skipped.")
        data["ghidra_out"] = "[skipped]"

    # capa
    if not args.skip_capa:
        print("[6/9] Running capa capability detection...")
        data["capa_out"] = run_capa(binary)
    else:
        data["capa_out"] = "[skipped]"

    # floss
    if not args.skip_floss:
        print("[7/9] Running FLOSS obfuscated string extraction...")
        data["floss_out"] = run_floss(binary)
    else:
        data["floss_out"] = "[skipped]"

    # Detect-It-Easy
    print("[8/9] Running packer detection...")
    data["die_out"] = run_die(binary)

    # Analysis
    print("[9/9] Analysing findings...")
    imports_text = data["r2"].get("imports", "") + data["r2"].get("strings_r2", "")
    data["import_findings"] = analyse_imports(imports_text)
    data["string_findings"] = analyse_strings(data["strings_out"])
    data["mitigations"]     = parse_security_mitigations(data["checksec_out"], data["r2"].get("security_flags", ""))
    data["risk_score"]      = calculate_risk_score(data["import_findings"], data["string_findings"], data["mitigations"])

    # Save raw JSON
    json_path = Path(outdir) / "re_data.json"
    with open(json_path, "w") as jf:
        json.dump(data, jf, indent=2)

    # Generate report
    report_path = generate_report(binary, data, outdir)

    print(f"\n  {'─'*52}")
    print(f"  Risk Score : {data['risk_score']}/100")
    print(f"  High       : {sum(1 for f in data['import_findings']+data['string_findings'] if f.get('severity')=='High')}")
    print(f"  Medium     : {sum(1 for f in data['import_findings']+data['string_findings'] if f.get('severity')=='Medium')}")
    print(f"  Report     : {report_path}")
    print(f"  JSON       : {json_path}")
    print(f"  {'─'*52}\n")

if __name__ == "__main__":
    main()
