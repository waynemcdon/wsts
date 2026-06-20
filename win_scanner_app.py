"""
win_scanner_app.py — Windows Security Threat Scanner (Flask web UI)
Scans local Windows artifacts for malware indicators, persistence
mechanisms, and evidence of log/credential-store tampering.

Run:  python win_scanner_app.py
Then open: http://127.0.0.1:5900
"""

import glob
import json
import os
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, abort

# ---------------------------------------------------------------------------
# Flask setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ---------------------------------------------------------------------------
# Known malicious / high-risk prefetch names (lowercase, no extension)
# ---------------------------------------------------------------------------
KNOWN_SUSPICIOUS_PREFETCH = {
    "mimikatz", "wce", "fgdump", "gsecdump", "cachedump", "pwdump",
    "procdump", "dumpert", "lsass", "wceservice", "cobaltstrike",
    "beacon", "empire", "powersploit", "meterpreter", "psexec",
    "psexesvc", "netscan", "advanced_port_scanner", "nbtscan",
    "nc", "netcat", "ncat", "socat",
    "certutil",         # used to download payloads
    "mshta",            # LOLBin – HTML application host
    "regsvr32",         # LOLBin – COM object abuse
    "wscript", "cscript",
    "rundll32",         # watch for unusual use
    "at",               # legacy scheduler
    "schtasks",         # scheduled-task manipulation
    "reg",              # registry manipulation CLI
    "net1",             # lateral movement
    "nltest",           # domain recon
    "ipconfig", "whoami", "systeminfo",  # common recon (flag in context)
    "bitsadmin",        # download cradle
    "esentutl",         # ntds.dit copy
    "vssadmin",         # shadow copy deletion
    "wbadmin",          # backup deletion
    "wmic",             # WMI persistence / lateral movement
    "powershell",       # flag for review — not inherently bad
    "cmd",
}

# Extensions that are suspicious in startup folders
SUSPICIOUS_STARTUP_EXTS = {
    ".ps1", ".vbs", ".bat", ".cmd", ".js", ".jse", ".wsh", ".wsf",
    ".hta", ".scr", ".pif", ".lnk", ".dll",
}

# Threshold: hive/log modified within this many hours = flag as recent
RECENT_HOURS = 24

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _age_hours(ts: float) -> float:
    return (_now().timestamp() - ts) / 3600


def _safe_stat(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _glob_first_match(patterns: list[str]) -> str | None:
    for p in patterns:
        matches = glob.glob(p)
        if matches:
            return matches[0]
    return None

# ---------------------------------------------------------------------------
# Scanner modules
# ---------------------------------------------------------------------------

def scan_prefetch() -> dict:
    """List prefetch files, flag recently executed and known-suspicious names."""
    prefetch_dir = r"C:\Windows\Prefetch"
    findings = []
    accessible = True

    try:
        entries = list(Path(prefetch_dir).glob("*.pf"))
    except PermissionError:
        return {"accessible": False, "path": prefetch_dir, "findings": [],
                "summary": "Permission denied — run as Administrator"}

    for pf in entries:
        st = _safe_stat(str(pf))
        if not st:
            continue
        mtime = st.st_mtime
        basename = pf.stem.split("-")[0].lower()   # NAME-XXXXXXXX.pf → name
        exe_name = pf.stem.split("-")[0]            # preserve case for display
        age_h = _age_hours(mtime)

        flags = []
        if basename in KNOWN_SUSPICIOUS_PREFETCH:
            flags.append("KNOWN_SUSPICIOUS_TOOL")
        if age_h < 1:
            flags.append("RAN_LAST_1H")
        elif age_h < 24:
            flags.append("RAN_LAST_24H")

        findings.append({
            "file": pf.name,
            "exe": exe_name,
            "last_run": _fmt_ts(mtime),
            "age_hours": round(age_h, 1),
            "size_bytes": st.st_size,
            "flags": flags,
            "severity": "HIGH" if "KNOWN_SUSPICIOUS_TOOL" in flags else
                        ("MEDIUM" if age_h < 24 else "LOW"),
        })

    # Sort: suspicious first, then by recency
    findings.sort(key=lambda x: (
        0 if "KNOWN_SUSPICIOUS_TOOL" in x["flags"] else 1,
        x["age_hours"]
    ))

    return {
        "accessible": True,
        "path": prefetch_dir,
        "total": len(findings),
        "suspicious_count": sum(1 for f in findings if "KNOWN_SUSPICIOUS_TOOL" in f["flags"]),
        "recent_count": sum(1 for f in findings if f["age_hours"] < 24),
        "findings": findings,
    }


def scan_startup_persistence() -> dict:
    """Check startup folders for persistence artifacts."""
    startup_paths = []

    # Per-user startup
    users_root = r"C:\Users"
    try:
        user_dirs = [d for d in Path(users_root).iterdir() if d.is_dir()]
    except (PermissionError, OSError):
        user_dirs = []

    for ud in user_dirs:
        sp = ud / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        startup_paths.append(("user", ud.name, str(sp)))

    # Global startup
    global_startup = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    startup_paths.append(("global", "All Users", global_startup))

    # Also check registry-equivalent Run keys via text (we read from filesystem only)
    findings = []

    for scope, owner, path in startup_paths:
        try:
            items = list(Path(path).iterdir())
        except (PermissionError, FileNotFoundError, OSError) as e:
            findings.append({
                "scope": scope,
                "owner": owner,
                "path": path,
                "accessible": False,
                "error": str(e),
                "items": [],
            })
            continue

        items_info = []
        for item in items:
            if item.name.startswith("."):
                continue
            st = _safe_stat(str(item))
            ext = item.suffix.lower()
            flags = []
            if ext in SUSPICIOUS_STARTUP_EXTS:
                flags.append("SUSPICIOUS_EXTENSION")
            if st and _age_hours(st.st_mtime) < RECENT_HOURS:
                flags.append("RECENTLY_MODIFIED")
            items_info.append({
                "name": item.name,
                "ext": ext,
                "size_bytes": st.st_size if st else None,
                "modified": _fmt_ts(st.st_mtime) if st else "N/A",
                "flags": flags,
                "severity": "HIGH" if "SUSPICIOUS_EXTENSION" in flags else
                            ("MEDIUM" if "RECENTLY_MODIFIED" in flags else "LOW"),
            })

        items_info.sort(key=lambda x: (
            0 if "SUSPICIOUS_EXTENSION" in x["flags"] else 1,
            0 if "RECENTLY_MODIFIED" in x["flags"] else 1,
        ))

        findings.append({
            "scope": scope,
            "owner": owner,
            "path": path,
            "accessible": True,
            "item_count": len(items_info),
            "suspicious_count": sum(1 for i in items_info if "SUSPICIOUS_EXTENSION" in i["flags"]),
            "items": items_info,
        })

    return {"locations": findings}


def scan_credential_stores() -> dict:
    """Check SAM and related credential stores for accessibility and modification time."""
    targets = [
        (r"C:\Windows\System32\config\SAM",      "SAM (local password hashes)"),
        (r"C:\Windows\repair\SAM",               "SAM Backup (repair copy)"),
        (r"C:\Windows\System32\config\SECURITY", "SECURITY (policies & ACLs)"),
        (r"C:\Windows\System32\config\SYSTEM",   "SYSTEM hive"),
        (r"C:\Windows\System32\config\SOFTWARE", "SOFTWARE hive"),
    ]
    findings = []
    for path, label in targets:
        st = _safe_stat(path)
        flags = []
        if st is None:
            findings.append({"path": path, "label": label, "accessible": False,
                             "note": "Locked by OS or permission denied (expected)", "flags": []})
            continue
        if _age_hours(st.st_mtime) < RECENT_HOURS:
            flags.append("RECENTLY_MODIFIED")
        findings.append({
            "path": path,
            "label": label,
            "accessible": True,
            "size_bytes": st.st_size,
            "modified": _fmt_ts(st.st_mtime),
            "age_hours": round(_age_hours(st.st_mtime), 1),
            "flags": flags,
            "severity": "HIGH" if "RECENTLY_MODIFIED" in flags else "INFO",
        })
    return {"findings": findings}


def scan_event_logs() -> dict:
    """Check Windows Event Log files for signs of tampering (cleared logs = tiny file)."""
    evtx_dir = r"C:\Windows\System32\winevt\Logs"
    # A cleared .evtx file is typically < 70 KB
    CLEARED_THRESHOLD_BYTES = 70_000
    # Critical logs to always report
    CRITICAL_LOGS = {"security.evtx", "system.evtx", "application.evtx",
                     "microsoft-windows-powershell%4operational.evtx",
                     "microsoft-windows-sysmon%4operational.evtx",
                     "microsoft-windows-taskscheduler%4operational.evtx",
                     "microsoft-windows-bits-client%4operational.evtx",
                     "microsoft-windows-winrm%4operational.evtx"}

    try:
        evtx_files = list(Path(evtx_dir).glob("*.evtx"))
    except (PermissionError, FileNotFoundError, OSError):
        return {"accessible": False, "path": evtx_dir, "findings": [],
                "summary": "Permission denied — run as Administrator"}

    findings = []
    for evtx in evtx_files:
        st = _safe_stat(str(evtx))
        if not st:
            continue
        name_lower = evtx.name.lower()
        is_critical = name_lower in CRITICAL_LOGS
        flags = []
        if st.st_size < CLEARED_THRESHOLD_BYTES:
            flags.append("POSSIBLY_CLEARED")
        if _age_hours(st.st_mtime) < RECENT_HOURS:
            flags.append("RECENTLY_MODIFIED")
        if is_critical:
            flags.append("CRITICAL_LOG")

        severity = "INFO"
        if "POSSIBLY_CLEARED" in flags:
            severity = "HIGH"
        elif "RECENTLY_MODIFIED" in flags and is_critical:
            severity = "MEDIUM"

        findings.append({
            "file": evtx.name,
            "path": str(evtx),
            "size_bytes": st.st_size,
            "size_kb": round(st.st_size / 1024, 1),
            "modified": _fmt_ts(st.st_mtime),
            "age_hours": round(_age_hours(st.st_mtime), 1),
            "flags": flags,
            "severity": severity,
            "is_critical": is_critical,
        })

    # Sort: critical & suspicious first
    findings.sort(key=lambda x: (
        0 if "POSSIBLY_CLEARED" in x["flags"] else 1,
        0 if x["is_critical"] else 1,
        x["size_bytes"],
    ))

    return {
        "accessible": True,
        "path": evtx_dir,
        "total": len(findings),
        "possibly_cleared": sum(1 for f in findings if "POSSIBLY_CLEARED" in f["flags"]),
        "findings": findings,
    }


def scan_amcache_ntuser() -> dict:
    """Check Amcache.hve and per-user NTUSER.dat for recent modifications."""
    results = []

    # Amcache
    amcache = r"C:\Windows\AppCompat\Programs\Amcache.hve"
    st = _safe_stat(amcache)
    flags = []
    if st and _age_hours(st.st_mtime) < RECENT_HOURS:
        flags.append("RECENTLY_MODIFIED")
    results.append({
        "label": "Amcache.hve (application execution history)",
        "path": amcache,
        "accessible": st is not None,
        "size_bytes": st.st_size if st else None,
        "modified": _fmt_ts(st.st_mtime) if st else "N/A",
        "age_hours": round(_age_hours(st.st_mtime), 1) if st else None,
        "flags": flags,
        "severity": "MEDIUM" if "RECENTLY_MODIFIED" in flags else "INFO",
    })

    # NTUSER.dat per user
    users_root = r"C:\Users"
    try:
        user_dirs = [d for d in Path(users_root).iterdir() if d.is_dir()]
    except (PermissionError, OSError):
        user_dirs = []

    for ud in user_dirs:
        ntuser = ud / "NTUSER.DAT"
        st = _safe_stat(str(ntuser))
        flags = []
        if st and _age_hours(st.st_mtime) < RECENT_HOURS:
            flags.append("RECENTLY_MODIFIED")
        results.append({
            "label": f"NTUSER.DAT — {ud.name}",
            "path": str(ntuser),
            "accessible": st is not None,
            "size_bytes": st.st_size if st else None,
            "modified": _fmt_ts(st.st_mtime) if st else "N/A (locked or missing)",
            "age_hours": round(_age_hours(st.st_mtime), 1) if st else None,
            "flags": flags,
            "severity": "MEDIUM" if "RECENTLY_MODIFIED" in flags else "INFO",
        })

    return {"findings": results}


def run_full_scan() -> dict:
    return {
        "scan_time": _now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "prefetch":     scan_prefetch(),
        "startup":      scan_startup_persistence(),
        "credentials":  scan_credential_stores(),
        "event_logs":   scan_event_logs(),
        "amcache_ntuser": scan_amcache_ntuser(),
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Threat Scanner</title>
<style>
  :root{
    --bg:#0d1117;--panel:#161b22;--border:#30363d;
    --red:#ff4c4c;--orange:#e69240;--yellow:#e3b341;
    --green:#3fb950;--blue:#58a6ff;--gray:#8b949e;
    --text:#c9d1d9;--white:#f0f6fc;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--panel);border-bottom:1px solid var(--border);
    padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
  header h1{color:var(--white);font-size:1.3rem;letter-spacing:.5px}
  header span{color:var(--gray);font-size:.8rem}
  #scan-btn{background:var(--blue);color:#000;border:none;padding:8px 20px;
    border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem}
  #scan-btn:hover{opacity:.85}
  #scan-btn:disabled{opacity:.4;cursor:default}
  #status{color:var(--gray);font-size:.8rem;margin-left:12px}

  main{padding:20px 24px;max-width:1400px;margin:auto}

  .summary-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
  .badge{border-radius:8px;padding:12px 18px;min-width:160px;text-align:center}
  .badge .num{font-size:2rem;font-weight:700}
  .badge .lbl{font-size:.75rem;color:var(--gray)}
  .badge.red{background:#2d1a1a;border:1px solid var(--red)}  .badge.red .num{color:var(--red)}
  .badge.orange{background:#2b1e10;border:1px solid var(--orange)} .badge.orange .num{color:var(--orange)}
  .badge.green{background:#0d1f12;border:1px solid var(--green)} .badge.green .num{color:var(--green)}
  .badge.blue{background:#0d1a2b;border:1px solid var(--blue)} .badge.blue .num{color:var(--blue)}

  section{background:var(--panel);border:1px solid var(--border);border-radius:10px;
    margin-bottom:20px;overflow:hidden}
  section .sec-header{
    background:#1c2128;padding:12px 18px;display:flex;align-items:center;
    justify-content:space-between;cursor:pointer;user-select:none}
  section .sec-header h2{font-size:1rem;color:var(--white)}
  section .sec-body{padding:0}

  table{width:100%;border-collapse:collapse}
  thead tr{background:#1c2128}
  th{padding:8px 12px;text-align:left;color:var(--gray);font-weight:600;
    font-size:.8rem;border-bottom:1px solid var(--border)}
  td{padding:7px 12px;border-bottom:1px solid #1c2128;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#1c2128}

  .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}
  .sev.HIGH{background:#2d1a1a;color:var(--red);border:1px solid var(--red)}
  .sev.MEDIUM{background:#2b1e10;color:var(--orange);border:1px solid var(--orange)}
  .sev.LOW,.sev.INFO{background:#111;color:var(--gray);border:1px solid #333}

  .flag{display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;border-radius:3px;
    font-size:.7rem;background:#1c2128;border:1px solid var(--border);color:var(--yellow)}
  .flag.KNOWN_SUSPICIOUS_TOOL,.flag.POSSIBLY_CLEARED{color:var(--red);border-color:var(--red)}
  .flag.RECENTLY_MODIFIED,.flag.RAN_LAST_1H,.flag.RAN_LAST_24H{color:var(--orange);border-color:var(--orange)}
  .flag.SUSPICIOUS_EXTENSION{color:var(--yellow);border-color:var(--yellow)}
  .flag.CRITICAL_LOG{color:var(--blue);border-color:var(--blue)}

  .path{font-size:.75rem;color:var(--gray);font-family:monospace}
  .inaccessible{color:var(--gray);font-style:italic;padding:12px 18px}
  .scope-label{font-size:.8rem;font-weight:700;color:var(--blue);padding:8px 12px 4px;
    border-bottom:1px solid var(--border);background:#0d1117}
  .no-items{color:var(--gray);padding:10px 18px;font-style:italic}

  .chevron{font-size:.8rem;color:var(--gray);transition:transform .2s}
  .collapsed .chevron{transform:rotate(-90deg)}
  .sec-body.hidden{display:none}
  @keyframes spin{to{transform:rotate(360deg)}}
  #spinner{display:none;margin-left:10px;color:var(--blue);font-weight:700}
  #spinner.on{display:inline-block;animation:spin .9s linear infinite}
  #scan-banner{display:none;align-items:center;gap:14px;background:#0d1a2b;
    border:1px solid var(--blue);border-radius:10px;padding:14px 20px;
    margin-bottom:20px;color:var(--white)}
  #scan-banner.on{display:flex}
  #scan-banner .ring{width:22px;height:22px;flex-shrink:0;border:3px solid #1c3a5e;
    border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite}
  .ready-prompt{width:100%;background:#0d1a2b;border:1px solid var(--blue);
    border-radius:10px;padding:16px 20px;color:var(--text)}
  .ready-prompt b{color:var(--white)}

  /* scrollable large tables */
  .scroll-wrap{max-height:480px;overflow-y:auto}
  .scroll-wrap::-webkit-scrollbar{width:6px}
  .scroll-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

  .app-footer{margin-top:32px;padding:20px 24px;border-top:1px solid var(--border);
    text-align:center;color:var(--gray)}
  .app-footer .footer-tagline{color:var(--text);font-size:0.95rem;margin:0 0 6px}
  .app-footer .footer-tagline b{color:var(--white)}
  .app-footer p{margin:4px 0;font-size:0.82rem}
</style>
</head>
<body>
<header>
  <h1>{% if shield_uri %}<img src="{{ shield_uri }}" alt="WSTS shield" style="height:30px;width:30px;vertical-align:-6px;margin-right:10px">{% else %}&#x1F6E1; {% endif %}Windows Security Threat Scanner - WSTS</h1>
  <div style="display:flex;align-items:center;gap:8px">
    <span id="scan-time"></span>
    <span id="spinner">&#9696;</span>
    <button id="scan-btn" onclick="runScan()">&#x21BA; Scan Now</button>
  </div>
</header>

<main>
  <div id="scan-banner">
    <div class="ring"></div>
    <div><b>Scanning your system&hellip;</b> inspecting Prefetch, Startup, Event Logs,
    Credential hives &amp; Amcache. Everything runs locally &mdash; nothing leaves this PC.</div>
  </div>
  <div class="summary-row" id="summary"></div>

  <section id="sec-prefetch">
    <div class="sec-header" onclick="toggleSection('sec-prefetch')">
      <h2>&#x1F5C4; Malware &amp; Threat Indicators — Prefetch</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-prefetch"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-startup">
    <div class="sec-header" onclick="toggleSection('sec-startup')">
      <h2>&#x23F0; Persistence &amp; Startup Locations</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-startup"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-evtx">
    <div class="sec-header" onclick="toggleSection('sec-evtx')">
      <h2>&#x1F4CB; Event Log Health</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-evtx"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-creds">
    <div class="sec-header" onclick="toggleSection('sec-creds')">
      <h2>&#x1F512; Credential &amp; Registry Hive Integrity</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-creds"><div class="inaccessible">Run scan to load…</div></div>
  </section>

  <section id="sec-amcache">
    <div class="sec-header" onclick="toggleSection('sec-amcache')">
      <h2>&#x1F4BE; Amcache &amp; NTUSER.DAT</h2>
      <span class="chevron">&#9660;</span>
    </div>
    <div class="sec-body" id="body-amcache"><div class="inaccessible">Run scan to load…</div></div>
  </section>
</main>

<footer class="app-footer">
  <p class="footer-tagline">&#x1F6E1; <b>Built for defenders</b> &middot; Antibody Cyber Technology, LLC</p>
  <p>&copy; 2026 Antibody Cyber Technology, LLC &middot; WSTS</p>
</footer>

<script>
function sev(s){return `<span class="sev ${s}">${s}</span>`}
function flags(arr){return arr.map(f=>`<span class="flag ${f}">${f}</span>`).join('')}

function toggleSection(id){
  const sec=document.getElementById(id);
  const body=sec.querySelector('.sec-body');
  sec.classList.toggle('collapsed');
  body.classList.toggle('hidden');
}

function renderSummary(d){
  const pf=d.prefetch, el=d.event_logs;
  const suspPF   = pf.suspicious_count ?? 0;
  const cleared  = el.possibly_cleared ?? 0;
  const startupH = d.startup.locations.reduce((a,l)=>a+(l.suspicious_count||0),0);
  const recentPF = pf.recent_count ?? 0;
  document.getElementById('summary').innerHTML=`
    <div class="badge ${suspPF>0?'red':'green'}">
      <div class="num">${suspPF}</div><div class="lbl">Suspicious Prefetch</div></div>
    <div class="badge ${cleared>0?'red':'green'}">
      <div class="num">${cleared}</div><div class="lbl">Possibly Cleared Logs</div></div>
    <div class="badge ${startupH>0?'orange':'green'}">
      <div class="num">${startupH}</div><div class="lbl">Suspicious Startup Items</div></div>
    <div class="badge blue">
      <div class="num">${recentPF}</div><div class="lbl">Tools Run Last 24h</div></div>
    <div class="badge blue">
      <div class="num">${pf.total??0}</div><div class="lbl">Total Prefetch Files</div></div>
  `;
  document.getElementById('scan-time').textContent='Last scan: '+d.scan_time+' | Host: '+d.host;
}

function renderPrefetch(pf){
  const el=document.getElementById('body-prefetch');
  if(!pf.accessible){el.innerHTML=`<div class="inaccessible">${pf.summary}</div>`;return}
  if(!pf.findings.length){el.innerHTML='<div class="no-items">No prefetch files found.</div>';return}
  let rows=pf.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td style="font-family:monospace">${f.exe}</td>
    <td>${f.last_run}</td>
    <td>${f.age_hours}h</td>
    <td>${(f.size_bytes/1024).toFixed(1)} KB</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Executable</th><th>Last Run</th><th>Age</th><th>Size</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function renderStartup(startup){
  const el=document.getElementById('body-startup');
  let html='';
  for(const loc of startup.locations){
    html+=`<div class="scope-label">${loc.scope==='global'?'&#x1F310;':
      '&#x1F464;'} ${loc.owner} — <span class="path">${loc.path}</span></div>`;
    if(!loc.accessible){html+=`<div class="inaccessible">Inaccessible: ${loc.error}</div>`;continue}
    if(!loc.items.length){html+='<div class="no-items">Empty — no startup items.</div>';continue}
    let rows=loc.items.map(i=>`<tr>
      <td>${sev(i.severity)}</td>
      <td style="font-family:monospace">${i.name}</td>
      <td>${i.ext||'—'}</td>
      <td>${i.size_bytes!=null?(i.size_bytes/1024).toFixed(1)+' KB':'—'}</td>
      <td>${i.modified}</td>
      <td>${flags(i.flags)||'—'}</td>
    </tr>`).join('');
    html+=`<table><thead><tr><th>SEV</th><th>File</th><th>Ext</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  el.innerHTML=html;
}

function renderEvtx(el_data){
  const el=document.getElementById('body-evtx');
  if(!el_data.accessible){el.innerHTML=`<div class="inaccessible">${el_data.summary}</div>`;return}
  if(!el_data.findings.length){el.innerHTML='<div class="no-items">No .evtx files found.</div>';return}
  let rows=el_data.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td style="font-family:monospace;font-size:.8rem">${f.file}</td>
    <td>${f.size_kb} KB</td>
    <td>${f.modified}</td>
    <td>${flags(f.flags)||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Log File</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function renderCreds(creds){
  const el=document.getElementById('body-creds');
  let rows=creds.findings.map(f=>`<tr>
    <td>${sev(f.severity||'INFO')}</td>
    <td>${f.label}</td>
    <td class="path">${f.path}</td>
    <td>${f.accessible?((f.size_bytes/1024).toFixed(1)+' KB'):'<span style="color:var(--gray)">Locked/denied (expected)</span>'}</td>
    <td>${f.modified||'—'}</td>
    <td>${flags(f.flags||[])||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<table>
    <thead><tr><th>SEV</th><th>Store</th><th>Path</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderAmcache(ac){
  const el=document.getElementById('body-amcache');
  let rows=ac.findings.map(f=>`<tr>
    <td>${sev(f.severity)}</td>
    <td>${f.label}</td>
    <td class="path">${f.path}</td>
    <td>${f.accessible?((f.size_bytes/1024).toFixed(1)+' KB'):'<span style="color:var(--gray)">Locked/denied</span>'}</td>
    <td>${f.modified||'—'}</td>
    <td>${flags(f.flags||[])||'—'}</td>
  </tr>`).join('');
  el.innerHTML=`<div class="scroll-wrap"><table>
    <thead><tr><th>SEV</th><th>Artifact</th><th>Path</th><th>Size</th><th>Modified</th><th>Flags</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function runScan(){
  const btn=document.getElementById('scan-btn');
  const spin=document.getElementById('spinner');
  const banner=document.getElementById('scan-banner');
  const started=Date.now();
  btn.disabled=true; btn.textContent='\u27F3 Scanning\u2026';
  spin.classList.add('on'); banner.classList.add('on');
  ['prefetch','startup','evtx','creds','amcache'].forEach(id=>{
    const b=document.getElementById('body-'+id);
    if(b) b.innerHTML='<div class="inaccessible">Scanning\u2026</div>';
  });
  try{
    const r=await fetch('/api/scan');
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    renderSummary(d);
    renderPrefetch(d.prefetch);
    renderStartup(d.startup);
    renderEvtx(d.event_logs);
    renderCreds(d.credentials);
    renderAmcache(d.amcache_ntuser);
  }catch(e){
    alert('Scan failed: '+e.message);
  }finally{
    // Keep the scanning banner visible long enough to be perceptible.
    const finish=()=>{
      btn.disabled=false; btn.innerHTML='&#x21BA; Scan Now';
      spin.classList.remove('on'); banner.classList.remove('on');
    };
    const elapsed=Date.now()-started;
    if(elapsed<800){ setTimeout(finish, 800-elapsed); } else { finish(); }
  }
}

// Show a ready prompt; the user starts the scan explicitly with "Scan Now".
window.addEventListener('DOMContentLoaded', function(){
  document.getElementById('summary').innerHTML=
    '<div class="ready-prompt">Ready. Click <b>Scan Now</b> to inspect this PC. '+
    'WSTS performs a <b>read-only</b> scan entirely on your machine and never uploads anything.</div>';
});
</script>
</body>
</html>
"""


def _shield_data_uri() -> str:
    """Return the bundled WSTS shield as a base64 data URI (empty if missing).

    Works both in dev and inside a PyInstaller one-file build (sys._MEIPASS).
    """
    import base64
    import sys

    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "static", "img", "wsts_shield.png"),
        os.path.join(base, "wsts_shield.png"),
    ]
    for path in candidates:
        try:
            with open(path, "rb") as fh:
                encoded = base64.b64encode(fh.read()).decode("ascii")
            return "data:image/png;base64," + encoded
        except OSError:
            continue
    return ""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, shield_uri=_shield_data_uri())


@app.route("/api/scan")
def api_scan():
    """Return full scan results as JSON."""
    return jsonify(run_full_scan())


if __name__ == "__main__":
    import socket
    import sys
    import threading
    import webbrowser

    HOST = "127.0.0.1"
    PORT = 5900
    URL = f"http://{HOST}:{PORT}"

    # In a windowed (--noconsole) PyInstaller build, sys.stdout/stderr are None.
    # Werkzeug writes to stderr, so give it a real sink to avoid silent crashes.
    if sys.stdout is None or sys.stderr is None:
        try:
            log_path = os.path.join(
                os.environ.get("TEMP", os.path.expanduser("~")), "wsts.log"
            )
            _sink = open(log_path, "a", buffering=1, encoding="utf-8")
        except Exception:
            _sink = open(os.devnull, "w")
        if sys.stdout is None:
            sys.stdout = _sink
        if sys.stderr is None:
            sys.stderr = _sink

    def _already_running():
        """True if another instance already holds the port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((HOST, PORT)) == 0

    # If WSTS is already running, just open the dashboard and exit.
    if _already_running():
        webbrowser.open(URL)
        sys.exit(0)

    # Open the dashboard in the default browser once the server is up.
    threading.Timer(1.2, lambda: webbrowser.open(URL)).start()

    print("=" * 60)
    print("  Windows Security Threat Scanner (WSTS)")
    print(f"  {URL}")
    print("  NOTE: Run as Administrator for full access")
    print("=" * 60)

    try:
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - last-resort visibility
        print(f"WSTS failed to start: {exc}")
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                f"WSTS could not start the local dashboard.\n\n{exc}",
                "WSTS",
                0x10,  # MB_ICONERROR
            )
        except Exception:
            pass
        sys.exit(1)

