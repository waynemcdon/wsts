# Windows Security Threat Scanner (WSTS)

**A free, read-only forensic scanner for Windows.**
WSTS inspects your PC for malware indicators, persistence mechanisms, and signs
of log or credential-store tampering — then shows the results in your browser.
It runs **100% on your machine**. Nothing is uploaded, and no account is required.

Website: **https://wsts.spatcyber.com**

---

## What WSTS does

WSTS examines the same forensic artifacts that incident responders review after a suspected compromise. It **only reads** these artifacts — it never changes, deletes, quarantines, or transmits anything.

Check what it tells you.

**Prefetch execution**: Whether known hacking tools or abused Windows utilities (Mimikatz, PsExec, certutil, mshta, etc.) have run recently.

**Startup persistence**: Suspicious scripts or shortcuts planted in Startup folders that would re-launch malware on every boot.

**Event-log tampering**: Cleared or recently wiped Security/System/Application logs — a common way attackers hide their tracks.

**Credential stores**: Recent changes to DPAPI / Credential Manager files that may indicate credential theft.

**Amcache & NTUSER**: Tampering with the hives that record application-execution history.

Each finding is tagged so you can tell routine activity from things worth a closer look (for example: `KNOWN_SUSPICIOUS_TOOL`, `RAN_LAST_24H`, `POSSIBLY_CLEARED`, `RECENTLY_MODIFIED`).

---

## Before you download — make sure it's safe

Security tools are often flagged by antivirus because they read the same files
malware does. To remove all doubt, every WSTS release is fully verifiable.

1. **Download only from** `https://wsts.spatcyber.com`. We never publish WSTS on
   third-party download sites.
2. **Check the SHA-256 hash.** The official hash is shown on the download page.
   Compare it against your downloaded file (see "Verify your download" below).
3. **Confirm the digital signature.** Releases are signed as
   *Antibody Cyber Technology, LLC*.
4. **Review the VirusTotal report.** The download page links to a multi-engine
   scan of the exact file you're getting.

> If the hash on your file does **not** match the one on the website, delete the
> file and download it again. Do not run a file whose hash doesn't match.

---

## Installing & running

1. Go to **https://wsts.spatcyber.com** and click **Download for Windows**.
2. Verify the file (see [Verify download](https://wsts.spatcyber.com/#verify)) — recommended.
3. **Right-click `WSTS-Setup-<version>.exe` → Run as administrator.**
4. Administrator rights let WSTS read protected logs and hives. Without them, the scan still runs, but some areas will show as *inaccessible*.
5. WSTS opens a dashboard in your default browser at **`http://127.0.0.1:5900`**.

**If Windows SmartScreen warns you,** that's expected with newer security tools. After you've verified the SHA-256 hash, click **More info → Run anyway**.

---

## Using the dashboard

1. Click **Run Scan**. The scan takes a few seconds.
2. Results are grouped into collapsible sections: Prefetch, Startup, Event Logs, Credential Stores, and Amcache/NTUSER.
3. Click any section header to expand or collapse it.
4. The summary row at the top shows the host name, scan time, and a count of flagged items.

### Reading the results

- **Green/informational** items are normal.
- **Flagged** items carry one or more tags explaining *why* they were flagged.
- A flag does **not** automatically mean infection. Some tools (like PowerShell or `cmd`) are flagged for review because attackers abuse them — but they're also used legitimately every day.

### What to do with a flagged item

1. Note the **path**, **timestamp**, and **tags**.
2. Ask: *Do I recognize this program, and did I expect it to run at that time?*
3. If something looks genuinely unexpected — for example, a hacking tool you never installed, or a Security log that was recently cleared — treat the machine as potentially compromised: disconnect it from the network and consult an incident-response professional.

---

## Verify your download

Open **PowerShell** in the folder where you saved the file and run:

```powershell
# 1. Check the SHA-256 hash (compare to the value on the website)
Get-FileHash .\WSTS-Setup-1.0.0.exe -Algorithm SHA256

# 2. Confirm the digital signature is valid
Get-AuthenticodeSignature .\WSTS-Setup-1.0.0.exe | Format-List Status, SignerCertificate
```

- The hash from step 1 must **exactly** match the one shown on
  https://wsts.spatcyber.com.
- Step 2 should report **Status: Valid** and a publisher of
  **Antibody Cyber Technology, LLC**.

---

## Privacy

- WSTS makes **no outbound network connections**. You can block it in your firewall, and it will still work.
- All scanning happens locally. **No results, files, or telemetry leave your machine.**
- No account, no registration, no email address required.

---

## Frequently asked questions

**Does WSTS remove malware?**
No. WSTS is a *detection and assessment* tool. It reports indicators so you can
investigate; it does not delete or quarantine anything.

**Will it change anything on my system?**
No. It is strictly read-only.

**Do I have to install it?**
No installation is required — it's a single executable. Run it and it opens the
dashboard.

**Why does it need administrator rights?**
Some Windows logs and registry hives are protected. Administrator access lets
WSTS read them. Running without admin still works, but those areas are skipped.

**Which Windows versions are supported?**
Windows 10 and Windows 11 (64-bit).

**How do I close it?**
Close the browser tab and close the WSTS window (or press `Ctrl+C` if a console
window is open).

---

## Support

Questions or to report a security issue: **security@spatcyber.com**
Source code: **https://github.com/waynemcdon/spat**

© 2026 Antibody Cyber Technology, LLC
