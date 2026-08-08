#!/usr/bin/env python3
"""
Himaya detonation harness (runs INSIDE the ephemeral ACI container).

Input : env DETONATION_JOB = base64(json) with:
          { "urls": ["http://..."],
            "attachments": [{"name": "file.docm", "url": "<SAS download url>"}] }
Output: the results JSON printed between RESULTS_START / RESULTS_END markers so
        the backend can parse it out of the container logs. Schema is a superset
        of the legacy contract (url_results / attachment_results) with extra
        signal fields consumed by the verdict engine.

Every analyzer is wrapped in try/except so a single tool failure never aborts
the whole detonation.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

RESULTS_START = "___SANDBOX_RESULTS_START___"
RESULTS_END = "___SANDBOX_RESULTS_END___"

RULES_DIR = "/opt/detonator/rules"
MAX_URLS = 5
MAX_ATTACHMENTS = 8
MAX_DL_BYTES = 25 * 1024 * 1024          # 25 MB per attachment
STRINGS_CAP = 4000                        # chars of `strings` output kept

MACRO_EXTS = {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb",
              ".xlt", ".xltm", ".ppt", ".pptm", ".pot", ".potm", ".rtf"}
HIGH_RISK_EXTS = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
                  ".js", ".jse", ".wsf", ".hta", ".jar", ".scr", ".pif",
                  ".com", ".cpl", ".lnk"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".gz", ".tar", ".cab", ".iso", ".img"}


def _run(cmd, timeout=45, input_bytes=None):
    """Run a subprocess, returning (returncode, stdout_text). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           input=input_bytes)
        out = (p.stdout or b"").decode("utf-8", "ignore")
        err = (p.stderr or b"").decode("utf-8", "ignore")
        return p.returncode, out + ("\n" + err if err else "")
    except Exception as e:
        return -1, f"__ERR__ {e}"


# ── YARA (compiled once) ─────────────────────────────────────────────────────
_YARA = None
try:
    import yara
    _rule_files = {}
    if os.path.isdir(RULES_DIR):
        for fn in os.listdir(RULES_DIR):
            if fn.endswith((".yar", ".yara")):
                _rule_files[fn] = os.path.join(RULES_DIR, fn)
    if _rule_files:
        _YARA = yara.compile(filepaths=_rule_files)
except Exception as _ye:
    _YARA = None


def _yara_scan(path):
    if not _YARA:
        return []
    try:
        hits = _YARA.match(path, timeout=30)
        return [{"rule": h.rule, "severity": (h.meta or {}).get("severity", "suspicious")}
                for h in hits]
    except Exception:
        return []


def _clamav_scan(path):
    rc, out = _run(["clamscan", "--no-summary", "--stdout", path], timeout=90)
    if rc == 1:
        m = re.search(r":\s*(.+?)\s+FOUND", out)
        return {"infected": True, "signature": (m.group(1) if m else "unknown")}
    return {"infected": False, "signature": ""}


def _olevba(path):
    info = {"macro_detected": False, "autoexec": False,
            "suspicious": [], "iocs": []}
    rc, out = _run(["olevba", "--no-color", path], timeout=60)
    if "VBA MACRO" in out or "VBA_MACRO" in out:
        info["macro_detected"] = True
    for line in out.splitlines():
        if "|AutoExec" in line or "|Auto_Open" in line:
            info["autoexec"] = True
        if "|Suspicious" in line:
            kw = line.split("|")
            if len(kw) > 2:
                info["suspicious"].append(kw[2].strip()[:80])
        if "|IOC" in line:
            kw = line.split("|")
            if len(kw) > 2:
                info["iocs"].append(kw[2].strip()[:200])
    info["suspicious"] = info["suspicious"][:15]
    info["iocs"] = info["iocs"][:15]
    return info


def _pdf_scan(path):
    try:
        with open(path, "rb") as f:
            data = f.read(5 * 1024 * 1024)
    except Exception:
        return {}
    counts = {}
    for kw in ("/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch",
               "/EmbeddedFile", "/URI", "/RichMedia", "/AcroForm"):
        c = len(re.findall(re.escape(kw.encode()), data))
        if c:
            counts[kw] = c
    return counts


def _archive_scan(path):
    """List archive contents; detect encryption + dangerous inner files."""
    info = {"encrypted": False, "entries": [], "dangerous_entries": []}
    rc, out = _run(["7z", "l", "-slt", "-p", path], timeout=45)
    cur = {}
    for line in out.splitlines():
        if line.startswith("Path = "):
            cur = {"path": line[7:]}
        elif line.startswith("Encrypted = "):
            enc = line.split("=", 1)[1].strip()
            if enc == "+":
                info["encrypted"] = True
        elif line == "" and cur.get("path"):
            info["entries"].append(cur["path"])
            cur = {}
    # 7z prints "Encrypted = +" per-file; some formats mark headers encrypted
    if "Encrypted = +" in out or "Wrong password" in out or "Enter password" in out:
        info["encrypted"] = True
    for e in info["entries"][:100]:
        ext = ("." + e.rsplit(".", 1)[-1]).lower() if "." in e else ""
        if ext in HIGH_RISK_EXTS or ext in MACRO_EXTS:
            info["dangerous_entries"].append(e)
    info["entries"] = info["entries"][:50]
    return info


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _file_type(path):
    try:
        import magic
        return magic.from_file(path)
    except Exception:
        rc, out = _run(["file", "-b", path], timeout=15)
        return out.strip()[:200]


def _strings(path):
    rc, out = _run(["strings", "-n", "8", path], timeout=30)
    return out[:STRINGS_CAP]


def analyze_attachment(name, path):
    res = {
        "filename": name, "sha256": _sha256(path),
        "size": os.path.getsize(path) if os.path.exists(path) else 0,
        "file_type": _file_type(path), "ext": "",
        "macro_detected": False, "olevba": {}, "pdf": {}, "archive": {},
        "yara": [], "clamav": {}, "strings_preview": "",
        "indicators": [], "severity": "clean", "error": "",
    }
    ext = ("." + name.rsplit(".", 1)[-1]).lower() if "." in name else ""
    res["ext"] = ext
    ind = res["indicators"]

    try:
        ft = (res["file_type"] or "").lower()

        # YARA + ClamAV on every file
        res["yara"] = _yara_scan(path)
        res["clamav"] = _clamav_scan(path)

        # Office / OLE macro analysis
        if ext in MACRO_EXTS or "composite document" in ft or "microsoft" in ft \
                or "opendocument" in ft or ("zip" in ft and ext in MACRO_EXTS):
            ole = _olevba(path)
            res["olevba"] = ole
            res["macro_detected"] = ole.get("macro_detected", False)
            if ole.get("autoexec"):
                ind.append("macro_autoexec")
            if ole.get("suspicious"):
                ind.append("macro_suspicious_keywords")
            elif ole.get("macro_detected"):
                ind.append("macro_present")

        # PDF structural analysis
        if ext == ".pdf" or "pdf document" in ft:
            pdf = _pdf_scan(path)
            res["pdf"] = pdf
            if pdf.get("/JS") or pdf.get("/JavaScript"):
                ind.append("pdf_javascript")
            if pdf.get("/OpenAction") or pdf.get("/AA"):
                ind.append("pdf_auto_action")
            if pdf.get("/Launch"):
                ind.append("pdf_launch_action")
            if pdf.get("/EmbeddedFile"):
                ind.append("pdf_embedded_file")

        # Archives
        if ext in ARCHIVE_EXTS or "archive" in ft or "zip" in ft:
            arc = _archive_scan(path)
            res["archive"] = arc
            if arc.get("encrypted"):
                ind.append("encrypted_archive")
            if arc.get("dangerous_entries"):
                ind.append("archive_contains_dangerous")

        # Dangerous by type / extension
        if ext in HIGH_RISK_EXTS:
            ind.append("dangerous_extension")
        if "pe32" in ft or "ms-dos executable" in ft:
            ind.append("windows_executable")

        res["strings_preview"] = _strings(path)

        # ── Severity roll-up ────────────────────────────────────────────────
        yara_mal = any(y.get("severity") == "malicious" for y in res["yara"])
        yara_any = bool(res["yara"])
        if res["clamav"].get("infected") or yara_mal \
                or ("macro_autoexec" in ind and "macro_suspicious_keywords" in ind) \
                or ("pdf_javascript" in ind and "pdf_auto_action" in ind) \
                or "pdf_launch_action" in ind \
                or ("windows_executable" in ind and ext not in ("",)) \
                or "archive_contains_dangerous" in ind:
            res["severity"] = "malicious"
        elif yara_any or "macro_present" in ind or "macro_autoexec" in ind \
                or "pdf_javascript" in ind or "encrypted_archive" in ind \
                or "dangerous_extension" in ind or "pdf_embedded_file" in ind:
            res["severity"] = "suspicious"
    except Exception as e:
        res["error"] = str(e)[:300]
    return res


def detonate_url(url):
    res = {
        "url": url, "status_code": None, "final_url": "", "redirect_chain": [],
        "page_title": "", "has_login_form": False, "auto_download": "",
        "phishing_keywords": [], "resource_domains": [],
        "suspicious_indicators": [], "screenshot_b64": "",
        "severity": "clean", "error": "",
    }
    ind = res["suspicious_indicators"]
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-gpu"],
            )
            ctx = browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/124.0 Safari/537.36"),
                accept_downloads=True, ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            page = ctx.new_page()

            def _on_resp(r):
                try:
                    if 300 <= r.status < 400:
                        loc = r.headers.get("location")
                        if loc:
                            res["redirect_chain"].append(loc)
                    dom = re.search(r"https?://([^/]+)", r.url)
                    if dom:
                        res["resource_domains"].append(dom.group(1))
                except Exception:
                    pass
            page.on("response", _on_resp)

            def _on_dl(d):
                try:
                    res["auto_download"] = d.suggested_filename or "download"
                except Exception:
                    res["auto_download"] = "download"
            page.on("download", _on_dl)

            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
                if resp:
                    res["status_code"] = resp.status
                page.wait_for_timeout(2500)
            except Exception as nav_e:
                res["error"] = f"nav: {str(nav_e)[:200]}"

            try:
                res["final_url"] = page.url
                res["page_title"] = (page.title() or "")[:200]
                res["has_login_form"] = page.query_selector(
                    "input[type=password]") is not None
                content = (page.content() or "").lower()
                for kw in ("verify your account", "sign in", "log in",
                           "password", "microsoft", "office365", "onedrive",
                           "docusign", "update your", "confirm your",
                           "unusual activity", "your account has been"):
                    if kw in content:
                        res["phishing_keywords"].append(kw)
                shot = page.screenshot(type="jpeg", quality=45)
                res["screenshot_b64"] = base64.b64encode(shot).decode()[:400000]
            except Exception:
                pass

            res["resource_domains"] = sorted(set(res["resource_domains"]))[:25]
            browser.close()

        # ── Indicators + severity ───────────────────────────────────────────
        host = re.search(r"https?://([^/]+)", res["final_url"] or url)
        hoststr = host.group(1) if host else ""
        if res["has_login_form"] and res["phishing_keywords"]:
            ind.append("credential_harvesting_page")
        if res["auto_download"]:
            dl_ext = ("." + res["auto_download"].rsplit(".", 1)[-1]).lower() \
                if "." in res["auto_download"] else ""
            ind.append("auto_download" + (f":{dl_ext}" if dl_ext else ""))
        if len(res["redirect_chain"]) > 2:
            ind.append(f"redirect_chain_{len(res['redirect_chain'])}")
        if hoststr and (re.search(r"\d{4,}", hoststr) or len(hoststr) > 40):
            ind.append("suspicious_domain_pattern")
        if res["phishing_keywords"]:
            ind.append("phishing_keywords")

        dl_dangerous = res["auto_download"] and (
            "." + res["auto_download"].rsplit(".", 1)[-1]).lower() in (
            HIGH_RISK_EXTS | ARCHIVE_EXTS) if "." in (res["auto_download"] or "") else False
        if "credential_harvesting_page" in ind or dl_dangerous:
            res["severity"] = "malicious"
        elif res["has_login_form"] or res["phishing_keywords"] \
                or len(res["redirect_chain"]) > 2 or res["auto_download"] \
                or "suspicious_domain_pattern" in ind:
            res["severity"] = "suspicious"
    except Exception as e:
        res["error"] = (res.get("error") or "") + f" | {str(e)[:200]}"
    return res


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "himaya-detonator"})
    with urllib.request.urlopen(req, timeout=60) as r:
        total = 0
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DL_BYTES:
                    raise RuntimeError("attachment exceeds size cap")
                f.write(chunk)
    return total


def main():
    job_raw = os.environ.get("DETONATION_JOB", "")
    try:
        job = json.loads(base64.b64decode(job_raw).decode()) if job_raw else {}
    except Exception:
        job = {}

    urls = (job.get("urls") or [])[:MAX_URLS]
    attachments = (job.get("attachments") or [])[:MAX_ATTACHMENTS]

    url_results = []
    for u in urls:
        if isinstance(u, str) and u.startswith("http"):
            url_results.append(detonate_url(u))

    attachment_results = []
    tmp = tempfile.mkdtemp(prefix="det_")
    for a in attachments:
        name = (a or {}).get("name", "attachment")
        src = (a or {}).get("url", "")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "attachment"
        dest = os.path.join(tmp, safe)
        if not src:
            attachment_results.append({
                "filename": name, "severity": "clean",
                "indicators": [], "error": "no download url (metadata only)",
            })
            continue
        try:
            _download(src, dest)
            attachment_results.append(analyze_attachment(name, dest))
        except Exception as e:
            attachment_results.append({
                "filename": name, "severity": "clean",
                "indicators": [], "error": f"download failed: {str(e)[:200]}",
            })

    # Overall verdict
    sev = [r.get("severity") for r in (url_results + attachment_results)]
    if "malicious" in sev:
        verdict = "MALICIOUS"
    elif "suspicious" in sev:
        verdict = "SUSPICIOUS"
    elif url_results or attachment_results:
        verdict = "CLEAN"
    else:
        verdict = "TIMEOUT"

    out = {
        "verdict": verdict,
        "url_results": url_results,
        "attachment_results": attachment_results,
        "tools": ["playwright", "clamav", "yara", "oletools", "pdf", "7z",
                  "exiftool", "file", "strings"],
    }
    print(RESULTS_START)
    print(json.dumps(out))
    print(RESULTS_END)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(RESULTS_START)
        print(json.dumps({"verdict": "UNAVAILABLE", "error": str(e)[:300],
                          "url_results": [], "attachment_results": []}))
        print(RESULTS_END)
        sys.exit(0)
