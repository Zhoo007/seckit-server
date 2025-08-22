from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import ipaddress, re, shlex, subprocess, shutil
from typing import List, Optional

app = FastAPI()

# ---------- basic ----------
@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/ip")
async def my_ip(request: Request):
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    return {"ip": ip or "unknown"}

# ---------- helpers ----------
DOMAIN_RE = re.compile(r"^(?:(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63})$")
def valid_target(s: str) -> bool:
    s = s.strip()
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(s))

def run(cmd: list[str], timeout: int = 45) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if p.returncode != 0 and not out:
            raise HTTPException(400, err[:400] or "Command error")
        return (out + ("\n" + err if err else "")).strip()
    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Command timed out")

# ---------- nmap ----------
class ScanReq(BaseModel):
    target: str
    fast: bool = True

@app.post("/scan_ports")
async def scan_ports(req: ScanReq):
    t = req.target.strip()
    if not valid_target(t):
        raise HTTPException(400, "Invalid target. Use an IP or domain.")
    # Force unprivileged TCP connect scans on Render
    flags = (["-Pn", "-F", "-T4", "-sT", "--unprivileged"]
             if req.fast else ["-Pn", "-sT", "-sV", "-T3", "--unprivileged"])
    cmd = ["nmap", *flags, t]
    output = run(cmd, timeout=45)
    return {"command": " ".join(shlex.quote(c) for c in cmd), "output": output}

# ---------- sherlock (batched) ----------
# Notes:
# - mode="quick"  -> 4 sites (very fast)
# - mode="many"   -> ~30 curated sites, processed in batches (default)
# - mode="full"   -> ALL sites (may fail on free tier)
# - sites=[] overrides everything (you specify exact sites)
CURATED_MANY = [
    "GitHub","Reddit","Twitter","Instagram","TikTok","YouTube","Twitch","Pinterest",
    "Tumblr","Flickr","Steam","SoundCloud","DeviantArt","Medium","Patreon","VK",
    "Goodreads","StackOverflow","HackerNews","Replit","Keybase","AboutMe","ProductHunt",
    "Gravatar","Trello","Spotify","Telegram","Discord","Kaggle","GitLab"
]

class SherlockReq(BaseModel):
    username: str
    mode: str = "many"                 # "quick" | "many" | "full"
    sites: Optional[List[str]] = None  # optional explicit site list
    batch_size: int = 12               # for "many" or explicit sites

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

def sherlock_cmd(username: str, sites: Optional[List[str]], per_site_timeout: int) -> list[str]:
    # choose CLI: 'sherlock' or 'python -m sherlock'
    base = ["sherlock"] if shutil.which("sherlock") else ["python", "-m", "sherlock"]
    cmd = [*base, username, "--print-found", "--no-color", "--timeout", str(per_site_timeout)]
    if sites:
        for s in sites:
            cmd += ["--site", s]
    return cmd

@app.post("/sherlock")
async def sherlock_lookup(req: SherlockReq):
    u = req.username.strip()
    if not USERNAME_RE.fullmatch(u):
        raise HTTPException(400, "Invalid username. Use 1–32 chars: letters, digits, _ . -")

    mode = req.mode.lower().strip()
    # Build site list and time budgets
    if req.sites:
        sites = req.sites
        per_site_timeout = 5
        batch_size = max(1, min(req.batch_size, 20))
        overall_timeout = 90
    elif mode == "quick":
        sites = ["GitHub","Reddit","Instagram","Twitter"]
        per_site_timeout = 5
        batch_size = 12
        overall_timeout = 60
    elif mode == "many":
        sites = CURATED_MANY
        per_site_timeout = 5
        batch_size = 10
        overall_timeout = 120
    elif mode == "full":
        sites = None  # let sherlock use its full site list (heavy)
        per_site_timeout = 4
        batch_size = 0
        overall_timeout = 150
    else:
        raise HTTPException(400, "mode must be one of: quick | many | full")

    outputs: list[str] = []

    if sites:
        # batched runs to avoid one giant long process
        for i in range(0, len(sites), batch_size):
            chunk = sites[i:i+batch_size]
            cmd = sherlock_cmd(u, chunk, per_site_timeout)
            out = run(cmd, timeout=overall_timeout)
            outputs.append(f"# Batch {i//batch_size+1}: {', '.join(chunk)}\n{out}")
    else:
        # FULL run (may exceed free tier limits)
        cmd = sherlock_cmd(u, None, per_site_timeout)
        out = run(cmd, timeout=overall_timeout)
        outputs.append(out)

    # keep payload sane
    joined = "\n\n".join(outputs)
    lines = joined.splitlines()
    tail = "\n".join(lines[-600:]) if len(lines) > 600 else joined

    # show the *last* command that ran (or the full one for full mode)
    last_cmd = " ".join(shlex.quote(c) for c in (cmd if not sites else sherlock_cmd(u, sites[-batch_size:], per_site_timeout)))
    return {"command": last_cmd, "output": tail}

# ---------- holehe (email OSINT) ----------
import re, shutil, shlex
from urllib.parse import urlparse
from pydantic import BaseModel

class HoleheReq(BaseModel):
    email: str
    # optional: set to false if you ever want raw output back too
    found_only: bool = True

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
URL_RE = re.compile(r"https?://[^\s<>()\"']+")

def parse_holehe(output: str):
    """
    Extract URLs that look like positive matches from holehe output.
    Different holehe versions print tables or lines; we keep it robust:
    - scrape all http(s) URLs
    - dedupe
    - map to site hostnames
    """
    urls = []
    for m in URL_RE.finditer(output):
        url = m.group(0).rstrip(").,;")  # trim trailing punctuation
        urls.append(url)

    # dedupe while preserving order
    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    found = []
    for u in unique_urls:
        try:
            host = urlparse(u).netloc or u
        except Exception:
            host = u
        # normalize host (strip www.)
        if host.startswith("www."):
            host = host[4:]
        found.append({"site": host, "url": u})
    return found

@app.post("/holehe")
async def holehe_lookup(req: HoleheReq):
    e = req.email.strip()
    if not EMAIL_RE.fullmatch(e):
        raise HTTPException(400, "Invalid email format.")

    base = ["holehe"] if shutil.which("holehe") else ["python", "-m", "holehe"]
    cmd = [*base, e]
    out = run(cmd, timeout=140)  # allow a bit more time

    hits = parse_holehe(out)
    resp = {
        "command": " ".join(shlex.quote(c) for c in cmd),
        "count": len(hits),
        "found": hits
    }
    # keep a short raw tail for debugging if you ever need it
    if not req.found_only:
        tail = "\n".join(out.splitlines()[-300:])
        resp["raw_tail"] = tail

    return resp