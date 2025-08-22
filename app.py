from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import ipaddress, re, shlex, subprocess

app = FastAPI()

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/ip")
async def my_ip(request: Request):
    # works behind Render’s proxy
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    return {"ip": ip or "unknown"}

# ---- helpers ----
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
        raise HTTPException(408, "Scan timed out")

class ScanReq(BaseModel):
    target: str
    fast: bool = True

@app.post("/scan_ports")
async def scan_ports(req: ScanReq):
    t = req.target.strip()
    if not valid_target(t):
        raise HTTPException(400, "Invalid target. Use an IP or domain.")

    # Force unprivileged TCP connect scans on Render
    flags = (
        ["-Pn", "-F", "-T4", "-sT", "--unprivileged"]
        if req.fast
        else ["-Pn", "-sT", "-sV", "-T3", "--unprivileged"]
    )
    cmd = ["nmap", *flags, t]
    output = run(cmd, timeout=45)
    return {
        "command": " ".join(shlex.quote(c) for c in cmd),
        "output": output
    }