from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/ip")
async def my_ip(request: Request):
    # works behind Render’s proxy
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    return {"ip": ip or "unknown"}