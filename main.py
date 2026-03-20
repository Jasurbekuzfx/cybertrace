# ============================================================
#  CyberTrace — FastAPI Backend + Static Frontend
#  Railway deployment ready
# ============================================================

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx
import hashlib
import time
import os
import base64
from collections import defaultdict
from pathlib import Path

app = FastAPI(
    title="CyberTrace API",
    version="2.4.1",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API KEYS ──
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
IPINFO_TOKEN       = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY      = os.getenv("ABUSEIPDB_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ── RATE LIMITER ──
rate_store = defaultdict(list)
RATE_LIMIT  = 20
RATE_WINDOW = 60

def check_rate_limit(ip: str):
    now = time.time()
    rate_store[ip] = [t for t in rate_store[ip] if now - t < RATE_WINDOW]
    if len(rate_store[ip]) >= RATE_LIMIT:
        raise HTTPException(429, "Rate limit: 20 req/min")
    rate_store[ip].append(now)

# ─────────────────────────────────────────────
#  HEALTH CHECK
# ─────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "version": "2.4.1",
        "platform": "Railway",
        "apis": {
            "virustotal": "✓ configured" if VIRUSTOTAL_API_KEY else "✗ missing",
            "ipinfo":     "✓ configured" if IPINFO_TOKEN else "✗ missing",
            "abuseipdb":  "✓ configured" if ABUSEIPDB_KEY else "✗ missing",
        }
    }

# ─────────────────────────────────────────────
#  1. URL / PHISHING ANALYZER
# ─────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

@app.post("/api/analyze/url")
async def analyze_url(body: URLRequest, request: Request):
    check_rate_limit(request.client.host)

    url = body.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    domain = ""
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).hostname or url
    except:
        domain = url

    # Parallel requests
    vt_result  = await vt_url_scan(url)
    ip_result  = await ipinfo_lookup(domain)
    risk_score = calc_url_risk(vt_result, ip_result, domain)

    return {
        "url": url,
        "domain": domain,
        "ip": ip_result.get("ip", "—"),
        "hosting_provider": ip_result.get("org", "—"),
        "location": f"{ip_result.get('city','')}, {ip_result.get('country','')}".strip(", "),
        "timezone": ip_result.get("timezone", "—"),
        "ssl_valid": "HTTPS — Xavfsiz" if url.startswith("https") else "HTTP — SSL yo'q",
        "virustotal": vt_result,
        "risk_score": risk_score,
        "verdict": get_verdict(risk_score),
        "ip_details": ip_result,
    }

async def vt_url_scan(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VT API key yo'q", "malicious": 0, "suspicious": 0}
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )
            if r.status_code == 200:
                data = r.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                total = sum(stats.values())
                return {
                    "found": True,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "engines_total": total,
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                }
            elif r.status_code == 404:
                # Yangi scan boshlash
                await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url}
                )
                return {"found": False, "malicious": 0, "suspicious": 0,
                        "message": "Scan boshlandi — 30 soniyadan keyin qayta urinib ko'ring",
                        "permalink": f"https://www.virustotal.com/gui/url/{url_id}"}
        except Exception as e:
            return {"error": str(e), "malicious": 0, "suspicious": 0}
    return {"malicious": 0, "suspicious": 0}

async def ipinfo_lookup(domain: str) -> dict:
    if not IPINFO_TOKEN:
        return {}
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            import socket
            try:    ip = socket.gethostbyname(domain)
            except: ip = domain
            r = await client.get(f"https://ipinfo.io/{ip}", params={"token": IPINFO_TOKEN})
            if r.status_code == 200:
                d = r.json()
                d["ip"] = ip
                return d
        except Exception as e:
            return {"error": str(e)}
    return {}

def calc_url_risk(vt: dict, ip: dict, domain: str) -> int:
    s = 0
    s += min((vt.get("malicious", 0)) * 9, 65)
    s += min((vt.get("suspicious", 0)) * 3, 15)
    bad_tlds = [".xyz",".bond",".win",".top",".tk",".ml",".ga",".cf",".site",".click",".gq"]
    if any(domain.endswith(t) for t in bad_tlds): s += 15
    brands = ["paypal","google","facebook","apple","amazon","netflix","bank","uzcard","humo","payme"]
    for b in brands:
        if b in domain and not domain.startswith(b + "."): s += 25; break
    first = domain.split(".")[0]
    if any(c.isdigit() for c in first): s += 10
    org = (ip.get("org") or "").lower()
    if any(x in org for x in ["tor","vpn","proxy","bulletproof"]): s += 15
    return min(s, 100)

def get_verdict(score: int) -> str:
    return "dangerous" if score >= 70 else "suspicious" if score >= 40 else "safe"

# ─────────────────────────────────────────────
#  2. IP INTELLIGENCE
# ─────────────────────────────────────────────
@app.get("/api/analyze/ip/{ip_address}")
async def analyze_ip(ip_address: str, request: Request):
    check_rate_limit(request.client.host)

    ip_data   = {}
    abuse_data = {}

    if IPINFO_TOKEN:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(
                    f"https://ipinfo.io/{ip_address}",
                    params={"token": IPINFO_TOKEN}
                )
                if r.status_code == 200:
                    ip_data = r.json()
            except: pass

    if ABUSEIPDB_KEY:
        async with httpx.AsyncClient(timeout=8) as client:
            try:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90}
                )
                if r.status_code == 200:
                    abuse_data = r.json().get("data", {})
            except: pass

    loc   = (ip_data.get("loc") or "0,0").split(",")
    lat   = float(loc[0]) if len(loc) == 2 else 0.0
    lon   = float(loc[1]) if len(loc) == 2 else 0.0
    org   = ip_data.get("org", "")
    abuse = abuse_data.get("abuseConfidenceScore", 0)
    is_tor = "tor" in org.lower()
    is_vpn = "vpn" in org.lower() or abuse_data.get("usageType","") == "VPN Service"

    risk = "dangerous" if abuse > 70 or is_tor else \
           "suspicious" if abuse > 30 or is_vpn else "safe"

    tags = []
    if is_tor: tags.append({"label":"TOR EXIT NODE","color":"red"})
    if is_vpn: tags.append({"label":"VPN","color":"orange"})
    if abuse > 50: tags.append({"label":"HIGH ABUSE","color":"red"})
    if not tags: tags.append({"label":"CLEAN","color":"green"})
    if ip_data.get("country"): tags.append({"label": ip_data["country"], "color":"cyan"})

    return {
        "ip":            ip_address,
        "city":          ip_data.get("city", ""),
        "region":        ip_data.get("region", ""),
        "country":       ip_data.get("country", ""),
        "org":           org,
        "asn":           org.split(" ")[0] if " " in org else org,
        "isp":           " ".join(org.split(" ")[1:]) if " " in org else "",
        "lat":           lat,
        "lon":           lon,
        "timezone":      ip_data.get("timezone", ""),
        "is_tor":        is_tor,
        "is_vpn":        is_vpn,
        "abuse_score":   abuse,
        "abuse_reports": abuse_data.get("totalReports", 0),
        "risk":          risk,
        "tags":          tags,
    }

# ─────────────────────────────────────────────
#  3. APK ANALYZER
# ─────────────────────────────────────────────
@app.post("/api/analyze/apk")
async def analyze_apk(request: Request, file: UploadFile = File(...)):
    check_rate_limit(request.client.host)

    if not file.filename.lower().endswith((".apk", ".xapk", ".aab")):
        raise HTTPException(400, "Faqat .apk, .xapk, .aab fayllar qabul qilinadi")

    content = await file.read()
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(413, "Fayl juda katta (max 100MB)")

    sha256 = hashlib.sha256(content).hexdigest()
    md5    = hashlib.md5(content).hexdigest()
    size   = round(len(content) / 1024 / 1024, 2)

    vt_result = await vt_hash_check(sha256)
    risk_score = min((vt_result.get("malicious", 0)) * 10 + 10, 100)

    return {
        "filename":  file.filename,
        "size_mb":   size,
        "sha256":    sha256,
        "md5":       md5,
        "virustotal": vt_result,
        "risk_score": risk_score,
        "verdict":   get_verdict(risk_score),
    }

async def vt_hash_check(file_hash: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VT API key yo'q", "malicious": 0}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if r.status_code == 200:
                d = r.json()
                stats = d["data"]["attributes"]["last_analysis_stats"]
                return {
                    "found":      True,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "engines_total": sum(stats.values()),
                    "name":       d["data"]["attributes"].get("meaningful_name", ""),
                    "permalink":  f"https://www.virustotal.com/gui/file/{file_hash}",
                }
            return {"found": False, "malicious": 0, "message": "VT bazasida topilmadi"}
        except Exception as e:
            return {"error": str(e), "malicious": 0}

# ─────────────────────────────────────────────
#  4. SCAM DATABASE
# ─────────────────────────────────────────────
scam_db = [
    {"domain":"secure-paypa1.com",      "type":"PHISHING","score":97,"reports":1247,"date":"2026-01-12","status":"TASDIQLANGAN"},
    {"domain":"bank0famerica.com",       "type":"PHISHING","score":99,"reports":2109,"date":"2026-02-01","status":"TASDIQLANGAN"},
    {"domain":"uzcard-verify.xyz",       "type":"PHISHING","score":95,"reports":847, "date":"2026-02-14","status":"TASDIQLANGAN"},
    {"domain":"crypto-profit-uz.net",    "type":"FRAUD",   "score":88,"reports":412, "date":"2026-03-01","status":"TEKSHIRILMOQDA"},
    {"domain":"apk-premium-mod.xyz",     "type":"MALWARE", "score":85,"reports":341, "date":"2026-03-05","status":"TEKSHIRILMOQDA"},
    {"domain":"humo-online.site",        "type":"PHISHING","score":93,"reports":623, "date":"2026-03-12","status":"TASDIQLANGAN"},
    {"domain":"payme-support-bot.ru",    "type":"PHISHING","score":91,"reports":512, "date":"2026-03-15","status":"TASDIQLANGAN"},
]

@app.get("/api/scamdb/search")
async def search_scamdb(q: str = ""):
    if not q:
        return {"results": scam_db, "total": len(scam_db)}
    results = [s for s in scam_db if q.lower() in s["domain"].lower() or q.lower() in s["type"].lower()]
    return {"results": results, "total": len(results)}

class ScamReport(BaseModel):
    url: str
    category: str
    severity: str
    description: str

@app.post("/api/scamdb/report")
async def report_scam(body: ScamReport, request: Request):
    check_rate_limit(request.client.host)
    entry = {
        "domain":  body.url,
        "type":    body.category.upper()[:20],
        "score":   50,
        "reports": 1,
        "date":    time.strftime("%Y-%m-%d"),
        "status":  "TEKSHIRILMOQDA"
    }
    scam_db.append(entry)
    return {"success": True, "message": "Xabar qabul qilindi!", "entry": entry}

# ─────────────────────────────────────────────
#  5. TELEGRAM SCANNER
# ─────────────────────────────────────────────
KNOWN_TG_SCAMS = {
    "crypto_profit_bot", "support_paypal_bot", "verify_account_bot",
    "free_usdt_bot", "investment_guaranteed_bot", "uzcard_bot_official",
    "humo_support_bot", "payme_help_bot", "nbu_official_bot_uz",
}

@app.get("/api/telegram/check")
async def check_telegram(username: str, request: Request):
    check_rate_limit(request.client.host)
    username = username.lstrip("@").lower().strip()

    patterns = [
        ("support" in username and "bot" in username),
        ("official" in username and any(b in username for b in ["uzcard","humo","payme","nbu"])),
        ("verify" in username),
        ("airdrop" in username),
        ("free" in username and ("usdt" in username or "btc" in username)),
        (username in KNOWN_TG_SCAMS),
    ]
    is_flagged = any(patterns)

    tg_info = {}
    if TELEGRAM_BOT_TOKEN:
        async with httpx.AsyncClient(timeout=6) as client:
            try:
                r = await client.get(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat",
                    params={"chat_id": f"@{username}"}
                )
                if r.status_code == 200:
                    tg_info = r.json().get("result", {})
            except: pass

    return {
        "username":       username,
        "is_flagged":     is_flagged,
        "risk":           "dangerous" if is_flagged else "safe",
        "telegram_info":  tg_info,
        "recommendation": "MULOQOT QILMANG!" if is_flagged else "Bazada topilmadi — ehtiyot bo'ling",
        "patterns_matched": sum(patterns),
    }

# ─────────────────────────────────────────────
#  STATIC FILES (Frontend)
# ─────────────────────────────────────────────
static_dir = Path("static")
if static_dir.exists():
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

# ─────────────────────────────────────────────
#  ISHGA TUSHIRISH:
#
#  1. pip install -r requirements.txt
#  2. mkdir static && cp cybertrace-v2.html static/index.html
#  3. export VIRUSTOTAL_API_KEY="..."
#  4. uvicorn main:app --reload --port 8000
#
#  Railway uchun:
#  Barcha fayllarni GitHub'ga yuklang
#  railway.app → Deploy from GitHub
# ─────────────────────────────────────────────
