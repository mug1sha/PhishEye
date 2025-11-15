import httpx, os, socket, whois
from dotenv import load_dotenv
from models import save_scan_result

load_dotenv()
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
US_API = os.getenv("URLSCAN_API_KEY")
GSB_API = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

async def virus_total_scan(url):
    headers = {"x-apikey": VT_API}
    async with httpx.AsyncClient() as client:
        res = await client.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
        scan_id = res.json()["data"]["id"]
        report = await client.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        return report.json()

async def urlscan_io_scan(url):
    headers = {"API-Key": US_API, "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        res = await client.post("https://urlscan.io/api/v1/scan", json={"url": url}, headers=headers)
        uuid = res.json()["uuid"]
        report = await client.get(f"https://urlscan.io/api/v1/result/{uuid}")
        return report.json()

async def google_safe_browsing(url):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}",
            json={
                "client": {"clientId": "mshield", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
        )
        return res.json()

def enrich_osint(url):
    domain = url.split("//")[-1].split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
        whois_data = whois.whois(domain)
    except:
        ip, whois_data = "N/A", {}
    return {"domain": domain, "ip": ip, "whois": str(whois_data)}

def perform_full_scan(url):
    import asyncio
    vt, us, gsb = asyncio.run(asyncio.gather(
        virus_total_scan(url),
        urlscan_io_scan(url),
        google_safe_browsing(url)
    ))
    osint = enrich_osint(url)
    result = {"url": url, "virustotal": vt, "urlscan": us, "google_safe": gsb, "osint": osint}
    save_scan_result(result)
    return result
