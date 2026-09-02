import asyncio
import os
import sys
import json
import random
import string
import urllib.parse
import argparse
from playwright.async_api import async_playwright

# Helper to generate smooth mouse movements (Bezier curve emulation)
async def move_mouse_smoothly(page, start_x, start_y, end_x, end_y, steps=20):
    for i in range(steps):
        t = i / steps
        # Simple quadratic Bezier curve
        cx = (1 - t) * (1 - t) * start_x + 2 * (1 - t) * t * (start_x + end_x) / 2 + t * t * end_x
        cy = (1 - t) * (1 - t) * start_y + 2 * (1 - t) * t * (start_y + end_y) / 2 + t * t * end_y
        await page.mouse.move(cx, cy)
        await asyncio.sleep(random.uniform(0.01, 0.03))

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", type=str, help="Proxy string to use (http://user:pass@host:port)")
    parser.add_argument("--output", type=str, default="primed_cookies.json", help="Output JSON path")
    args = parser.parse_args()

    proxy = args.proxy
    if proxy in ["none", "direct", ""]:
        proxy = None
    elif not proxy:
        # Load user proxies as fallback
        proxy_path = r"D:\codev1\Tool Roblox\Roblox Account Generator\roblox-generator-netz\input\proxies.txt"
        if os.path.exists(proxy_path):
            with open(proxy_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
                if lines:
                    proxy = random.choice(lines)
    
    playwright_proxy = None
    if proxy:
        if not proxy.startswith('http') and not proxy.startswith('socks5'):
            proxy = 'http://' + proxy
        parsed = urllib.parse.urlparse(proxy)
        playwright_proxy = {
            "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
        }
        if parsed.username:
            playwright_proxy["username"] = parsed.username
        if parsed.password:
            playwright_proxy["password"] = parsed.password

    async with async_playwright() as p:
        print(f"[PRIMER] Launching browser with proxy: {proxy}")
        browser = await p.chromium.launch(
            headless=False,
            proxy=playwright_proxy,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-web-security",
                "--disable-features=UserAgentClientHint",
                "--disable-features=WebRtcHideLocalIpsWithMdns"
            ]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.96 Safari/537.36",
            viewport={"width": 1280, "height": 800}
        )
        page = await context.new_page()
        # Clean custom stealth init script
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            delete window.RTCPeerConnection;
            delete window.webkitRTCPeerConnection;
        """)
        
        print("[PRIMER] Navigating to Roblox.com/CreateAccount...")
        await page.goto("https://www.roblox.com/CreateAccount", timeout=25000, wait_until="load")
        
        print("[PRIMER] Simulating human interactions (warming up PerimeterX)...")
        # Scroll up and down
        await page.evaluate("window.scrollTo(0, 400)")
        await asyncio.sleep(random.uniform(0.5, 1.0))
        await page.evaluate("window.scrollTo(0, 0)")
        
        # Emulate smooth mouse movements
        for _ in range(5):
            x1, y1 = random.randint(100, 500), random.randint(100, 500)
            x2, y2 = random.randint(600, 1000), random.randint(400, 700)
            await move_mouse_smoothly(page, x1, y1, x2, y2, steps=15)
            await asyncio.sleep(random.uniform(0.3, 0.8))

        # Focus random fields or hover elements
        try:
            # Hover over a logo or text block to simulate engagement
            await page.hover("a.logo", timeout=3000)
        except Exception:
            pass

        print("[PRIMER] Taking screenshot of the page...")
        ss_path = r"C:\Users\my PC\.gemini\antigravity\brain\c8b036c0-0660-48c1-8d94-869e8bd07294\scratch\primer_roblox.png"
        await page.screenshot(path=ss_path)
        print(f"[PRIMER] Screenshot saved: {ss_path}")

        print("[PRIMER] Waiting for PerimeterX token computation to finish...")
        await asyncio.sleep(8)
        
        # Extract cookies
        cookies_list = await context.cookies()
        cookies_map = {}
        target_cookies = ["GuestData"]
        
        print("[PRIMER] ALL Extracted Cookies:")
        for c in cookies_list:
            print(f"  - {c['name']}: {c['value'][:25]}...")
            if c["name"] in target_cookies or c["name"].startswith("RBX"):
                cookies_map[c["name"]] = c["value"]

        # If PerimeterX cookies are missing, print warning
        if "_px3" not in cookies_map:
            print("[WARNING] PerimeterX cookie _px3 was not generated. Proxy might be blocked or JS failed.")

        # Ensure output directory exists
        out_dir = os.path.dirname(args.output)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # Write to JSON
        with open(args.output, "w") as f:
            json.dump(cookies_map, f, indent=2)
        print(f"[PRIMER] Saved primed cookies to {args.output}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
