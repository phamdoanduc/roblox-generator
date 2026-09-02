import asyncio
import json
import time
import requests
import random
import string
from urllib.parse import urlparse

try:
    from cloakbrowser import launch_async
except ImportError:
    from playwright.async_api import async_playwright
    async def launch_async(**kwargs):
        p = await async_playwright().start()
        browser = await p.chromium.launch(headless=kwargs.get("headless", True))
        return browser

async def main():
    print("[1] Launching browser to test registration & capture traffic...")
    proxy_str = "http://663e0bafbfdc38180cc0__cr.la,id,ph,sg,th,hk:44c3cd56014a9abf@gw.dataimpulse.com:10000"
    
    parsed = urlparse(proxy_str)
    playwright_proxy = {
        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
        "username": parsed.username,
        "password": parsed.password,
    }

    captured_requests = []

    try:
        browser = await launch_async(headless=True, proxy=playwright_proxy)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            locale="en-US",
            viewport={"width": 1280, "height": 720}
        )
        page = await context.new_page()

        async def on_request(request):
            if "roblox.com" in request.url:
                captured_requests.append({
                    "id": id(request),
                    "method": request.method,
                    "url": request.url,
                    "request_headers": dict(request.headers),
                    "postData": request.post_data
                })

        async def on_response(response):
            if "roblox.com" in response.url:
                try:
                    body = await response.text()
                except:
                    body = "<binary or missing>"
                for req in captured_requests:
                    if req.get("id") == id(response.request):
                        req["status"] = response.status
                        req["response_headers"] = dict(response.headers)
                        req["response_body"] = body
                        break

        page.on("request", on_request)
        page.on("response", on_response)

        print("[2] Navigating to https://www.roblox.com/...")
        await page.goto("https://www.roblox.com/", wait_until="networkidle", timeout=40000)
        await asyncio.sleep(3)

        cookies = await context.cookies()
        px3 = next((c["value"] for c in cookies if c["name"] == "_px3"), "")
        pxvid = next((c["value"] for c in cookies if c["name"] == "_pxvid"), "")
        print(f"[3] Harvested PX Cookies: _px3 len={len(px3)}, _pxvid={pxvid}")

        username = "TestUser" + "".join(random.choices(string.ascii_letters + string.digits, k=8))
        password = "P" + "".join(random.choices(string.ascii_letters + string.digits, k=10))
        print(f"[4] Attempting registration for username: {username}")

        # Wait for MonthDropdown element to load
        await page.wait_for_selector("#MonthDropdown", timeout=15000)
        await page.select_option("#MonthDropdown", index=3)
        await page.select_option("#DayDropdown", index=15)
        await page.select_option("#YearDropdown", label="2000")
        await page.fill("#signup-username", username)
        await page.fill("#signup-password", password)
        
        male_btn = await page.query_selector("#maleButton")
        if male_btn:
            await male_btn.click()
        
        await asyncio.sleep(2)

        signup_btn = await page.query_selector("#signup-button")
        if signup_btn:
            print("[5] Clicking signup button...")
            await signup_btn.click()
            await asyncio.sleep(8)

        print(f"[6] Total captured Roblox network requests: {len(captured_requests)}")
        
        with open("captured_traffic.json", "w", encoding="utf-8") as f:
            json.dump(captured_requests, f, indent=2)
        print("[7] Saved captured traffic to captured_traffic.json")

        await browser.close()

    except Exception as e:
        print(f"[ERROR] Exception during browser run: {e}")

if __name__ == "__main__":
    asyncio.run(main())
