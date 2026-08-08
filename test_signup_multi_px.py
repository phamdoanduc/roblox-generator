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
    print("=== Multi-Account Browser Capture Script (10 accounts) ===")
    proxy_str = "http://663e0bafbfdc38180cc0__cr.la,id,ph,sg,th,hk:44c3cd56014a9abf@gw.dataimpulse.com:10000"
    
    parsed = urlparse(proxy_str)
    playwright_proxy = {
        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
        "username": parsed.username,
        "password": parsed.password,
    }

    all_captured_traffic = []

    try:
        print("[1] Launching CloakBrowser...")
        browser = await launch_async(headless=True, proxy=playwright_proxy)
        
        for acc_num in range(1, 11):
            print(f"\n--- [Account #{acc_num}/10] ---")
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                locale="en-US",
                viewport={"width": 1280, "height": 720}
            )
            page = await context.new_page()

            acc_traffic = {
                "account_index": acc_num,
                "requests": []
            }

            async def on_request(request):
                if "roblox.com" in request.url:
                    acc_traffic["requests"].append({
                        "method": request.method,
                        "url": request.url,
                        "headers": dict(request.headers),
                        "postData": request.post_data
                    })

            page.on("request", on_request)

            try:
                print(f"[{acc_num}] Navigating to https://www.roblox.com/...")
                await page.goto("https://www.roblox.com/", wait_until="networkidle", timeout=30000)
                await asyncio.sleep(2)

                cookies = await context.cookies()
                px3 = next((c["value"] for c in cookies if c["name"] == "_px3"), "")
                print(f"[{acc_num}] PX3 Cookie len: {len(px3)}")

                username = "NetZTest" + "".join(random.choices(string.ascii_letters + string.digits, k=6))
                password = "P" + "".join(random.choices(string.ascii_letters + string.digits, k=10))
                print(f"[{acc_num}] Target Username: {username}")

                await page.wait_for_selector("#MonthDropdown", timeout=10000)
                await page.select_option("#MonthDropdown", index=random.randint(1, 12))
                await page.select_option("#DayDropdown", index=random.randint(1, 28))
                await page.select_option("#YearDropdown", label=str(random.randint(1995, 2005)))
                await page.fill("#signup-username", username)
                await page.fill("#signup-password", password)
                
                male_btn = await page.query_selector("#maleButton")
                if male_btn:
                    await male_btn.click()
                
                await asyncio.sleep(1)

                signup_btn = await page.query_selector("#signup-button")
                if signup_btn:
                    print(f"[{acc_num}] Submitting signup form...")
                    await signup_btn.click()
                    # Wait up to 15 seconds to capture full signup / challenge response
                    await asyncio.sleep(12)

                print(f"[{acc_num}] Captured {len(acc_traffic['requests'])} network requests.")
                all_captured_traffic.append(acc_traffic)

            except Exception as e:
                print(f"[{acc_num}] Error during signup: {e}")
            finally:
                await context.close()

        with open("captured_traffic_multi.json", "w", encoding="utf-8") as f:
            json.dump(all_captured_traffic, f, indent=2)
        print("\n=== Done! Saved multi-account traffic to captured_traffic_multi.json ===")

        await browser.close()

    except Exception as e:
        print(f"[ERROR] Exception during browser run: {e}")

if __name__ == "__main__":
    asyncio.run(main())
