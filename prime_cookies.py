"""
Validation-test tool (not part of production flow).

Opens a REAL Chrome browser through a given proxy, visits the same page the
Go client warms up on (www.roblox.com), lets PerimeterX/Arkose JS run for a
few seconds, then dumps the resulting cookies to a JSON file that
register.go's loadPrimedCookies() can pick up via the PRIMED_COOKIES_FILE
env var.

Goal: find out whether a real-browser-obtained trust cookie (vs. one minted
purely from azuretls's TLS fingerprint) changes registration outcome, and how
much dwell time PerimeterX actually needs before it upgrades trust.

Usage:
    python prime_cookies.py --proxy-index 0 --dwell 5 --out primed_cookies.json

Never print cookie VALUES to stdout -- only names -- these are live session
tokens.
"""

import argparse
import json
import os
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

WATCH_DOMAINS = ("roblox.com", "arkoselabs.com", "funcaptcha.com")


def load_proxy(index: int) -> dict:
    path = os.path.join(os.path.dirname(__file__), "input", "proxies.txt")
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    raw = lines[index]
    parsed = urlparse(raw)
    proxy = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
    if parsed.username:
        proxy["username"] = parsed.username
    if parsed.password:
        proxy["password"] = parsed.password
    return proxy


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-index", type=int, default=0)
    ap.add_argument("--dwell", type=float, default=5.0, help="seconds to wait on the page before reading cookies")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "primed_cookies.json"))
    ap.add_argument("--url", default="https://www.roblox.com/")
    ap.add_argument("--headless", action="store_true", help="run headless (default: headed, real Chrome)")
    args = ap.parse_args()

    proxy = load_proxy(args.proxy_index)
    print(f"[*] Using proxy server: {proxy['server']} (session pinned by proxy provider)")

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=args.headless, proxy=proxy)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = context.new_page()
        print(f"[*] Navigating to {args.url} ...")
        page.goto(args.url, wait_until="load", timeout=30000)

        print(f"[*] Dwelling {args.dwell}s to let PerimeterX/Arkose sensor JS run ...")
        page.wait_for_timeout(int(args.dwell * 1000))

        cookies = context.cookies()
        matched = [c for c in cookies if any(d in c["domain"] for d in WATCH_DOMAINS)]

        primed = {}
        for c in matched:
            primed[c["name"]] = c["value"]

        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(primed, f)

        print(f"[+] Captured {len(primed)} cookies: {', '.join(sorted(primed.keys()))}")
        print(f"[+] Written to {args.out}")

        context.close()
        browser.close()


if __name__ == "__main__":
    main()
