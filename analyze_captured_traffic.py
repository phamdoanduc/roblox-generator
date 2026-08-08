import json

with open("captured_traffic.json", "r", encoding="utf-8") as f:
    traffic = json.load(f)

print(f"Total Captured Requests: {len(traffic)}")

for i, req in enumerate(traffic):
    url = req.get("url", "")
    method = req.get("method", "")
    if any(k in url for k in ["signup", "continue", "captcha", "arkoselabs"]):
        print(f"\n--- Request #{i}: {method} {url} ---")
        headers = req.get("headers", {})
        print("Headers:", json.dumps(headers, indent=2))
        data = req.get("postData", "")
        if data:
            print("PostData:", data[:400])
