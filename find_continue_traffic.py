import json

with open("captured_traffic.json", "r", encoding="utf-8") as f:
    traffic = json.load(f)

for i, req in enumerate(traffic):
    url = req.get("url", "")
    if "continue" in url:
        print(f"--- Captured Continue Request #{i} ---")
        print("URL:", url)
        print("Method:", req.get("method"))
        print("Headers:", json.dumps(req.get("headers"), indent=2))
        print("PostData:", req.get("postData"))
