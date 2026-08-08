import asyncio
from px_harvester_service import harvest_px_cookies

proxy = "http://663e0bafbfdc38180cc0:44c3cd56014a9abf@gw.dataimpulse.com:10000"
cookies = asyncio.run(harvest_px_cookies(proxy))
print("Direct Test Cookies Result:", cookies)
