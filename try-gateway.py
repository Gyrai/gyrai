"""Send a few prompts through the gateway, the way a customer app would.
Standard library only, so it runs on any Python (and inside the containers).
    python try-gateway.py              # targets http://localhost:8080/v1
    AICP_TARGET=http://host:8080/v1 python try-gateway.py
"""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("AICP_TARGET", "http://localhost:8080/v1")
KEY = os.environ.get("AICP_GW_KEY", "gw-dev-key-alice")

tests = [
    ("clean prompt", "Summarize the standup notes"),
    ("CUI marked", "Rewrite: CUI//SP-CTI bracket shall withstand 400 lbf"),
    ("leaked API key", "Debug this: api_key = sk-proj-AbCdEfGhIjKlMnOpQrStUvWx1234567890"),
    ("SSN", "Check SSN 123-45-6789 for formatting"),
]

for label, prompt in tests:
    body = json.dumps({"model": "mock-1", "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(f"{BASE}/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            content = json.load(r)["choices"][0]["message"]["content"]
            print(f"{label:15} -> {content[:70]}")
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)["detail"]
            print(f"{label:15} -> BLOCKED {d['policy_id']}: {d['reason']}")
        except Exception:
            print(f"{label:15} -> HTTP {e.code}")
    except urllib.error.URLError as e:
        print(f"{label:15} -> gateway unreachable at {BASE}: {e.reason}")
        break

print("\nNow open http://localhost:8000/events and look for source=gateway.")
