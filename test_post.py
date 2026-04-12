import urllib.request
import json
import time

url = 'http://127.0.0.1:8000/api/siem/trusted-ips'
data = json.dumps({"ip_prefix": "8.8.8.8", "description": "test"}).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

try:
    print("Sending POST request...")
    start = time.time()
    res = urllib.request.urlopen(req, timeout=3)
    print("Response:", res.read().decode())
    print("Time taken:", time.time() - start)
except Exception as e:
    print("Error:", e)
