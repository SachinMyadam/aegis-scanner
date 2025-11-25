import requests
import base64

# 1. Define the target (Google)
url = "http://localhost:8000/api/v1/scan/url"
payload = {"url": "https://www.google.com", "client_ip": "127.0.0.1"}

print("Scanning Google.com...")
response = requests.post(url, json=payload)
data = response.json()

# 2. Extract the base64 string
# The string comes as "data:image/jpeg;base64,....." so we split at the comma
image_data = data['sandbox_report']['screenshot_path'].split(",")[1]

# 3. Decode and save
with open("scan_evidence.jpg", "wb") as f:
    f.write(base64.b64decode(image_data))

print("Success! Saved screenshot to 'scan_evidence.jpg'")
