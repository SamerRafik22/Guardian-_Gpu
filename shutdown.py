import urllib.request
import json
import os
import sys

# Get the path to guardian_config.json
here = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(here, "guardian_config.json")

# Extract the API key
api_key = ""
if os.path.exists(config_path):
    with open(config_path, "r") as f:
        config = json.load(f)
        api_key = config.get("api_key", "")

if not api_key:
    print("Warning: No API key found in config. Shutdown may be rejected.")

try:
    # Send the shutdown POST request
    req = urllib.request.Request(
        "http://localhost:8080/api/shutdown",
        data=b"",  # Empty POST body
        headers={"Authorization": f"Bearer {api_key}"}
    )
    urllib.request.urlopen(req, timeout=3.0)
    print("Shutdown signal sent successfully.")
except urllib.error.HTTPError as e:
    print(f"Failed to shut down server: HTTP {e.code} - {e.reason}")
    sys.exit(1)
except Exception as e:
    print(f"Error connecting to server: {e}")
    sys.exit(1)
