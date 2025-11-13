#!/usr/bin/env python3
"""
Professional SAP Ariba Supplier Data Client
Purpose: Authenticate with SAP Ariba and fetch ALL supplier data via Open API
Author: Your Name
"""

import os
import sys
import json
import time
import base64
import logging
import csv
import requests
from dotenv import load_dotenv
from typing import Optional, Dict, Any, List

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

ARIBA_API_KEY = os.getenv("ARIBA_API_KEY")
ARIBA_CLIENT_ID = os.getenv("ARIBA_CLIENT_ID")
ARIBA_CLIENT_SECRET = os.getenv("ARIBA_CLIENT_SECRET")
ARIBA_BASE64_AUTH = os.getenv("ARIBA_BASE64_AUTH")
ARIBA_REALM = os.getenv("ARIBA_REALM")
ARIBA_ENV = os.getenv("ARIBA_ENV", "test").lower()

TOKEN_URL = f"https://api.au.cloud.ariba.com/v2/oauth/token"
ARIBA_BASE_URL = f"https://openapi.au.cloud.ariba.com/api"

# ------------------------------------------------------------
# Validation
# ------------------------------------------------------------
if not all([ARIBA_API_KEY, ARIBA_REALM]):
    logging.error("❌ Missing required environment variables. Check your .env file.")
    sys.exit(1)
if not (ARIBA_BASE64_AUTH or (ARIBA_CLIENT_ID and ARIBA_CLIENT_SECRET)):
    logging.error("❌ Missing authentication details. Provide either ARIBA_BASE64_AUTH or CLIENT_ID/SECRET.")
    sys.exit(1)

# ------------------------------------------------------------
# Helper: OAuth2 Authentication
# ------------------------------------------------------------
def get_access_token() -> Optional[str]:
    """Get OAuth2 access token using Base64 credentials."""
    b64_auth = ARIBA_BASE64_AUTH or base64.b64encode(f"{ARIBA_CLIENT_ID}:{ARIBA_CLIENT_SECRET}".encode()).decode()

    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {"grant_type": "client_credentials"}

    logging.info("Requesting OAuth2 token from SAP Ariba...")
    try:
        r = requests.post(TOKEN_URL, headers=headers, data=payload, timeout=30)
        r.raise_for_status()
        token_data = r.json()
        token = token_data.get("access_token")
        if not token:
            logging.error(f"❌ Token missing in response: {token_data}")
            return None
        logging.info("✅ Successfully obtained access token.")
        return token
    except Exception as e:
        logging.error(f"❌ Token request failed: {e}")
        return None

# ------------------------------------------------------------
# Step 1 – Submit vendor data request
# ------------------------------------------------------------
def submit_vendor_request(access_token: str, request_body: Dict[str, Any]) -> Optional[Any]:
    """Submit vendor data request and handle both async (requestId) and sync (list) modes."""
    url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/"
    params = {"realm": ARIBA_REALM}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "apiKey": ARIBA_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "DataServiceVersion": "2.0",
    }

    logging.info(f"Submitting vendorDataRequest for realm '{ARIBA_REALM}'...")
    r = requests.post(url, headers=headers, params=params, json=request_body, timeout=300)
    logging.debug(f"Response text: {r.text[:500]}...")
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        logging.error(f"❌ Response not valid JSON:\n{r.text}")
        return None

    # Handle both response types
    if isinstance(data, dict) and "requestId" in data:
        logging.info(f"✅ Asynchronous job started. Request ID: {data['requestId']}")
        return {"type": "job", "requestId": data["requestId"]}
    elif isinstance(data, list):
        logging.info(f"✅ Received vendor data immediately ({len(data)} records).")
        return {"type": "data", "vendors": data}
    else:
        logging.warning("⚠️ Unexpected response structure.")
        logging.warning(json.dumps(data, indent=2))
        return None

# ------------------------------------------------------------
# Step 2 – Async job polling
# ------------------------------------------------------------
def check_status(access_token: str, request_id: str) -> Optional[str]:
    """Poll job status for async requests."""
    url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/{request_id}/status"
    params = {"realm": ARIBA_REALM}
    headers = {"Authorization": f"Bearer {access_token}", "apiKey": ARIBA_API_KEY, "Accept": "application/json"}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    if r.status_code == 200:
        return r.json().get("status")
    logging.warning(f"⚠️ Could not get status ({r.status_code}): {r.text}")
    return None

# ------------------------------------------------------------
# Step 3 – Fetch paginated results
# ------------------------------------------------------------
def fetch_results(access_token: str, request_id: str, page_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch paginated vendor data results."""
    url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/{request_id}/results"
    params = {"realm": ARIBA_REALM}
    if page_token:
        params["nextToken"] = page_token
    headers = {"Authorization": f"Bearer {access_token}", "apiKey": ARIBA_API_KEY, "Accept": "application/json"}
    r = requests.get(url, headers=headers, params=params, timeout=120)
    r.raise_for_status()
    return r.json()

# ------------------------------------------------------------
# Step 4 – Utility: Save to JSON and CSV
# ------------------------------------------------------------
def save_to_files(vendors: List[Dict[str, Any]]):
    """Save vendor data to JSON and CSV (handles missing fields safely)."""
    json_file = "vendors.json"
    csv_file = "vendors.csv"

    # Save JSON
    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(vendors, jf, indent=2, ensure_ascii=False)
    logging.info(f"💾 Saved {len(vendors)} vendors to {json_file}")

    # Flatten to CSV
    fieldnames = set()
    for v in vendors:
        fieldnames.update(v.keys())
    fieldnames = sorted(fieldnames)

    with open(csv_file, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for v in vendors:
            row = {}
            for k in fieldnames:
                val = v.get(k, "")
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, ensure_ascii=False)
                row[k] = val
            writer.writerow(row)
    logging.info(f"💾 Saved CSV export to {csv_file}")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    token = get_access_token()
    if not token:
        sys.exit(1)

    request_body = {
        "outputFormat": "JSON",
        "asyncMode": True,
        "withQuestionnaire": True,
        "withGenericCustomFields": True,
        "withBankDetail": True,
        "withTaxDetail": True,
        "withCompanyCodeDetail": True,
        "withDisqualifications": True,
    }

    response = submit_vendor_request(token, request_body)
    if not response:
        sys.exit(1)

    # Case 1 – Immediate vendor data (synchronous mode)
    if response["type"] == "data":
        all_vendors = []
        page_data = response["vendors"]

        # Detect nextToken (sometimes appended as last element)
        next_token = None
        if isinstance(page_data, list) and len(page_data) > 0:
            last = page_data[-1]
            if isinstance(last, dict) and "nextToken" in last:
                next_token = last["nextToken"]
                page_data = page_data[:-1]  # remove the token marker

        all_vendors.extend(page_data)

        # Pagination loop for nextToken pages
        while next_token:
            logging.info(f"🔁 Fetching next page (nextToken={next_token})...")
            next_url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/"
            params = {"realm": ARIBA_REALM, "nextToken": next_token}
            headers = {
                "Authorization": f"Bearer {token}",
                "apiKey": ARIBA_API_KEY,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "DataServiceVersion": "2.0",
            }

            try:
                r = requests.post(next_url, headers=headers, json=request_body, params=params, timeout=180)
                r.raise_for_status()
                new_data = r.json()

                # Extract vendors and new nextToken
                if isinstance(new_data, list):
                    if len(new_data) > 0 and isinstance(new_data[-1], dict) and "nextToken" in new_data[-1]:
                        next_token = new_data[-1]["nextToken"]
                        new_vendors = new_data[:-1]
                    else:
                        new_vendors = new_data
                        next_token = None
                    all_vendors.extend(new_vendors)
                else:
                    next_token = new_data.get("nextToken")

            except Exception as e:
                logging.error(f"❌ Failed to fetch next page ({next_token}): {e}")
                break

        save_to_files(all_vendors)
        logging.info(f"✅ Retrieved total {len(all_vendors)} vendor records.")
        return

    # Case 2 – Asynchronous job (unchanged)
    request_id = response["requestId"]
    logging.info("⏳ Waiting for job completion...")
    for _ in range(30):
        status = check_status(token, request_id)
        logging.info(f"Job status: {status}")
        if status and status.lower() == "completed":
            break
        time.sleep(10)
    else:
        logging.error("❌ Timeout waiting for job completion.")
        sys.exit(1)

    # Fetch paginated results for async job
    all_vendors = []
    next_token = None
    while True:
        page_data = fetch_results(token, request_id, page_token=next_token)
        vendors = page_data.get("vendors", [])
        all_vendors.extend(vendors)
        next_token = page_data.get("nextToken")
        if not next_token:
            break
        logging.info(f"Fetching next page with token {next_token}...")

    save_to_files(all_vendors)
    logging.info(f"✅ Retrieved total {len(all_vendors)} vendor records.")

if __name__ == "__main__":
    main()
