#!/usr/bin/env python3
"""
Professional SAP Ariba Supplier Data Client (Demo Mode)
Purpose: Authenticate with SAP Ariba and fetch supplier data (no pagination).
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

TOKEN_URL = "https://api.au.cloud.ariba.com/v2/oauth/token"
ARIBA_BASE_URL = "https://openapi.au.cloud.ariba.com/api"

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
# OAuth2 Authentication
# ------------------------------------------------------------
def get_access_token() -> Optional[str]:
    """Get OAuth2 access token."""
    b64_auth = ARIBA_BASE64_AUTH or base64.b64encode(f"{ARIBA_CLIENT_ID}:{ARIBA_CLIENT_SECRET}".encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}", "Content-Type": "application/x-www-form-urlencoded"}
    payload = {"grant_type": "client_credentials"}

    logging.info("Requesting OAuth2 token from SAP Ariba...")
    try:
        r = requests.post(TOKEN_URL, headers=headers, data=payload, timeout=30)
        r.raise_for_status()
        token = r.json().get("access_token")
        if not token:
            logging.error(f"❌ Token missing in response: {r.text}")
            return None
        logging.info("✅ Successfully obtained access token.")
        return token
    except Exception as e:
        logging.error(f"❌ Token request failed: {e}")
        return None

# ------------------------------------------------------------
# Submit vendor data request
# ------------------------------------------------------------
def submit_vendor_request(access_token: str, request_body: Dict[str, Any]) -> Optional[Any]:
    """Submit vendor data request."""
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
    r = requests.post(url, headers=headers, params=params, json=request_body, timeout=120)
    try:
        data = r.json()
    except Exception:
        logging.error(f"❌ Non-JSON response: {r.text}")
        return None

    if isinstance(data, list):
        logging.info(f"✅ Received vendor data immediately ({len(data)} records).")
        return data
    elif isinstance(data, dict) and "requestId" in data:
        logging.warning("⚠️ Asynchronous response received, skipping async mode for demo.")
        return []
    else:
        logging.warning("⚠️ Unexpected response format.")
        logging.warning(json.dumps(data, indent=2))
        return []

# ------------------------------------------------------------
# Save results
# ------------------------------------------------------------
def save_to_files(vendors: List[Dict[str, Any]]):
    """Save vendor data to JSON and CSV safely."""
    if not vendors:
        logging.warning("⚠️ No vendor data to save.")
        return

    json_file = "vendors.json"
    csv_file = "vendors.csv"

    # Save JSON
    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(vendors, jf, indent=2, ensure_ascii=False)
    logging.info(f"💾 Saved {len(vendors)} vendors to {json_file}")

    # Save CSV
    fieldnames = sorted({k for v in vendors for k in v.keys()})
    with open(csv_file, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for v in vendors:
            row = {
                k: (
                    json.dumps(v.get(k, ""), ensure_ascii=False)
                    if isinstance(v.get(k, ""), (dict, list))
                    else v.get(k, "")
                )
                for k in fieldnames
            }
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
        "withQuestionnaire": True,
        "withGenericCustomFields": True,
        "withBankDetail": True,
        "withTaxDetail": True,
        "withCompanyCodeDetail": True,
        "withDisqualifications": True,
    }

    vendors = submit_vendor_request(token, request_body)
    save_to_files(vendors)
    logging.info("✅ Demo completed successfully.")

if __name__ == "__main__":
    main()
