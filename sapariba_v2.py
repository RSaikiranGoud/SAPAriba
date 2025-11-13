#!/usr/bin/env python3
"""
Professional SAP Ariba Supplier Data Client
Author: Your Name
Purpose: Authenticate with SAP Ariba and fetch all supplier data (bulk) via Open API
"""

import os
import sys
import json
import time
import base64
import logging
import requests
from dotenv import load_dotenv
from typing import Optional, Dict, Any

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
ARIBA_ENV = os.getenv("ARIBA_ENV", "test").lower()  # "prod" or "test"

# ------------------------------------------------------------
# Base URLs
# ------------------------------------------------------------
TOKEN_URLS = {
    "test": "https://api.au.cloud.ariba.com/v2/oauth/token",
    "prod": "https://api.au.cloud.ariba.com/v2/oauth/token",
}
BASE_URLS = {
    "test": "https://openapi.au.cloud.ariba.com/api",
    "prod": "https://openapi.au.cloud.ariba.com/api",
}

TOKEN_URL = TOKEN_URLS.get(ARIBA_ENV, TOKEN_URLS["test"])
ARIBA_BASE_URL = BASE_URLS.get(ARIBA_ENV, BASE_URLS["test"])

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
# Authentication
# ------------------------------------------------------------
def get_access_token() -> Optional[str]:
    """Obtain an OAuth2 access token using Base64 credentials."""
    if ARIBA_BASE64_AUTH:
        b64_auth = ARIBA_BASE64_AUTH
    else:
        creds = f"{ARIBA_CLIENT_ID}:{ARIBA_CLIENT_SECRET}"
        b64_auth = base64.b64encode(creds.encode()).decode()

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
            logging.error(f"❌ Token response missing 'access_token'. Raw: {token_data}")
            return None
        logging.info("✅ Successfully obtained access token.")
        return token
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Token request failed: {e}")
        return None

# ------------------------------------------------------------
# Step 1: Submit Vendor Data Request
# ------------------------------------------------------------
def submit_vendor_request(access_token: str, request_body: Dict[str, Any]) -> Optional[str]:
    """Submit a vendor data request job and return the requestId."""
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
    try:
        r = requests.post(url, headers=headers, params=params, json=request_body, timeout=120)
        logging.info(f"Raw response: {r.text}")
        r.raise_for_status()
        data = r.json()
        request_id = data.get("requestId")
        if request_id:
            logging.info(f"✅ Request submitted. Request ID: {request_id}")
            return request_id
        else:
            logging.error(f"❌ No 'requestId' found. Response: {data}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Vendor data request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"❌ Failed to parse response JSON: {e}")
        logging.error(f"Response text: {r.text}")
        return None

# ------------------------------------------------------------
# Step 2: Poll for Job Completion
# ------------------------------------------------------------
def check_request_status(access_token: str, request_id: str) -> Optional[str]:
    """Check the status of a vendor data request."""
    url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/{request_id}/status"
    params = {"realm": ARIBA_REALM}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "apiKey": ARIBA_API_KEY,
        "Accept": "application/json",
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code == 200:
            return r.json().get("status")
        else:
            logging.warning(f"⚠️ Unable to get status ({r.status_code}): {r.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Status check failed: {e}")
        return None

# ------------------------------------------------------------
# Step 3: Fetch Results Pages
# ------------------------------------------------------------
def fetch_results(access_token: str, request_id: str, page_number: int = 1) -> Optional[Dict[str, Any]]:
    """Retrieve vendor data results for a completed job."""
    url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendorDataRequests/{request_id}/results"
    params = {"realm": ARIBA_REALM, "pageNumber": page_number}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "apiKey": ARIBA_API_KEY,
        "Accept": "application/json",
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=120)
        r.raise_for_status()
        data = r.json()
        logging.info(f"✅ Retrieved results page {page_number}.")
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Failed to fetch results page {page_number}: {e}")
        return None
    except json.JSONDecodeError:
        logging.error(f"❌ Invalid JSON response on page {page_number}. Response:\n{r.text}")
        return None

# ------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------
def main():
    token = get_access_token()
    if not token:
        sys.exit(1)

    # Broadest request possible
    request_body = {
        "outputFormat": "JSON",
        "withQuestionnaire": True,
        "withGenericCustomFields": True,
        "withBankDetail": True,
        "withTaxDetail": True,
        "withCompanyCodeDetail": True,
        "withDisqualifications": True
    }

    request_id = submit_vendor_request(token, request_body)
    if not request_id:
        logging.critical("Exiting: Failed to start vendor data job.")
        sys.exit(1)

    # Poll until completed
    for _ in range(30):  # 5 min max @10s interval
        status = check_request_status(token, request_id)
        logging.info(f"Job status: {status}")
        if status and status.lower() == "completed":
            logging.info("✅ Job completed.")
            break
        time.sleep(10)
    else:
        logging.error("❌ Timeout waiting for job completion.")
        sys.exit(1)

    # Fetch results (loop pages until empty)
    page = 1
    all_results = []
    while True:
        page_data = fetch_results(token, request_id, page_number=page)
        if not page_data or not page_data.get("vendors"):
            break
        all_results.extend(page_data["vendors"])
        page += 1

    if all_results:
        logging.info(f"✅ Retrieved {len(all_results)} vendor records total.")
        print(json.dumps(all_results, indent=2))
    else:
        logging.warning("⚠️ No vendor records found.")

if __name__ == "__main__":
    main()
