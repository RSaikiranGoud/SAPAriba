#!/usr/bin/env python3
"""
Professional SAP Ariba Supplier Data Client
Purpose: Authenticate with SAP Ariba, fetch all supplier data, and download related documents.
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
# Helper: OAuth2 Authentication
# ------------------------------------------------------------
def get_access_token() -> Optional[str]:
    """Get OAuth2 access token using Base64 credentials."""
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
# Step 1 – Submit vendor data request
# ------------------------------------------------------------
def submit_vendor_request(access_token: str, request_body: Dict[str, Any]) -> Optional[Any]:
    """Submit vendor data request and handle async/sync responses."""
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
    try:
        data = r.json()
    except Exception:
        logging.error(f"❌ Non-JSON response: {r.text}")
        return None

    if isinstance(data, dict) and "requestId" in data:
        logging.info(f"✅ Asynchronous job started. Request ID: {data['requestId']}")
        return {"type": "job", "requestId": data["requestId"]}
    elif isinstance(data, list):
        logging.info(f"✅ Received vendor data immediately ({len(data)} records).")
        return {"type": "data", "vendors": data}
    else:
        logging.warning(f"⚠️ Unexpected response: {json.dumps(data, indent=2)}")
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
# Step 4 – Download supplier-related documents
# ------------------------------------------------------------
def download_document(access_token: str, document_id: str, save_dir: str = "downloads"):
    """Download all attachments for a given Ariba document."""
    os.makedirs(save_dir, exist_ok=True)
    doc_base = ARIBA_BASE_URL.replace("supplierdatapagination", "document")
    url = f"{doc_base}/v1/prod/documents/{document_id}/attachments"
    params = {"realm": ARIBA_REALM}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "apiKey": ARIBA_API_KEY,
        "Accept": "application/json",
    }

    logging.info(f"📄 Checking attachments for document {document_id}...")
    r = requests.get(url, headers=headers, params=params, timeout=60)
    if r.status_code != 200:
        logging.warning(f"⚠️ No attachments for {document_id} ({r.status_code})")
        return

    data = r.json()
    for att in data.get("attachments", []):
        att_id = att["attachmentId"]
        file_name = att.get("fileName", f"{att_id}.bin")
        file_path = os.path.join(save_dir, file_name)
        file_url = f"{doc_base}/v1/prod/attachments/{att_id}/content"

        logging.info(f"⬇️ Downloading {file_name} ...")
        with requests.get(file_url, headers=headers, params=params, stream=True) as resp:
            resp.raise_for_status()
            with open(file_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
        logging.info(f"✅ Saved: {file_path}")

# ------------------------------------------------------------
# Step 5 – Utility: Save to JSON and CSV
# ------------------------------------------------------------
def save_to_files(vendors: List[Dict[str, Any]]):
    """Save vendor data to JSON and CSV safely."""
    json_file = "vendors.json"
    csv_file = "vendors.csv"

    # Save full JSON
    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(vendors, jf, indent=2, ensure_ascii=False)
    logging.info(f"💾 Saved {len(vendors)} vendors to {json_file}")

    # Flatten for CSV
    fieldnames = set()
    for v in vendors:
        fieldnames.update(v.keys())
    fieldnames = sorted(fieldnames)

    with open(csv_file, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for v in vendors:
            row = {
                k: (
                    json.dumps(v.get(k, ""), ensure_ascii=False)
                    if isinstance(v.get(k, ""), (list, dict))
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
        "smVendorIds": [
        "S10717420",  # steam1automobile
        "S10739552",  # Kapaasa Apparels LLP
        "S10739550",   # Alps Traders
        "S10822821",   # fanout
        "S10834561",   # srinu
        "S10836858"    # arun
    ]
}

    response = submit_vendor_request(token, request_body)
    if not response:
        sys.exit(1)

    # Case 1 – Synchronous
    if response["type"] == "data":
        vendors = response["vendors"]
        save_to_files(vendors)
        for v in vendors:
            for q in v.get("questionnaires", []):
                doc_id = q.get("questionnaireId")
                if doc_id:
                    download_document(token, doc_id)
        return

    # Case 2 – Asynchronous
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

    # Paginate
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
    for v in all_vendors:
        for q in v.get("questionnaires", []):
            doc_id = q.get("questionnaireId")
            if doc_id:
                download_document(token, doc_id)
    logging.info(f"✅ Retrieved total {len(all_vendors)} vendor records.")

if __name__ == "__main__":
    main()
