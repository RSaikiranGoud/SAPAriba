#!/usr/bin/env python3
"""
Professional SAP Ariba Supplier Data Client
Author: Your Name
Purpose: Authenticate with SAP Ariba and fetch supplier data via Open API
"""

import os
import sys
import json
import base64
import logging
import requests
from dotenv import load_dotenv
from typing import Optional, Dict, Any

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
load_dotenv()  # Load variables from .env file

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Environment variables
ARIBA_API_KEY = os.getenv("ARIBA_API_KEY")
ARIBA_CLIENT_ID = os.getenv("ARIBA_CLIENT_ID")
ARIBA_CLIENT_SECRET = os.getenv("ARIBA_CLIENT_SECRET")
ARIBA_BASE64_AUTH = os.getenv("ARIBA_BASE64_AUTH")  # Optional pre-encoded value
ARIBA_REALM = os.getenv("ARIBA_REALM")
ARIBA_ENV = os.getenv("ARIBA_ENV", "test").lower()  # "prod" or "test"

# ------------------------------------------------------------
# Base URLs (adjust for your region)
# ------------------------------------------------------------
# Authentication endpoints (usually region-independent)
TOKEN_URLS = {
    "test": "https://api.au.cloud.ariba.com/v2/oauth/token"
}

# API base URLs
BASE_URLS = {
    "test": "https://openapi.au.cloud.ariba.com/api"
}

TOKEN_URL = TOKEN_URLS.get(ARIBA_ENV, TOKEN_URLS["test"])
ARIBA_BASE_URL = BASE_URLS.get(ARIBA_ENV, BASE_URLS["test"])

# ------------------------------------------------------------
# Validate configuration
# ------------------------------------------------------------
if not all([ARIBA_API_KEY, ARIBA_REALM]):
    logging.error("❌ Missing required environment variables. Check your .env file.")
    sys.exit(1)

if not (ARIBA_BASE64_AUTH or (ARIBA_CLIENT_ID and ARIBA_CLIENT_SECRET)):
    logging.error("❌ Missing authentication details. Provide either ARIBA_BASE64_AUTH or CLIENT_ID/SECRET.")
    sys.exit(1)

# ------------------------------------------------------------
# Authentication - Get OAuth Token (Base64)
# ------------------------------------------------------------
def get_access_token() -> Optional[str]:
    """
    Obtain an OAuth2 access token using Base64-encoded client credentials.
    Returns the access token string, or None on failure.
    """
    # Use pre-encoded value if available, else encode client_id:client_secret
    if ARIBA_BASE64_AUTH:
        b64_auth = ARIBA_BASE64_AUTH
    else:
        auth_str = f"{ARIBA_CLIENT_ID}:{ARIBA_CLIENT_SECRET}"
        b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = {"grant_type": "client_credentials"}

    logging.info("Requesting OAuth2 token from SAP Ariba...")

    try:
        response = requests.post(TOKEN_URL, headers=headers, data=payload, timeout=30)
        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get("access_token")
        if not access_token:
            logging.error(f"❌ Token response missing 'access_token'. Raw: {token_data}")
            return None

        logging.info("✅ Successfully obtained access token.")
        return access_token

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Token request failed: {e}")
        return None


# ------------------------------------------------------------
# Fetch Supplier Data
# ------------------------------------------------------------
def fetch_suppliers(access_token: str, limit: int = 10) -> Optional[Dict[str, Any]]:
    """
    Fetch supplier data from Ariba Supplier Data API.
    :param access_token: OAuth token
    :param limit: Number of suppliers to fetch
    :return: JSON data (dict) or None on failure
    """
    supplier_url = f"{ARIBA_BASE_URL}/supplierdatapagination/v4/prod/vendors/"
    params = {"realm": ARIBA_REALM, "limit": limit}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "apiKey": ARIBA_API_KEY,
        "Accept": "application/json"
    }

    logging.info(f"Fetching up to {limit} suppliers for realm '{ARIBA_REALM}'...")

    try:
        response = requests.get(supplier_url, headers=headers, params=params, timeout=60)
        if response.status_code == 401:
            logging.error("❌ Unauthorized (401) — Token expired or invalid.")
            return None

        response.raise_for_status()
        data = response.json()
        supplier_list = data.get("suppliers", [])
        logging.info(f"✅ Retrieved {len(supplier_list)} supplier records.")
        return data

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Supplier data request failed: {e}")
        return None


# ------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------
def main():
    token = get_access_token()
    if not token:
        logging.critical("Exiting: Cannot proceed without access token.")
        sys.exit(1)

    suppliers = fetch_suppliers(token, limit=20)
    if suppliers:
        logging.info("Supplier data:")
        print(json.dumps(suppliers, indent=2))
    else:
        logging.error("❌ No supplier data retrieved.")


if __name__ == "__main__":
    main()
