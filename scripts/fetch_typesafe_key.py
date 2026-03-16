#!/usr/bin/env python3
"""Fetch the TypeSafe API key from gem's AWS Secrets Manager and push to Render.

Usage:
    python3 scripts/fetch_typesafe_key.py

You'll be prompted for MFA if needed. Requires the 'admin' AWS profile
configured (same as gem dev setup).
"""

import json
import os
import subprocess
import sys

import botocore.session
import botocore.utils
import boto3


def get_gem_secrets_client():
    """Get a Secrets Manager client using the gem admin profile with MFA cache."""
    working_dir = os.path.join(os.path.expanduser("~"), ".aws/cli/cache")
    os.makedirs(working_dir, exist_ok=True)

    session = botocore.session.get_session()
    session.set_config_variable("profile", "admin")

    # Use the AWS CLI's MFA cache so you don't have to re-auth every time
    provider = session.get_component("credential_provider").get_provider("assume-role")
    provider.cache = botocore.utils.JSONFileCache(working_dir)

    client = boto3.Session(botocore_session=session).client(
        service_name="secretsmanager",
        region_name="us-east-1",
        endpoint_url="https://secretsmanager.us-east-1.amazonaws.com",
    )
    return client


def fetch_typesafe_key():
    """Fetch the TypeSafe API key from gem's prod secrets."""
    print("Connecting to gem AWS Secrets Manager (admin profile)...")
    client = get_gem_secrets_client()

    print("Fetching prod/externalApiKeys...")
    response = client.get_secret_value(SecretId="prod/externalApiKeys")
    secrets = json.loads(response["SecretString"])

    key = secrets.get("TYPESAFE_API_KEY")
    if not key:
        print("ERROR: TYPESAFE_API_KEY not found in secrets")
        sys.exit(1)

    print(f"Found TypeSafe key: {key[:8]}...")
    return key


def push_to_render(key: str):
    """Push the key to Render as an env var."""
    print("\nPushing to Render...")

    # Use Render CLI if available, otherwise print instructions
    try:
        # Try using render CLI
        result = subprocess.run(
            ["render", "env", "set", "TYPESAFE_API_KEY", key,
             "--service", "penelope-api"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("Set TYPESAFE_API_KEY on Render")
            return
    except FileNotFoundError:
        pass

    # Fallback: print for manual entry
    print(f"\nRender CLI not available. Set this manually in Render dashboard:")
    print(f"  Service: penelope-api")
    print(f"  Key:     TYPESAFE_API_KEY")
    print(f"  Value:   {key}")
    print(f"\nOr run:")
    print(f"  render env set TYPESAFE_API_KEY '{key}' --service penelope-api")


if __name__ == "__main__":
    key = fetch_typesafe_key()
    push_to_render(key)
    print("\nDone!")
