#!/usr/bin/env python3
"""Test OAuth session persistence"""

import requests
import re

# Base URL
BASE_URL = "http://localhost:5000"

# Create a session to maintain cookies
session = requests.Session()

print("=" * 60)
print("OAuth Session Test")
print("=" * 60)

# Step 1: Initiate OAuth login
print("\n1. Initiating OAuth login...")
response = session.get(f"{BASE_URL}/oauth/login/google", allow_redirects=False)
print(f"   Status: {response.status_code}")
print(f"   Cookies: {dict(session.cookies)}")

if response.status_code == 302:
    redirect_url = response.headers.get('Location', '')
    print(f"   Redirect URL: {redirect_url[:100]}...")
    
    # Extract state from redirect URL
    state_match = re.search(r'state=([^&]+)', redirect_url)
    if state_match:
        state = state_match.group(1)
        print(f"   State parameter: {state[:20]}...")
        
        # Step 2: Simulate callback (this would normally come from Google)
        print("\n2. Testing session persistence...")
        print(f"   Session cookies before callback: {dict(session.cookies)}")
        
        # Try to hit callback with state (should fail but we can see session data)
        test_code = "test_code_12345"
        callback_url = f"{BASE_URL}/oauth/callback/google?code={test_code}&state={state}"
        callback_response = session.get(callback_url, allow_redirects=False)
        print(f"   Callback status: {callback_response.status_code}")
        print(f"   Cookies after callback: {dict(session.cookies)}")
        
else:
    print(f"   ERROR: Expected redirect (302), got {response.status_code}")
    print(f"   Response: {response.text[:200]}")

print("\n" + "=" * 60)
print("Test complete. Check logs for debug output.")
print("=" * 60)
