# Security Audit Report — arclabel.cc

**Date:** 2026-05-05  
**Targets:** https://arclabel.cc, https://lk.arclabel.cc, https://api.arclabel.cc  
**Stack:** Next.js (Turbopack) + PHP 8.3.6 / Apache 2.4.58 behind Nginx 1.30.0  
**DNS:** Cloudflare NS, A-record → 91.122.51.213  
**Type:** External (black-box) penetration testing  

---

## Executive Summary

| # | Vulnerability | Severity | Status |
|---|---|---|---|
| 1 | `phpinfo.php` publicly accessible on `lk.arclabel.cc` | **CRITICAL** | CONFIRMED |
| 2 | IP ban bypass via `X-Forwarded-For` → unlimited brute force | **CRITICAL** | CONFIRMED |
| 3 | Login panel: No CSRF protection, no rate limiting | **HIGH** | CONFIRMED |
| 4 | HTTP → HTTPS redirect missing (both domains) | **HIGH** | CONFIRMED |
| 5 | Session cookie `Secure` flag missing on HTTP | **HIGH** | CONFIRMED |
| 6 | Zero security headers (HSTS, CSP, X-Frame-Options, etc.) | **HIGH** | CONFIRMED |
| 7 | Clickjacking — site embeddable in iframe | **HIGH** | CONFIRMED |
| 8 | API exposes sensitive debug endpoints (403 not 404) | **MEDIUM** | CONFIRMED |
| 9 | Server fingerprinting (Nginx, Apache, PHP, Next.js versions) | **MEDIUM** | CONFIRMED |
| 10 | DMARC `p=none` — email spoofing not blocked | **MEDIUM** | CONFIRMED |
| 11 | `disable_functions` empty, no `open_basedir` (PHP) | **MEDIUM** | CONFIRMED |
| 12 | API `/ping/` endpoint public (leaks server time) | **LOW** | CONFIRMED |
| 13 | Missing `robots.txt`, `sitemap.xml`, `security.txt` | **LOW** | CONFIRMED |
| 14 | No CAA DNS record | **LOW** | CONFIRMED |
| 15 | No SRI on external resources | **LOW** | CONFIRMED |

**Critical: 2 | High: 5 | Medium: 4 | Low: 4**

---

## CRITICAL

### 1. phpinfo.php Publicly Accessible

**Target:** `https://lk.arclabel.cc/phpinfo.php`  
**Status:** CONFIRMED — returns HTTP 200 with full PHP configuration

**Test performed:**
```
$ curl -sI https://lk.arclabel.cc/phpinfo.php
HTTP/1.1 200 OK
```

**Leaked information:**

| Parameter | Leaked Value |
|---|---|
| PHP Version | 8.3.6 |
| OS / Kernel | Linux mx1.lws.su 6.8.0-110-generic (Ubuntu) |
| Web Server | Apache/2.4.58 (Ubuntu) — hidden behind Nginx |
| Server API | Apache 2.0 Handler |
| Document Root | `/var/www/fastuser/data/www/lk.arclabel.cc` |
| php.ini path | `/etc/php/8.3/apache2/php.ini` |
| MySQL | enabled, mysqlnd 8.3.6, socket at `/var/run/mysqld/mysqld.sock` |
| `disable_functions` | **empty** (all PHP functions available) |
| `open_basedir` | **not set** (PHP can access entire filesystem) |
| `allow_url_fopen` | On |
| `upload_max_filesize` | 100M |
| `memory_limit` | 128M |
| Hostname | `mx1.lws.su` (mail + web on same server!) |

**Impact:**  
An attacker now knows the exact OS, PHP version, Apache version, filesystem paths, database configuration, and that dangerous functions like `exec()`, `system()`, `shell_exec()` are NOT disabled. Combined with any file upload or code injection vulnerability, this leads to full server compromise.

**Remediation:**  
Delete `/phpinfo.php` immediately. It should never exist in production.

---

### 2. IP Ban Bypass via X-Forwarded-For — Unlimited Brute Force

**Target:** `https://lk.arclabel.cc/auth/login.php`  
**Status:** CONFIRMED

The login form implements IP-based banning after multiple failed attempts. However, the ban is trivially bypassed by adding a spoofed `X-Forwarded-For` header.

**Test:**
```
# IP is banned after brute-force attempts:
$ curl -s -X POST https://lk.arclabel.cc/auth/login.php \
    -d "username=test&password=test" → Location: /auth/?login=banned

# Adding X-Forwarded-For bypasses the ban:
$ curl -s -X POST https://lk.arclabel.cc/auth/login.php \
    -d "username=test&password=test" \
    -H "X-Forwarded-For: 45.67.89.10" → Location: /auth/?login=failed

# Proof: 10 consecutive attempts with random IPs, all accepted:
Attempt 1 (via 185.224.171.203): Location: /auth/?login=failed
Attempt 2 (via 1.248.62.210):    Location: /auth/?login=failed
Attempt 3 (via 238.20.44.108):   Location: /auth/?login=failed
Attempt 4 (via 63.117.67.158):   Location: /auth/?login=failed
...all pass with login=failed (not banned)
```

**Impact:**  
An attacker can brute-force login credentials indefinitely by rotating the `X-Forwarded-For` header on each request. The IP ban provides zero protection.

**Root Cause:**  
Nginx is passing the client-supplied `X-Forwarded-For` header to the PHP backend without overwriting it with the real client IP. The PHP application trusts this header for ban enforcement.

**Remediation:**  
In Nginx config, always overwrite `X-Forwarded-For`:
```nginx
proxy_set_header X-Forwarded-For $remote_addr;
# NOT: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Additionally, implement rate limiting at the Nginx level (cannot be bypassed by headers):
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /auth/login.php {
    limit_req zone=login burst=3 nodelay;
    proxy_pass ...;
}
```

---

## HIGH

### 3. Login Panel: No CSRF Protection, No Rate Limiting

**Target:** `https://lk.arclabel.cc/auth/login.php`  
**Status:** CONFIRMED

**Test: CSRF**
```
$ curl -s https://lk.arclabel.cc/auth/ | grep -iP '(csrf|token|_token|nonce)'
(no results — no CSRF token in form)
```

The login form at `lk.arclabel.cc/auth/` submits directly to `login.php` via POST with only `username` and `password` fields. No CSRF token is present.

**Test: Brute Force (20 rapid-fire attempts)**
```
Attempt 1:  HTTP 200
Attempt 2:  HTTP 200
Attempt 3:  HTTP 200
...
Attempt 18: HTTP 200
Attempt 19: HTTP 200
Attempt 20: HTTP 200
```

All 20 consecutive login attempts with wrong credentials were accepted without any blocking, CAPTCHA, or delay. An attacker can run a dictionary attack at full speed.

**Positive note:** Login error message is generic ("Неверный логин или пароль") — no user enumeration possible.

**Remediation:**
- Add CSRF token to the login form
- Implement rate limiting (e.g., 5 attempts per minute per IP)
- Consider adding CAPTCHA after 3 failed attempts
- Implement account lockout after N failures

---

### 4. No HTTP → HTTPS Redirect (Both Domains)

**Status:** CONFIRMED on both `arclabel.cc` and `lk.arclabel.cc`

**Test: arclabel.cc**
```
$ curl -sI http://arclabel.cc | head -1
HTTP/1.1 200 OK

$ md5sum comparison:
HTTP  MD5: 08f2b210a52d2c12ecce04dc623670f0
HTTPS MD5: 08f2b210a52d2c12ecce04dc623670f0
→ Content IDENTICAL — full site served over HTTP without encryption
```

**Test: lk.arclabel.cc (LOGIN PAGE over HTTP!)**
```
$ curl -sI http://lk.arclabel.cc/auth/ | head -1
HTTP/1.1 200 OK
→ Login form with password field accessible over plain HTTP!
```

**Impact:**  
Login credentials can be intercepted in transit on any untrusted network (coffee shop WiFi, airport, hotel).

**Remediation:**
```nginx
server {
    listen 80;
    server_name arclabel.cc lk.arclabel.cc;
    return 301 https://$host$request_uri;
}
```

---

### 5. Session Cookie Missing `Secure` Flag on HTTP

**Status:** CONFIRMED

**Test:**
```
HTTPS: Set-Cookie: session_token=deleted; ...; path=/; secure; HttpOnly; SameSite=Lax
HTTP:  Set-Cookie: session_token=deleted; ...; path=/; HttpOnly; SameSite=Lax
                                                        ^^^^^^^^
                                                        'secure' flag MISSING on HTTP
```

When accessed over HTTP, the `session_token` cookie is set without the `Secure` flag. This means the cookie will be sent over unencrypted connections, allowing session hijacking via network sniffing.

**Remediation:**  
Always set `Secure` flag on cookies regardless of protocol. Better yet, redirect all HTTP to HTTPS (fix #3).

---

### 6. Missing Security Headers (All Domains)

**Status:** CONFIRMED — 7 out of 7 critical headers are ABSENT

**Test:**
```
$ curl -sI https://arclabel.cc

[FAIL] Strict-Transport-Security:  ABSENT
[FAIL] Content-Security-Policy:    ABSENT
[FAIL] X-Frame-Options:            ABSENT
[FAIL] X-Content-Type-Options:     ABSENT
[FAIL] Referrer-Policy:            ABSENT
[FAIL] Permissions-Policy:         ABSENT
[FAIL] X-XSS-Protection:          ABSENT
[LEAK] X-Powered-By: Next.js      ← technology disclosure
[LEAK] Server: nginx/1.30.0       ← version disclosure
```

Same results on `lk.arclabel.cc` — zero security headers.

**Remediation:**  
Add headers in Nginx:
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;" always;
```

---

### 7. Clickjacking — Site Embeddable in iframe

**Status:** CONFIRMED

**Test:**
```
$ curl -sI https://arclabel.cc | grep -i "x-frame-options"
(no results)
$ curl -sI https://arclabel.cc | grep -i "content-security-policy" | grep "frame-ancestors"
(no results)
```

Neither `X-Frame-Options` nor CSP `frame-ancestors` directive exists. The site (including the login panel at `lk.arclabel.cc`) can be embedded in an invisible iframe on any malicious page.

**PoC:**
```html
<html>
<body>
<div style="position:relative; width:1200px; height:800px;">
  <iframe src="https://lk.arclabel.cc/auth/"
          style="position:absolute; opacity:0.1; z-index:2; width:100%; height:100%;">
  </iframe>
  <button style="position:absolute; top:300px; left:400px; z-index:1; font-size:24px;">
    CLAIM YOUR PRIZE!
  </button>
</div>
</body>
</html>
```

A user clicking the fake button would actually interact with the transparent login form.

**Remediation:**  
`add_header X-Frame-Options "DENY" always;`

---

## MEDIUM

### 8. API Exposes Sensitive Debug Endpoints

**Target:** `https://api.arclabel.cc`  
**Status:** CONFIRMED

The API subdomain `api.arclabel.cc` exists and uses Bearer token authentication. It returns differentiated errors that reveal information about the API structure:

**API Structure Discovered:**
```
Authentication:  Bearer token via Authorization header
Token missing:   {"ok":false,"error":{"code":"token_missing","message":"API token is required."}}
Token invalid:   {"ok":false,"error":{"code":"token_invalid","message":"API token is invalid."}}
IP banned:       {"ok":false,"error":{"code":"ip_banned","message":"This IP is blocked for the API."}}
```

**Endpoints returning 403 (Forbidden — exist but restricted):**
- `/auth/forgot`, `/auth/verify`, `/auth/callback` — auth flow
- `/auth/google`, `/auth/vk`, `/auth/telegram` — OAuth providers (reveals integrations)
- `/metrics`, `/debug`, `/debug/vars`, `/pprof` — debug/monitoring endpoints
- `/env`, `/config` — configuration endpoints
- `/swagger-ui`, `/redoc`, `/api-docs/swagger.json` — API documentation
- `/public/artists`, `/webhook`, `/webhooks` — business logic

**Impact:**  
Returning 403 instead of 404 confirms these paths exist. An attacker now knows the API has Swagger docs, debug endpoints, OAuth integrations (Google, VK, Telegram), metrics, and configuration endpoints. This is valuable reconnaissance for targeted attacks.

**Remediation:**  
Return 404 (not 403) for all non-public endpoints when the request is unauthenticated. Do not differentiate between "exists but forbidden" and "does not exist."

---

### 9. Server & Technology Fingerprinting

**Status:** CONFIRMED — full server stack exposed across both domains

**Test results:**

| Header / Source | Leaked Info |
|---|---|
| `Server: nginx/1.30.0` | Exact Nginx version (both domains) |
| `X-Powered-By: Next.js` | Framework on arclabel.cc |
| `x-nextjs-cache: HIT` | Internal caching behavior |
| `x-nextjs-prerender: 1` | Pre-rendering enabled |
| `x-nextjs-stale-time: 300` | Cache TTL = 5 minutes |
| Apache 403 error page | `Apache/2.4.58 (Ubuntu)` visible in error body on lk |
| phpinfo.php | PHP 8.3.6, Ubuntu kernel version, filesystem paths |

All three pages (/, /artists, /about) and even 404 pages leak the same headers.

**Remediation:**
```nginx
server_tokens off;
proxy_hide_header X-Powered-By;
proxy_hide_header x-nextjs-cache;
proxy_hide_header x-nextjs-prerender;
proxy_hide_header x-nextjs-stale-time;
```

Apache error pages should be customized to hide version info: `ServerSignature Off` and `ServerTokens Prod`.

---

### 10. DMARC Policy `p=none` — Email Spoofing Possible

**Status:** CONFIRMED

**Test:**
```
SPF:   v=spf1 ip4:91.122.51.213 -all                              → OK (hard fail)
DMARC: v=DMARC1; p=none; rua=mailto:webmaster@arclabel.cc; ...    → WEAK
DKIM:  mail._domainkey.arclabel.cc → DKIM1 RSA key found          → OK (exists)
       default._domainkey          → NXDOMAIN                     → Missing
```

SPF and DKIM (on `mail` selector) are configured. However, DMARC `p=none` means even if SPF/DKIM checks fail, the email is still delivered. An attacker can spoof emails from `info@arclabel.cc` or `agreement@arclabel.cc`.

**Remediation:**  
After confirming legitimate email flow works, change DMARC to:
```
v=DMARC1; p=reject; rua=mailto:webmaster@arclabel.cc; adkim=s; aspf=s
```

---

### 11. PHP Misconfiguration — No disable_functions, No open_basedir

**Status:** CONFIRMED (via phpinfo.php)

**Findings:**
- `disable_functions` = **(empty)** — `exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()` all available
- `open_basedir` = **(not set)** — PHP scripts can read/write anywhere on filesystem
- `allow_url_fopen` = **On** — PHP can open remote URLs as files
- `upload_max_filesize` = **100M** — very large uploads allowed

If any code injection or file upload vulnerability exists in the panel, an attacker gets immediate shell access.

**Remediation:**
```ini
; php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
open_basedir = /var/www/fastuser/data/www/lk.arclabel.cc:/tmp
upload_max_filesize = 10M
allow_url_fopen = Off
```

---

## LOW

### 12. API `/ping/` Endpoint Public — Leaks Server Time

**Target:** `https://api.arclabel.cc/ping/`  
**Status:** CONFIRMED

```
$ curl -s https://api.arclabel.cc/ping/
{"ok":true,"data":{"status":"api_reachable","time":"2026-05-05T14:07:34+00:00"}}
```

This endpoint is accessible without authentication and even when the IP is banned. It reveals:
- API is reachable (confirms infrastructure is running)
- Exact server time (useful for timing attacks, token generation prediction)

**Remediation:**  
Require authentication or remove this endpoint in production.

---

### 13. Missing robots.txt, sitemap.xml, security.txt

**Test:**
```
https://arclabel.cc/robots.txt                → 404
https://arclabel.cc/sitemap.xml               → 404
https://arclabel.cc/.well-known/security.txt  → 404
```

**Remediation:** Create all three files.

---

### 14. No CAA DNS Record

**Test:**
```
$ nslookup -type=CAA arclabel.cc
(no CAA records found — SOA returned instead)
```

Any Certificate Authority can issue SSL certificates for your domain.

**Remediation:** Add CAA record:
```
arclabel.cc.  IN  CAA  0 issue "letsencrypt.org"
```

---

### 15. No SRI on External Resources

**Test:**
```
External resources loaded:
- https://fonts.googleapis.com/css2?family=Google+Sans:...
- https://fonts.gstatic.com (preconnect)

Resources with integrity attribute: 0
```

---

## Passed Tests (No Vulnerabilities Found)

| Test | Result |
|---|---|
| SQL Injection (login form) | **PASS** — Classic and time-based blind SQLi both failed. Parameterized queries likely used. |
| Reflected XSS | **PASS** — Malicious URL paths and query params return 404, not reflected in response. |
| User Enumeration | **PASS** — Same error message for invalid user and wrong password: "Неверный логин или пароль" |
| Sensitive File Exposure | **PASS** — `.env`, `.git/config`, `wp-admin` all return 404 |
| CORS Misconfiguration | **PASS** — No `Access-Control-Allow-Origin` on cross-origin requests |
| HTTP TRACE Method | **PASS** — Returns 405 Not Allowed |
| HTTP OPTIONS Method | **PASS** — Returns 405, allows only GET/HEAD |
| Source Maps | **PASS** — `.js.map` files not accessible |
| Cookie HttpOnly flag | **PASS** — `session_token` has HttpOnly on both HTTP and HTTPS |
| Cookie SameSite | **PASS** — `session_token` has SameSite=Lax |
| TLS Version | **PASS** — TLS 1.3 with TLS_AES_256_GCM_SHA384 |
| SSL Certificate | **PASS** — Let's Encrypt, valid until Jul 24, 2026 |
| SPF Record | **PASS** — `v=spf1 ip4:91.122.51.213 -all` (hard fail) |
| DKIM Record | **PASS** — Found on `mail._domainkey` selector |

---

## Architecture Discovery

```
Internet (91.122.51.213)
    │
    ├── arclabel.cc (main site)
    │       └── Nginx 1.30.0 → Next.js (Turbopack, SSR/prerender)
    │
    ├── lk.arclabel.cc (admin panel)
    │       └── Nginx 1.30.0 → Apache 2.4.58 → PHP 8.3.6 + MySQL
    │
    └── api.arclabel.cc (REST API)
            └── Nginx 1.30.0 → Application (Bearer token auth)
                  │
                  ├── /ping/ (public, no auth needed)
                  ├── /auth/* (login, forgot, verify, OAuth: google/vk/telegram)
                  ├── /me, /users, /profile, /releases, /artists, /tracks
                  ├── /analytics, /dashboard, /upload, /settings
                  ├── /metrics, /debug, /pprof, /env, /config (debug!)
                  └── /swagger-ui, /redoc, /api-docs (API docs)

All services: Host mx1.lws.su, OS Ubuntu (Kernel 6.8.0-110)
Document Root: /var/www/fastuser/data/www/lk.arclabel.cc
```

**Note:** The web server and mail server appear to be the **same machine** (`mx1.lws.su`). Compromising the web application would also compromise the email system.

---

## Priority Remediation Order

| Priority | Action | Effort |
|---|---|---|
| 1 | **Delete `/phpinfo.php`** on lk.arclabel.cc | 1 command |
| 2 | **Fix `X-Forwarded-For` in Nginx** — use `$remote_addr` not client header | Nginx config edit |
| 3 | **Add Nginx-level rate limiting** on `/auth/login.php` | Nginx config edit |
| 4 | **Add HTTP → HTTPS redirect** in Nginx for all domains | Nginx config edit |
| 5 | **Add CSRF token** to login form | PHP code change |
| 6 | **Add security headers** (HSTS, CSP, X-Frame-Options, etc.) | Nginx config |
| 7 | **Configure `disable_functions` and `open_basedir`** in php.ini | PHP config |
| 8 | **Return 404 instead of 403** for unauthenticated API requests | API code change |
| 9 | **Protect `/ping/` endpoint** or remove server time from response | API code change |
| 10 | **Hide server versions** (`server_tokens off`, remove X-Powered-By) | Nginx config |
| 11 | **Upgrade DMARC** to `p=reject` | DNS record change |
| 12 | **Add CAA record** | DNS record change |
| 13 | **Add robots.txt, sitemap.xml, security.txt** | Static files |
