# Security Audit Report — arclabel.cc

**Date:** 2026-05-05  
**Target:** https://arclabel.cc  
**Stack:** Next.js (Turbopack), Nginx 1.30.0, Let's Encrypt TLS  
**DNS:** Cloudflare NS, A-record → 91.122.51.213  
**Type:** External (black-box) analysis  

---

## Summary

| Category | Severity | Status |
|---|---|---|
| HTTP → HTTPS redirect missing | **HIGH** | FAIL |
| Missing security headers (CSP, HSTS, etc.) | **HIGH** | FAIL |
| Server/technology fingerprinting | **MEDIUM** | FAIL |
| DMARC policy too weak (`p=none`) | **MEDIUM** | WARN |
| DKIM not configured | **MEDIUM** | FAIL |
| Missing `robots.txt` | **LOW** | WARN |
| Missing `sitemap.xml` | **LOW** | WARN |
| No CAA DNS record | **LOW** | WARN |
| No IPv6 (AAAA record) | **LOW** | INFO |
| No SRI on third-party resources | **LOW** | WARN |
| Google Sans font licensing risk | **LOW** | INFO |

**Critical/High issues: 2 | Medium: 2 | Low: 5 | Info: 2**

---

## HIGH Severity

### 1. No HTTP → HTTPS Redirect

**Description:**  
Accessing `http://arclabel.cc` returns a `200 OK` with the full page content instead of redirecting to `https://`. This means all traffic over HTTP is served in cleartext, exposing users to man-in-the-middle (MITM) attacks, cookie theft, and content injection.

**Evidence:**
```
$ curl -sI http://arclabel.cc
HTTP/1.1 200 OK
Server: nginx/1.30.0
Content-Type: text/html; charset=utf-8
```

**Recommendation:**  
Add a permanent redirect in the Nginx configuration:

```nginx
server {
    listen 80;
    server_name arclabel.cc www.arclabel.cc;
    return 301 https://$host$request_uri;
}
```

---

### 2. Missing Critical Security Headers

**Description:**  
The server returns almost no security headers. The only non-standard headers present are `X-Powered-By: Next.js` (which itself is a leak — see below).

| Header | Expected | Current |
|---|---|---|
| `Strict-Transport-Security` (HSTS) | `max-age=63072000; includeSubDomains; preload` | **MISSING** |
| `Content-Security-Policy` (CSP) | Strict policy | **MISSING** |
| `X-Content-Type-Options` | `nosniff` | **MISSING** |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | **MISSING** |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | **MISSING** |
| `Permissions-Policy` | Restrictive policy | **MISSING** |
| `X-XSS-Protection` | `0` (deprecated, but still checked by scanners) | **MISSING** |

**Impact:**  
- Without HSTS, browsers won't enforce HTTPS even after an initial secure visit.
- Without CSP, the site has no defense against XSS via injected scripts.
- Without `X-Frame-Options`, the site can be embedded in an `<iframe>` on malicious pages (clickjacking).
- Without `X-Content-Type-Options`, browsers may MIME-sniff responses into executable content.

**Recommendation:**  
Add these headers in Nginx or via Next.js `next.config.js`:

```javascript
// next.config.js
async headers() {
  return [
    {
      source: '/(.*)',
      headers: [
        { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        {
          key: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
        },
      ],
    },
  ];
}
```

Also remove the `X-Powered-By` header:

```javascript
// next.config.js
module.exports = {
  poweredByHeader: false,
  // ...
}
```

---

## MEDIUM Severity

### 3. Server and Technology Fingerprinting

**Description:**  
Multiple response headers reveal exact software versions:

```
Server: nginx/1.30.0
X-Powered-By: Next.js
x-nextjs-cache: HIT
x-nextjs-prerender: 1
x-nextjs-stale-time: 300
```

An attacker can use this information to find known vulnerabilities in specific Nginx and Next.js versions.

**Recommendation:**
- In Nginx config, add: `server_tokens off;`
- In `next.config.js`, set `poweredByHeader: false`
- Consider removing or obfuscating `x-nextjs-*` headers in production via Nginx:

```nginx
proxy_hide_header X-Powered-By;
proxy_hide_header x-nextjs-cache;
proxy_hide_header x-nextjs-prerender;
proxy_hide_header x-nextjs-stale-time;
```

---

### 4. Email Security — Weak DMARC Policy, Missing DKIM

**Description:**  

**DMARC** is configured but with `p=none`, meaning failed emails are still delivered:
```
v=DMARC1; p=none; rua=mailto:webmaster@arclabel.cc; adkim=s; aspf=s
```

**DKIM** record at `default._domainkey.arclabel.cc` does not exist (NXDOMAIN). Without DKIM, emails from `@arclabel.cc` cannot be cryptographically verified.

**SPF** is present and correctly configured:
```
v=spf1 ip4:91.122.51.213 -all
```

**Impact:**  
An attacker can spoof emails from `info@arclabel.cc` or `agreement@arclabel.cc` (both listed on the site) to artists, partners, or anyone. With `p=none` in DMARC, recipient servers will log but not block these spoofed emails.

**Recommendation:**
1. Configure DKIM signing on your mail server (`mx1.lws.su`) and publish the public key as a TXT record.
2. After verifying DKIM works, change DMARC policy to `p=quarantine` or `p=reject`:
```
v=DMARC1; p=reject; rua=mailto:webmaster@arclabel.cc; adkim=s; aspf=s
```

---

## LOW Severity

### 5. Missing `robots.txt`

**Description:**  
`https://arclabel.cc/robots.txt` returns `404`. Search engines cannot find crawling instructions.

**Recommendation:**  
Create a `robots.txt` in the `public/` directory:
```
User-agent: *
Allow: /
Sitemap: https://arclabel.cc/sitemap.xml
```

---

### 6. Missing `sitemap.xml`

**Description:**  
`https://arclabel.cc/sitemap.xml` returns `404`. This hurts SEO discoverability.

**Recommendation:**  
Use `next-sitemap` package or create a static sitemap listing `/`, `/artists`, `/about`.

---

### 7. No CAA DNS Record

**Description:**  
There is no CAA (Certificate Authority Authorization) record. Any CA can issue certificates for `arclabel.cc`.

**Recommendation:**  
Add a CAA record in Cloudflare DNS:
```
arclabel.cc.  IN  CAA  0 issue "letsencrypt.org"
arclabel.cc.  IN  CAA  0 iodef "mailto:webmaster@arclabel.cc"
```

---

### 8. No Subresource Integrity (SRI) on External Resources

**Description:**  
Google Fonts stylesheet is loaded from `fonts.googleapis.com` without an `integrity` attribute. If Google's CDN were compromised, malicious CSS could be injected.

**Recommendation:**  
Consider self-hosting fonts or adding SRI hashes where feasible.

---

### 9. Google Sans Font — Potential Licensing Issue

**Description:**  
The site loads `Google Sans` font from Google Fonts. Google Sans is not listed as a publicly available Google Font — it's typically restricted to Google products. If used without a license, this could be a legal issue.

**Recommendation:**  
Verify that you have a license to use Google Sans, or switch to a similar publicly available font like `Inter`, `Outfit`, or `Plus Jakarta Sans`.

---

## INFO

### 10. No IPv6 (AAAA) Record

No AAAA record exists for `arclabel.cc`. Not a vulnerability, but IPv6 support is recommended for modern web accessibility.

---

## Positive Findings

The following security aspects are properly configured:

- **TLS 1.3** with strong cipher `TLS_AES_256_GCM_SHA384`
- **SSL certificate** is valid (Let's Encrypt, expires Jul 24, 2026)
- **No sensitive files exposed** (`.env`, `.git/config`, `wp-admin` — all return 404)
- **XSS in URL path** is handled safely (malicious URL paths return 404, not reflected)
- **No leaked API keys or secrets** found in HTML source
- **CORS** is not misconfigured (no `Access-Control-Allow-Origin` on cross-origin requests)
- **TRACE method** is disabled (returns 405)
- **OPTIONS method** is properly restricted
- **No source maps** exposed for JS bundles
- **No open admin panels** or login pages found
- **SPF** record is correctly configured with `-all` (hard fail)

---

## Recommended Priority Order

1. **[URGENT]** Add HTTP → HTTPS redirect in Nginx
2. **[URGENT]** Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers
3. **[HIGH]** Remove server version disclosure (`server_tokens off`, `poweredByHeader: false`)
4. **[MEDIUM]** Configure DKIM and upgrade DMARC to `p=reject`
5. **[LOW]** Add `robots.txt`, `sitemap.xml`, CAA record
6. **[LOW]** Self-host fonts or verify Google Sans license
