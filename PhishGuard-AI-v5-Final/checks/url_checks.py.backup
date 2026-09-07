import urllib.parse
import ipaddress
import math
import re


KEYWORDS = [
    "login",
    "signin",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "confirm",
    "wallet",
    "bank",
    "otp",
    "auth",
    "billing",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
}


def hostname_entropy(host):
    if not host:
        return 0.0

    length = len(host)
    entropy = 0.0

    for char in set(host):
        count = host.count(char)
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def url_checks(url):
    url = (url or "").strip()

    if not url:
        return {
            "evidence": [
                {
                    "severity": "high",
                    "message": "Empty URL",
                    "points": 30,
                }
            ],
            "features": {},
            "summary": {
                "host": "",
                "risk_score": 30,
                "risk_level": "HIGH",
            },
        }

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
    except Exception:
        return {
            "evidence": [
                {
                    "severity": "high",
                    "message": "Invalid URL format",
                    "points": 30,
                }
            ],
            "features": {},
            "summary": {
                "host": "",
                "risk_score": 30,
                "risk_level": "HIGH",
            },
        }

    evidence = []
    score = 0

    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # --------------------------------------------------
    # BASIC FEATURES
    # --------------------------------------------------

    url_length = len(url)
    hostname_length = len(host)
    dot_count = host.count(".")
    hyphen_count = host.count("-")
    digit_count = sum(c.isdigit() for c in url)

    subdomain_count = max(0, dot_count - 1)

    has_https = scheme == "https"

    try:
        ipaddress.ip_address(host)
        has_ip = True
    except ValueError:
        has_ip = False

    at_symbol = "@" in url

    keyword_hits = [
        keyword
        for keyword in KEYWORDS
        if keyword in url.lower()
    ]

    punycode = "xn--" in host.lower()

    double_slash_path = "//" in path

    try:
        port = parsed.port
    except ValueError:
        port = None

    hostname_digit_count = sum(c.isdigit() for c in host)

    suspicious_characters = bool(
        re.search(r"[^a-zA-Z0-9.\-:/?=&_%+#]", url)
    )

    multiple_hyphens = hyphen_count >= 3

    digit_heavy_hostname = (
        not has_ip
        and hostname_length >= 8
        and hostname_digit_count >= 5
    )

    shortener = host.lower() in SHORTENERS

    entropy = hostname_entropy(host)

    # --------------------------------------------------
    # RISK CHECKS
    # --------------------------------------------------

    if scheme != "https":
        evidence.append(
            {
                "severity": "medium",
                "message": "Website is not using HTTPS",
                "points": 8,
            }
        )
        score += 8

    if url_length > 120:
        evidence.append(
            {
                "severity": "medium",
                "message": "Unusually long URL",
                "points": 8,
            }
        )
        score += 8

    if has_ip:
        evidence.append(
            {
                "severity": "high",
                "message": "IP address used as hostname",
                "points": 25,
            }
        )
        score += 25

    if at_symbol:
        evidence.append(
            {
                "severity": "high",
                "message": "@ symbol detected in URL",
                "points": 20,
            }
        )
        score += 20

    if parsed.username or parsed.password:
        evidence.append(
            {
                "severity": "high",
                "message": "Embedded credentials detected",
                "points": 25,
            }
        )
        score += 25

    if keyword_hits:
        points = min(12, len(keyword_hits) * 2)

        evidence.append(
            {
                "severity": "medium",
                "message": (
                    "Sensitive URL keywords: "
                    + ", ".join(keyword_hits)
                ),
                "points": points,
            }
        )

        score += points

    if subdomain_count >= 3:
        evidence.append(
            {
                "severity": "medium",
                "message": "Multiple subdomains detected",
                "points": 8,
            }
        )
        score += 8

    if punycode:
        evidence.append(
            {
                "severity": "medium",
                "message": "Punycode hostname detected",
                "points": 10,
            }
        )
        score += 10

    if shortener:
        evidence.append(
            {
                "severity": "medium",
                "message": "URL shortener detected",
                "points": 8,
            }
        )
        score += 8

    if double_slash_path:
        evidence.append(
            {
                "severity": "medium",
                "message": "Double-slash path obfuscation detected",
                "points": 6,
            }
        )
        score += 6

    if port is not None and port not in (80, 443):
        evidence.append(
            {
                "severity": "medium",
                "message": f"Non-standard port detected: {port}",
                "points": 6,
            }
        )
        score += 6

    if suspicious_characters:
        evidence.append(
            {
                "severity": "low",
                "message": "Suspicious characters detected",
                "points": 4,
            }
        )
        score += 4

    if multiple_hyphens:
        evidence.append(
            {
                "severity": "low",
                "message": "Multiple hyphens in hostname",
                "points": 3,
            }
        )
        score += 3

    # IMPORTANT:
    # Check digits in HOSTNAME only.
    # UUIDs or numbers in URL paths should not trigger this warning.
    if digit_heavy_hostname:
        evidence.append(
            {
                "severity": "medium",
                "message": "Hostname contains unusually many digits",
                "points": 8,
            }
        )
        score += 8

    # --------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # --------------------------------------------------
    # FEATURES FOR PROFESSIONAL DISPLAY
    # --------------------------------------------------

    features = {
        "URL Length": url_length,
        "Hostname Length": hostname_length,
        "Scheme": scheme.upper(),
        "HTTPS": "YES" if has_https else "NO",
        "IP Host": "YES" if has_ip else "NO",
        "Dot Count": dot_count,
        "Hyphen Count": hyphen_count,
        "Digit Count": digit_count,
        "Hostname Digit Count": hostname_digit_count,
        "Subdomain Count": subdomain_count,
        "Path Length": len(path),
        "Query Length": len(query),
        "Fragment Length": len(fragment),
        "Sensitive Keywords": (
            ", ".join(keyword_hits)
            if keyword_hits
            else "NONE"
        ),
        "Punycode": "YES" if punycode else "NO",
        "URL Shortener": "YES" if shortener else "NO",
        "@ Symbol": "YES" if at_symbol else "NO",
        "Embedded Credentials": (
            "YES"
            if parsed.username or parsed.password
            else "NO"
        ),
        "Double Slash Path": (
            "YES"
            if double_slash_path
            else "NO"
        ),
        "Port": (
            str(port)
            if port is not None
            else "Default"
        ),
        "Hostname Entropy": entropy,
    }

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    return {
        "evidence": evidence,
        "features": features,
        "summary": {
            "host": host,
            "length": url_length,
            "keywords": keyword_hits,
            "scheme": scheme,
            "has_ip": has_ip,
            "risk_score": score,
            "risk_level": risk_level,
        },
    }
