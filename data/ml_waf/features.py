"""
WAF feature extraction — identical logic ported to Rust (waf_infer/src/features.rs).
29 dense engineered features per HTTP request.
"""
import math
import re
import urllib.parse
from collections import Counter

FEATURE_NAMES = [
    "request_len",       # 0  total byte length
    "method_id",         # 1  GET=0 POST=1 PUT=2 DELETE=3 PATCH=4 HEAD=5 OPTIONS=6 other=7
    "path_len",          # 2  length of URL path
    "query_len",         # 3  length of query string
    "body_len",          # 4  length of request body
    "num_params",        # 5  number of key=value params (query + body)
    "entropy",           # 6  Shannon entropy of url+body
    "digit_ratio",       # 7  fraction of digit chars
    "upper_ratio",       # 8  fraction of uppercase chars
    "special_char_count",  # 9  count of  ' " < > ; = % & +
    "single_quote_count",  # 10
    "double_quote_count",  # 11
    "angle_bracket_count", # 12 '<' + '>'
    "semicolon_count",     # 13
    "pct_encoded_count",   # 14 %XX sequences
    "sql_keyword_count",   # 15
    "xss_pattern_count",   # 16
    "path_traversal_count",# 17 occurrences of '../'
    "cmd_injection_count", # 18
    "scanner_count",       # 19
    "ssrf_count",          # 20 SSRF indicators
    "php_pattern_count",   # 21 PHP-specific patterns
    "null_byte_count",     # 22 null byte injection
    "hex_encode_count",    # 23 hex-encoded payloads
    "crlf_inject_count",   # 24 CRLF / header injection
    "double_encode_count", # 25 double URL encoding (%25xx)
    "ssti_count",          # 26 Server-Side Template Injection patterns
    "header_count",        # 27 number of HTTP headers present
    "header_entropy",      # 28 Shannon entropy of header text (high for real browsers, 0 for bare probes)
]

NUM_FEATURES = len(FEATURE_NAMES)

_SQL = re.compile(
    r"\b(select|union|insert|update|delete|drop|create|alter|exec|execute|"
    r"where|from|having|order|group|join|table|database|schema|"
    r"char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b",
    re.IGNORECASE,
)
_XSS = re.compile(
    r"(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|"
    r"alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|"
    r"<iframe|<img\s|<svg|srcdoc=)",
    re.IGNORECASE,
)
_SCANNER = re.compile(
    r"(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|"
    r"dirbuster|gobuster|wfuzz|w3af|commix)",
    re.IGNORECASE,
)
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
# `\(\s*\)\s*\{` = shellshock function-definition signature "() {"
# (CVE-2014-6271), delivered via headers like Accept-Language / User-Agent.
_CMD = re.compile(r"\||&&|\$\(|`[^`]*`|\(\s*\)\s*\{")
_SSRF = re.compile(
    r"(?:127\.0\.0\.1|localhost|169\.254\.|0\.0\.0\.0|::1|"
    r"file://|dict://|gopher://|ftp://)",
    re.IGNORECASE,
)
_PHP = re.compile(
    r"(?:\.php|eval\(|base64_decode\(|system\(|passthru\(|"
    r"shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)",
    re.IGNORECASE,
)
_NULL_BYTE = re.compile(r"%00|\\x00|\\u0000")
_HEX_ENCODE = re.compile(r"0x[0-9a-fA-F]{4,}")
_CRLF = re.compile(r"%0[aAdD]|\\r\\n|\r\n")
_DBL_ENC = re.compile(r"%25[0-9a-fA-F]{2}")
_SSTI = re.compile(
    r"(\{\{.*?\}\})"                                      # Jinja2/Twig: {{expr}}
    r"|(\$\{[^}]{1,200}\})"                               # FreeMarker/Spring EL: ${expr}
    r"|(#\{[^}]{1,200}\})"                                # Spring EL: #{expr}
    r"|(<%=.*?%>)"                                        # ERB/JSP: <%= expr %>
    r"|(\?\s*new\s*\()"                                   # FreeMarker: ?new()
    r"|(__(class|mro|subclasses|globals|builtins|import)__)"  # Python dunders
    r"|(freemarker\.template|velocity\.tools)"             # template engine namespaces
    r"|(\{\s*\d+\s*\*\s*\d+\s*\})",                      # {N*N} arithmetic probe
    re.IGNORECASE | re.DOTALL,
)

_METHOD_MAP = {
    "GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
    "PATCH": 4, "HEAD": 5, "OPTIONS": 6,
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def extract_features(request: str) -> list[float]:
    # Format: "METHOD /url [body]\nHeader: val\n..."
    # Old single-line format is still handled (no \n present).
    nl = request.find("\n")
    if nl == -1:
        first_line, headers_text = request, ""
    else:
        first_line = request[:nl]
        headers_text = request[nl + 1:].replace("\n", " ")

    parts = first_line.split(" ", 2)
    method = parts[0] if parts else "GET"
    url    = parts[1] if len(parts) > 1 else "/"
    body   = parts[2] if len(parts) > 2 else ""

    path, _, query = url.partition("?")

    num_params = (query.count("&") + 1 if query else 0) + (
        body.count("&") + 1 if body else 0
    )

    full_for_chars = url + (" " + body if body else "")
    full_for_patterns = url + (" " + body if body else "") + (" " + headers_text if headers_text else "")
    n = max(len(full_for_chars), 1)

    try:
        full_dec_for_patterns = urllib.parse.unquote(full_for_patterns)
    except Exception:
        full_dec_for_patterns = full_for_patterns

    return [
        # ── length / structural (raw) ────────────────────────────────────────
        float(len(request)),                                    # 0
        float(_METHOD_MAP.get(method.upper(), 7)),              # 1
        float(len(path)),                                       # 2
        float(len(query)),                                      # 3
        float(len(body)),                                       # 4
        float(num_params),                                      # 5
        _entropy(full_for_chars),                               # 6
        sum(1 for c in full_for_chars if c.isdigit()) / n,      # 7
        sum(1 for c in full_for_chars if c.isupper()) / n,      # 8
        float(sum(1 for c in full_for_chars if c in "'\"><;=%&+")),  # 9
        float(full_for_chars.count("'")),                       # 10
        float(full_for_chars.count('"')),                       # 11
        float(full_for_chars.count("<") + full_for_chars.count(">")),  # 12
        float(full_for_chars.count(";")),                       # 13
        # ── encoding indicators (raw — the encoding itself is the signal) ───
        float(len(_PCT.findall(full_for_chars))),               # 14
        # ── attack patterns (decoded — catch encoded payloads in URL+body+headers) ───
        float(len(_SQL.findall(full_dec_for_patterns))),        # 15
        float(len(_XSS.findall(full_dec_for_patterns))),        # 16
        float(full_dec_for_patterns.lower().count("../")),      # 17
        float(len(_CMD.findall(full_dec_for_patterns))),        # 18
        float(len(_SCANNER.findall(full_dec_for_patterns))),    # 19
        float(len(_SSRF.findall(full_dec_for_patterns))),       # 20
        float(len(_PHP.findall(full_dec_for_patterns))),        # 21
        float(len(_NULL_BYTE.findall(full_for_patterns))),       # 22 raw — %00 vanishes after unquote; scan raw to catch it in Cookie/headers
        float(len(_HEX_ENCODE.findall(full_for_chars))),        # 23
        float(len(_CRLF.findall(full_for_chars))),              # 24
        float(len(_DBL_ENC.findall(full_for_chars))),           # 25
        float(len(_SSTI.findall(full_dec_for_patterns))),       # 26
        float(request.count("\n")),                              # 27 header_count
        _entropy(headers_text),                                  # 28 header_entropy
    ]
