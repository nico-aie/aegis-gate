use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// Reconnaissance detector: directory scanning, known tools, probing.
pub struct ReconDetector;

static RECON_PATHS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // 2026-06-21 (l-tester FP sweep) — segment-anchored so `.Env.`
        // inside a JSONP callback (`YUI.Env.JSONP`) doesn't FP. `.env`
        // is always a dotfile at a path segment (`/.env`, `/app/.env.prod`).
        r"(?i)(?:^|/)\.env(?:\.|$)",
        r"(?i)(?:\.git(?:/|$))",
        r"(?i)(?:\.svn(?:/|$))",
        r"(?i)(?:\.hg(?:/|$))",
        r"(?i)(?:\.DS_Store)",
        r"(?i)(?:\.htaccess)",
        r"(?i)(?:\.htpasswd)",
        r"(?i)(?:wp-config\.php)",
        // 2026-06-21 (l-tester FP sweep) — segment-anchored so a mid-filename
        // `_web.Config…` (e.g. `config_fare_families_web.ConfigPrePageLanding`)
        // doesn't FP. Real probe is the IIS `/web.config` file.
        r"(?i)(?:^|/)web\.config(?:$|[/?#])",
        r"(?i)(?:phpinfo\(\))",
        // 2026-05-22 FP fix — anchor admin-panel probes to a path
        // SEGMENT (preceded by `/` or start, followed by a boundary)
        // so `/wp-admin/`, `/administrator/`, `/adminer.php` still match
        // but mid-word legit paths don't (`/api/administrators`,
        // `/myadminer-helper`).
        r"(?i)(?:^|/)wp-admin(?:$|[/?])",
        r"(?i)(?:^|/)wp-login(?:$|[/?.])",
        r"(?i)(?:^|/)administrator(?:$|[/?])",
        r"(?i)(?:^|/)phpmyadmin(?:$|[/?])",
        r"(?i)(?:^|/)adminer(?:$|[/?.])",
        // 2026-06-21 (l-tester FP sweep) — narrowed from the blanket
        // `/debug/` (which FP'd on app routes like `/api/v4/debug/logs`
        // and Privacy-Sandbox `/.well-known/.../debug/...`) to the Go
        // expvar/pprof recon surface, the actual high-signal target.
        r"(?i)/debug/(?:pprof|vars)\b",
        r"(?i)(?:/console)(?:$|[/?])",
        r"(?i)(?:elmah\.axd)",
        r"(?i)(?:trace\.axd)",
        r"(?i)(?:server-status)",
        r"(?i)(?:server-info)",
        r"(?i)(?:backup\.(?:sql|zip|tar|gz|bak))",
        r"(?i)(?:database\.(?:sql|dump))",
        // RC-3 (2026-07-05) — `.backup` added to the generic editor/backup
        // suffix tail (zero legit use as a served extension).
        r"(?i)(?:\.(?:bak|old|orig|save|swp|tmp|backup)$)",
        // Editor backup files left in the webroot (`/index.php~`,
        // `/config~`). 2026-06-21 (l-tester FP sweep) — the `~` must
        // terminate the PATH, not a query value: `^[^?]*~$` rejects
        // analytics pixels whose query ends in `~` (GA `__utm.gif?…~`,
        // SHEIN `…scici=…~~~~`) while still catching path-tail backups.
        r"^[^?]*~$",
        r"(?i)(?:Dockerfile)",
        // 2026-06-19 (btc-miss report) — broadened from the narrow
        // `docker-compose\.ya?ml`. Covers Compose v1 override variants
        // (`docker-compose.override.yml`, `docker-compose.prod.yml`)
        // and the Compose v2 canonical name (`compose.yml`/`compose.yaml`).
        // Segment + value anchored so `/static/compose-ui/widget.js`
        // and similar don't FP.
        r"(?i)(?:^|/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml(?:$|[?#])",
        // SEC-L001 (2026-05-08) — Docker REST API surface.
        // Versioned paths /v{major}.{minor}/{containers,images,...}
        // are how the Docker daemon's HTTP API is reachable when
        // the socket is mistakenly exposed via TCP / a sidecar
        // proxy. Probe: `GET /v1.24/containers/json`.
        // 2026-06-18 (round-2 FP fix): anchored to major version `1`
        // (`v1.NN`). The Docker Engine API has only ever been `v1.x`
        // (1.24…1.45); the previous `v\d+\.\d+` collided with Facebook
        // Graph SDK plugin URLs (`/v6.0/plugins/page.php`,
        // `/v5.0/plugins/customerchat.php`).
        r"(?i)(?:^|/)v1\.\d+/(?:containers|images|networks|volumes|services|tasks|secrets|configs|swarm|nodes|plugins|info|version|events|system|build|auth)\b",
        r"(?i)(?:^|/)_ping\b",
        r"(?i)(?:Makefile$)",
        r"(?i)(?:\.aws/credentials)",
        r"(?i)(?:\.ssh/)",
        // VULN-03 (waf_security_report 2026-06-10) — bare config /
        // secret files served at a path segment leak DB creds & keys.
        // Anchored to a segment (`^` or `/`) and a value boundary so
        // they fire on `/config.yaml`, `/app/secrets.yml` but never
        // mid-word (`/reconfigure-status`). Deliberately NOT the
        // report's blanket `\.(yaml|yml|json|toml|ini|cfg|conf)$` —
        // that FPs on the heap of legit `*.json` / `*.yaml` API and
        // manifest traffic. Score stays at the probe tier (25): a lone
        // hit accumulates via the per-IP risk model rather than
        // single-blocking (operator decision 2026-06-13).
        r"(?i)(?:^|/)config\.ya?ml(?:$|[?#])",
        r"(?i)(?:^|/)(?:secrets?|settings|credentials)\.ya?ml(?:$|[?#])",
        // 2026-06-19 (btc-miss report) — framework DB/parameter config
        // files. Same segment + value anchoring as the config/secrets
        // family above: `/config/database.yaml` (Rails), `/app/config/
        // parameters.yml` (Symfony) leak DB creds. Specific filenames
        // only — NOT a blanket `*.yml` (FPs on legit manifest traffic).
        r"(?i)(?:^|/)(?:database|parameters)\.ya?ml(?:$|[?#])",
        // SQL dumps left in the webroot — `dump.sql`, `db.sql.gz`,
        // `backup.sql`, `mysql.sql`, `pg_dump.sql`. Anchored to
        // dump-shaped filenames (NOT bare `*.sql`) + optional `.gz`.
        r"(?i)(?:^|/)(?:dump|db|backup|mysql|pg[_-]?dump)[\w.-]*\.sql(?:\.gz)?(?:$|[?#])",
        // Laravel log exposure — `/storage/logs/laravel.log` leaks
        // stack traces, queries, env. Anchored to the framework's
        // log directory so generic `*.log` API params don't FP.
        r"(?i)(?:^|/)storage/logs/[\w.-]*\.log\b",
        // Private-key / keystore material. Restrict to private-bearing
        // extensions; .crt/.cer/.der are EXCLUDED (public certs are
        // sometimes legitimately downloadable) to keep FP at zero.
        r"(?i)\.(?:pem|key|p12|pfx|jks|keystore)(?:$|[?#])",
        // GAP-001 (Run-5, 2026-05-08) — framework recon paths.
        // Spring Boot actuator danger endpoints (/health and /info
        // are intentionally public on most Spring deployments;
        // only the dangerous subpaths flag).
        r"(?i)/actuator/(?:heapdump|threaddump|env|configprops|loggers|trace|httptrace|auditevents|dump|jolokia|liquibase|flyway|gateway|conditions|beans|mappings|metrics/.*|sessions|shutdown)\b",
        // Laravel Ignition — CVE-2021-3129 (RCE).
        r"(?i)/_ignition/(?:execute-solution|health-check|update-config)\b",
        // Swagger / OpenAPI surface enumeration.
        r"(?i)/(?:swagger-ui\.html|swagger\.json|swagger\.yaml|v\d+/api-docs|api-docs|openapi\.json|openapi\.yaml)\b",
        // GraphQL recon. 2026-05-20 — DON'T flag the bare `/graphql`
        // endpoint: it's a normal API surface and matching the path
        // blocked every legitimate query (e.g.
        // `/api/aggregator/graphql?query={ findContent(...) }`). The
        // real recon signal is INTROSPECTION — `__schema`,
        // `__type(name:…)`, or a named `IntrospectionQuery`. Note
        // `__typename` is a benign meta-field and must NOT match
        // (hence `__type\s*\(`, which `__typename` can't satisfy).
        // The interactive IDE/playground surfaces ARE recon-worthy
        // (rarely exposed in prod) so they stay path-matched.
        r"(?i)(?:__schema\b|\bIntrospectionQuery\b|__type\s*\()",
        r"(?i)/graphiql(?:/|\?|$)",
        r"(?i)/playground(?:/|\?|$)",
        // Kubernetes API namespaces / pods / deployments.
        r"(?i)/api/v1/namespaces\b",
        r"(?i)/api/v1/pods\b",
        r"(?i)/apis/apps/v1/deployments\b",
        // Kibana / Elastic internals.
        // Kibana 6+: classic `app/kibana`. Kibana 7/8: `/kibana/app`,
        // `/kibana/api/...`. Elastic API: `_cat/indices`,
        // `_cluster/health`, `.kibana/_search` (config index).
        // 2026-05-09 — Run-7 added `/kibana/app` + `/kibana/api`
        // shapes (Run-6 only had `app/kibana`).
        r"(?i)/(?:app/kibana|kibana/(?:app|api)|\.kibana(?:/|/_search)|_cat/indices|_cluster/health)\b",
        // Jenkins script console (Groovy RCE) and CLI jar.
        // 2026-06-21 (l-tester FP sweep) — `/script(Text)?` is anchored to
        // a full path segment (end-of-path or query) so JS assets
        // (`/assets/script.js`), tag-manager routes (`/api/tag/script/<id>`),
        // and recon tokens inside decoded redirect params
        // (`dl=…/script.google.com/…`) don't FP. Bare `/manage` was DROPPED:
        // "Manage Jenkins" is too generic a segment — it collided with
        // `/account/manage`, `/users/<id>/manage`, and analytics
        // `ref=…/manage.wix.com`. The Jenkins-specific high-signal tokens
        // (`/scriptText`, the CLI jar, per-node `/computer/.../script`) stay.
        r"(?i)/script(?:Text)?(?:$|[?#])",
        r"(?i)/(?:jnlpJars/jenkins-cli\.jar|computer/(?:\(master\)|\(built-in\))/script)\b",
        // CGI legacy probes — Shellshock surface, classic info
        // disclosure.
        r"(?i)/cgi-bin/(?:printenv\.pl|test-cgi|php-cgi|\.\.)\b",
        // Prometheus federation/scrape-target probe. Bare
        // `/metrics` is a legit operator-hosted endpoint and
        // is NOT flagged; only the suspicious-query shapes
        // (`?format=`, `?target=`, `?module=`) fire.
        r"(?i)/metrics\?(?:format=|target=|module=)",
        // GAP-001b (Run-6, 2026-05-09) — bare actuator discovery
        // page. Spring Boot Actuator's root index lists every
        // available endpoint; operators legitimately exposing
        // actuator typically expose `/actuator/health` and
        // `/actuator/info` (the safe subset) but rarely the bare
        // index. Match `/actuator` followed by end-of-path or
        // query-prefix only — `/actuator/health` (subpath form)
        // does NOT match here.
        r"(?i)/actuator(?:$|\?|#)",
        // Rails debug surface — `/rails/info/*` leaks installed
        // gems, environment, and routes. Development-only page;
        // reachable in prod = recon dump.
        r"(?i)/rails/info(?:/|$)",
        // Classic PHP-developer-debug files — `phpinfo()` output
        // dumps loaded modules / paths / environment. Distinct
        // from the existing `phpinfo\(\)` function-call match,
        // which catches the shape inside a body or query value.
        // Common filenames operators leave behind by accident:
        // `phpinfo.php`, `info.php`, `test.php`, `i.php`.
        r"(?i)/(?:phpinfo|info|test|i)\.php(?:$|\?|/)",
        // 2026-06-19 (btc-miss report) — vendor/control-panel recon
        // surfaces that were fully missed.
        // SAP NetWeaver RECON (CVE-2020-6287) — unauthenticated admin
        // user creation via the LM Configuration Wizard.
        r"(?i)(?:^|/)developmentserver/metadatauploader\b",
        // MSSQL Reporting Services root. Distinct anchored token so the
        // `report` substring in `/api/reports/monthly` doesn't FP.
        r"(?i)(?:^|/)ReportServer(?:$|[/?])",
        // Control Web Panel file manager (CVE-2021-45467) — the
        // `initialize` action is the LFI/RCE entry point.
        r"(?i)(?:^|/)file-manager/initialize\b",
        // cPanel / WHM internal subdomain proxy — `___proxy_subdomain*`
        // is a cPanel-internal token never seen in legit external traffic.
        r"(?i)(?:^|/)___proxy_subdomain",
        // ── RC-3 (2026-07-05) — genuinely-missing signature families ────
        // All score at recon::PATH (25): accumulate via the per-IP model,
        // never single-block. Tight anchors + look-alike negatives in the
        // test module; corpus re-validation deferred to Wave B.
        //
        // Secrets — bare SSH private key at the webroot. Segment-anchored
        // to a value boundary so `/id_rsa_setup_guide.html` (the `_`
        // breaks the boundary) does NOT fire. The `.ssh/` directory form
        // is already covered above.
        r"(?i)(?:^|/)id_rsa(?:$|[?#])",
        // npm credential file (`_authToken=…`) and the git-credentials
        // store (`https://user:pass@host`). `.git-credentials` is NOT
        // caught by the `\.git(?:/|$)` dir pattern (the `-` breaks it).
        r"(?i)(?:^|/)\.npmrc(?:$|[?#])",
        r"(?i)(?:^|/)\.git-credentials(?:$|[?#])",
        // Generic `secrets.*` / `secret.*` exposure — broadens the
        // existing `secrets?\.ya?ml` to the other credential-bearing
        // extensions. Value-anchored so `/secrets-rotation-guide.html`
        // and `/api/secretary/…` (no `.`-boundary) do NOT fire.
        r"(?i)(?:^|/)secrets?\.(?:json|txt|ya?ml|env|config)(?:$|[?#])",
        // `word.env` dotenv variants (`config.env`, `aws.env`, `db.env`)
        // — distinct from the `/.env` dotfile pattern above, which
        // requires `.env` right after a `/`. Value-anchored so
        // `*.environment` does NOT fire (the trailing chars break `$`).
        r"(?i)(?:^|/)[\w-]+\.env(?:$|[?#])",
        // WordPress config leaked as `.txt` (the `.php.bak` etc. forms
        // are already caught by the generic backup-suffix tail below).
        r"(?i)(?:^|/)wp-config\.txt(?:$|[?#])",
        // Webroot backup archives — anchored to a *backup-shaped* leading
        // word so legit downloadable archives (`/downloads/report.zip`,
        // `/assets/app.js.gz`) do NOT fire. Catches `/www.tar.gz`,
        // `/site.zip`, `/db.gz`, `/backup.tar.gz`, `/wwwroot.zip`.
        r"(?i)(?:^|/)(?:backup|bak|www|wwwroot|web|htdocs|public_html|site|db|database|dump|release|deploy|full|old)[\w.-]*\.(?:zip|tgz|tar\.gz|tar|gz|rar|7z)(?:$|[?#])",
        // Exchange / ProxyShell — the `.json` autodiscover SSRF vector
        // (CVE-2021-34473). The `.xml` autodiscover endpoint is hit by
        // every legit Outlook client and is deliberately NOT matched.
        r"(?i)(?:^|/)autodiscover/autodiscover\.json\b",
        // OWA / ManageEngine login pages — exploit-chain entry points
        // (ProxyLogon, CVE-2022-47966). On a site NOT fronting Exchange/
        // ManageEngine any hit is recon; run one behind the WAF and tune
        // these out. Score 25 keeps the blast radius bounded.
        r"(?i)(?:^|/)owa/auth/logon\.aspx(?:$|[?#])",
        r"(?i)(?:^|/)Core/Skin/Login\.aspx(?:$|[?#])",
        // WordPress — abused wp-json subpaths (Gravity Forms SMTP creds,
        // wp/v2/settings enumeration). Bare `/wp-json/` and legit REST
        // collections (`/wp-json/wp/v2/posts`) are NOT matched.
        r"(?i)(?:^|/)wp-json/(?:gravitysmtp|wp/v2/settings)\b",
        // WLW manifest + XML-RPC — classic WP enumeration / pingback and
        // brute-force surfaces. Value-anchored.
        r"(?i)(?:^|/)wlwmanifest\.xml(?:$|[?#])",
        r"(?i)(?:^|/)xmlrpc\.php(?:$|[?#])",
        // CI/CD — Jenkins pipeline definition + job config.xml (leaks
        // credentials/secrets). `config.xml` is anchored to a jenkins
        // path context so bare `/config.xml` (too generic) does NOT fire.
        r"(?i)(?:^|/)Jenkinsfile(?:$|[?#])",
        r"(?i)(?:^|/)jenkins[\w./-]*config\.xml\b",
        // Terraform working directory — may contain state with plaintext
        // provider creds. Segment-anchored so `/my.terraform-guide`
        // (the `-` breaks the boundary) does NOT fire.
        r"(?i)(?:^|/)\.terraform(?:/|$)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

static RECON_UA: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:sqlmap)",
        r"(?i)(?:nikto)",
        r"(?i)(?:nmap)",
        r"(?i)(?:masscan)",
        r"(?i)(?:dirbuster)",
        r"(?i)(?:gobuster)",
        r"(?i)(?:feroxbuster)",
        r"(?i)(?:wfuzz)",
        r"(?i)(?:ffuf)",
        r"(?i)(?:nuclei)",
        r"(?i)(?:burp)",
        r"(?i)(?:zap)",
        r"(?i)(?:acunetix)",
        r"(?i)(?:nessus)",
        r"(?i)(?:openvas)",
        r"(?i)(?:w3af)",
        r"(?i)(?:whatweb)",
        r"(?i)(?:wpscan)",
        r"(?i)(?:joomscan)",
        r"(?i)(?:arachni)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Standard browser/CMS/SDK paths that collide with the generic recon
/// patterns but are NOT probes (2026-06-18 round-2 FP fix). Suppressing
/// them up front avoids non-blocking recon noise polluting per-IP risk.
fn is_benign_recon_path(path: &str) -> bool {
    // Chrome Privacy Sandbox Attribution Reporting (W3C standard) — the
    // `/debug/` recon pattern otherwise fires on its debug subpaths.
    path.starts_with("/.well-known/attribution-reporting/")
        // Chrome Privacy Sandbox Private Aggregation (W3C standard) — same
        // shape as attribution-reporting; emits `/debug/...` report subpaths.
        || path.starts_with("/.well-known/private-aggregation/")
        // WordPress front-end AJAX endpoints — hit by every visitor; the
        // `wp-admin` panel-probe pattern otherwise fires.
        || path.ends_with("/admin-ajax.php")
        || path.ends_with("/admin-post.php")
        // WordPress static front-end assets served from /wp-admin/ and loaded
        // by anonymous visitors (e.g. password-strength-meter.min.js, the
        // login/registration form scripts and styles). The directory itself
        // is the admin panel — only these asset subpaths are benign.
        || path.contains("/wp-admin/js/")
        || path.contains("/wp-admin/css/")
        || path.contains("/wp-admin/images/")
        || path.contains("/wp-admin/load-scripts.php")
        || path.contains("/wp-admin/load-styles.php")
}

impl Detector for ReconDetector {
    fn id(&self) -> &'static str {
        "recon"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();
        // (see is_benign_recon_path below for the benign-collision allowlist)

        // Check path-and-query for recon targets. We use the full
        // path-and-query (not just `path()`) so query-shaped probes
        // like `/metrics?format=prometheus` (Prometheus federation
        // scrape) can match. Existing path-only patterns are
        // unaffected — they don't contain `?`.
        let path_q = req
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or_else(|| req.uri.path());
        // 2026-06-18 (round-2 FP fix): standard browser/CMS/SDK paths that
        // collide with the generic recon patterns are suppressed up front.
        if !is_benign_recon_path(req.uri.path()) {
            for re in RECON_PATHS.iter() {
                if re.is_match(path_q) {
                    signals.push(Signal {
                        score: super::scores::recon::PATH,
                        tag: "recon_path".into(),
                        field: "uri".into(),
                    });
                    break;
                }
            }
        }

        // Check User-Agent for known tools.
        if let Some(ua) = req.headers.get("user-agent").and_then(|v| v.to_str().ok()) {
            for re in RECON_UA.iter() {
                if re.is_match(ua) {
                    signals.push(Signal {
                        score: super::scores::recon::TOOL,
                        tag: "recon_tool".into(),
                        field: "user-agent".into(),
                    });
                    break;
                }
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn view_with_path(path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            path.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn view_with_ua(ua: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut headers = http::HeaderMap::new();
        headers.insert("user-agent", ua.parse().unwrap());
        (
            http::Method::GET,
            "/".parse().unwrap(),
            headers,
            BodyPeek::empty(),
        )
    }

    fn make_view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m, uri: u, version: http::Version::HTTP_11,
            headers: h, peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None, body: b,
        }
    }

    // Path-based positive tests.
    macro_rules! path_positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = ReconDetector;
                let (m, u, h, b) = view_with_path($input);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(s.iter().any(|s| s.tag == "recon_path"), "expected recon for path: {}", $input);
            }
        };
    }

    macro_rules! path_negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = ReconDetector;
                let (m, u, h, b) = view_with_path($input);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(
                    !s.iter().any(|s| s.tag == "recon_path"),
                    "false positive: recon fired on benign path: {}",
                    $input,
                );
            }
        };
    }

    path_positive!(env_file, "/.env");
    path_positive!(env_prod, "/.env.production");
    path_positive!(git_dir, "/.git/HEAD");
    path_positive!(git_config, "/.git/config");
    path_positive!(svn_dir, "/.svn/entries");
    path_positive!(ds_store, "/.DS_Store");
    path_positive!(htaccess, "/.htaccess");
    path_positive!(htpasswd, "/.htpasswd");
    path_positive!(wp_config, "/wp-config.php");
    path_positive!(web_config, "/web.config");
    path_positive!(wp_admin, "/wp-admin/");
    path_positive!(wp_login, "/wp-login.php");
    path_positive!(phpmyadmin, "/phpmyadmin/");
    path_positive!(adminer, "/adminer.php");
    path_positive!(debug_path, "/debug/vars");
    path_positive!(console_path, "/console");
    path_positive!(server_status, "/server-status");
    path_positive!(server_info, "/server-info");
    path_positive!(backup_sql, "/backup.sql");
    path_positive!(backup_zip, "/backup.zip");
    path_positive!(database_dump, "/database.dump");
    path_positive!(bak_file, "/config.bak");
    path_positive!(old_file, "/settings.old");
    path_positive!(swp_file, "/file.swp");
    path_positive!(tilde_file, "/config~");
    path_positive!(dockerfile, "/Dockerfile");
    path_positive!(docker_compose, "/docker-compose.yml");
    // SEC-L001 (2026-05-08) — Docker REST API surface.
    path_positive!(docker_api_containers,    "/v1.24/containers/json");
    path_positive!(docker_api_info,          "/v1.41/info");
    path_positive!(docker_api_images_short,  "/v1.43/images/json");
    path_positive!(docker_api_networks,      "/v1.40/networks");
    path_positive!(docker_api_swarm,         "/v1.41/swarm");
    path_positive!(docker_api_ping,          "/_ping");
    path_positive!(aws_creds, "/.aws/credentials");
    path_positive!(ssh_dir, "/.ssh/id_rsa");
    path_positive!(hg_dir, "/.hg/store");
    // VULN-03 (waf_security_report 2026-06-10) — bare config / secret
    // files + private-key/keystore material.
    path_positive!(config_yaml,       "/config.yaml");
    path_positive!(config_yml,        "/config.yml");
    path_positive!(config_yaml_nested,"/app/config.yaml");
    path_positive!(config_yaml_query, "/config.yaml?v=1");
    path_positive!(secrets_yaml,      "/secrets.yaml");
    path_positive!(secret_yaml,       "/secret.yml");
    path_positive!(settings_yaml,     "/settings.yml");
    path_positive!(credentials_yaml,  "/credentials.yaml");
    path_positive!(key_pem,           "/server.pem");
    path_positive!(key_file,          "/tls.key");
    path_positive!(keystore_p12,      "/keystore.p12");
    path_positive!(keystore_jks,      "/store.jks");
    path_positive!(cert_pfx,          "/cert.pfx");
    // GAP-001 (Run-5) — framework recon positives.
    path_positive!(actuator_heapdump,     "/actuator/heapdump");
    path_positive!(actuator_env,          "/actuator/env");
    path_positive!(actuator_jolokia,      "/actuator/jolokia");
    path_positive!(actuator_threaddump,   "/actuator/threaddump");
    path_positive!(actuator_shutdown,     "/actuator/shutdown");
    path_positive!(ignition_solve,        "/_ignition/execute-solution");
    path_positive!(ignition_health,       "/_ignition/health-check");
    path_positive!(swagger_ui,            "/swagger-ui.html");
    path_positive!(swagger_json,          "/swagger.json");
    path_positive!(openapi_v3,            "/v3/api-docs");
    // 2026-05-20 FP fix — the bare GraphQL endpoint is normal API
    // traffic, NOT recon. Only introspection (`__schema` / `__type(`
    // / IntrospectionQuery) and the IDE surfaces are recon.
    path_negative!(graphql_root,          "/graphql");
    path_negative!(graphql_legit_query,   "/api/aggregator/graphql?query=%7BfindContent(brand%3A%22x%22)%7Bcontent%20__typename%7D%7D");
    path_positive!(graphql_introspection, "/graphql?query=__schema");
    path_positive!(graphql_type_introspect, "/graphql?query=__type(name:%22User%22)");
    path_positive!(graphiql_ide,          "/graphiql/");
    path_positive!(playground_ide,        "/playground");
    path_positive!(k8s_namespaces,        "/api/v1/namespaces");
    path_positive!(k8s_pods,              "/api/v1/pods");
    path_positive!(k8s_deployments,       "/apis/apps/v1/deployments");
    path_positive!(kibana_app,            "/app/kibana");
    path_positive!(kibana_search,         "/.kibana/_search");
    // 2026-05-09 — Run-7 added Kibana 7+/8+ path layouts (`/kibana/app`,
    // `/kibana/api/...`). Run-6 only had the legacy `app/kibana` form.
    path_positive!(kibana_v7_app,         "/kibana/app/dashboards");
    path_positive!(kibana_v7_api,         "/kibana/api/saved_objects/_find");
    path_positive!(elastic_cat_indices,   "/_cat/indices");
    path_positive!(elastic_cluster,       "/_cluster/health");
    path_positive!(jenkins_script,        "/script");
    path_positive!(jenkins_script_text,   "/scriptText");
    path_positive!(jenkins_cli_jar,       "/jnlpJars/jenkins-cli.jar");
    path_positive!(cgi_printenv,          "/cgi-bin/printenv.pl");
    path_positive!(cgi_test,              "/cgi-bin/test-cgi");
    path_positive!(cgi_phpcgi,            "/cgi-bin/php-cgi");
    path_positive!(prom_federate,         "/metrics?format=prometheus");
    path_positive!(prom_target_probe,     "/metrics?target=10.0.0.1:9100");
    // GAP-001b (Run-6) — bare framework discovery + Rails debug + PHP debug.
    path_positive!(actuator_bare,            "/actuator");
    path_positive!(actuator_bare_with_query, "/actuator?refresh=true");
    path_positive!(rails_info_properties,    "/rails/info/properties");
    path_positive!(rails_info_routes,        "/rails/info/routes");
    path_positive!(phpinfo_php,              "/phpinfo.php");
    path_positive!(info_php,                 "/info.php");
    path_positive!(test_php,                 "/test.php");
    path_positive!(i_php,                    "/i.php");
    path_positive!(phpinfo_php_with_query,   "/phpinfo.php?details=1");

    // 2026-05-22 FP fix — anchored admin-panel probes still fire as a
    // path segment...
    path_positive!(administrator_panel,   "/administrator/");
    path_positive!(administrator_index,   "/administrator/index.php");
    path_positive!(console_subpath,       "/console/login");
    // ...but mid-word legit paths no longer false-positive.
    path_negative!(fp_api_administrators, "/api/administrators");
    path_negative!(fp_administration,     "/users/administration");
    path_negative!(fp_console_dashboard,  "/console-dashboard");
    path_negative!(fp_my_adminer_helper,  "/myadminer-helper");
    path_negative!(fp_wp_admin_guide,     "/blog/wp-administration-tips");
    // S-F (2026-06-18 round-2) — standard browser/CMS/SDK paths that collide
    // with generic recon patterns but are NOT probes.
    // Chrome Privacy Sandbox Attribution Reporting (W3C standard) vs `/debug/`.
    path_negative!(fp_attribution_debug_verbose,
        "/.well-known/attribution-reporting/debug/verbose");
    path_negative!(fp_attribution_debug_report,
        "/.well-known/attribution-reporting/debug/report-event-attribution");
    // WordPress front-end AJAX endpoint vs the `wp-admin` panel probe.
    path_negative!(fp_wp_admin_ajax,  "/wp-admin/admin-ajax.php");
    path_negative!(fp_wp_admin_post,  "/wp-admin/admin-post.php");
    // Facebook Graph SDK plugin URLs vs the Docker `v1.NN/...plugins` probe.
    path_negative!(fp_fb_plugins_page,    "/v6.0/plugins/page.php");
    path_negative!(fp_fb_plugins_chat,    "/v5.0/plugins/customerchat.php");
    path_negative!(fp_fb_plugins_v22,     "/v2.2/plugins/page.php");

    // 2026-06-19 (btc-miss report) — recon path coverage gaps. These
    // probe shapes were FULLY-MISSED (rule=none) before; each is a
    // distinct config/secret/control-panel surface.
    // Docker Compose: override variants + Compose v2 canonical name.
    path_positive!(compose_override,      "/docker-compose.override.yml");
    path_positive!(compose_v2_yml,        "/compose.yml");
    path_positive!(compose_v2_yaml,       "/compose.yaml");
    // Rails/Symfony framework config files (segment-anchored filenames).
    path_positive!(config_database_yaml,  "/config/database.yaml");
    path_positive!(config_database_yml,   "/config/database.yml");
    path_positive!(symfony_parameters,    "/app/config/parameters.yml");
    // SQL dumps left in the webroot.
    path_positive!(sql_dump,              "/dump.sql");
    path_positive!(sql_dump_gz,           "/db.sql.gz");
    path_positive!(sql_backup,            "/backup.sql");
    // Laravel log exposure.
    path_positive!(laravel_log,           "/storage/logs/laravel.log");
    // SAP RECON (CVE-2020-6287).
    path_positive!(sap_recon,             "/developmentserver/metadatauploader");
    // MSSQL Reporting Services.
    path_positive!(ssrs_reportserver,     "/ReportServer");
    // Control Web Panel file manager (CVE-2021-45467).
    path_positive!(cwp_file_manager,      "/file-manager/initialize");
    // cPanel / WHM internal proxy.
    path_positive!(whm_proxy,             "/___proxy_subdomain_whm/login/?login_only=1");
    // ...and the FP guards: legit traffic that brushes the new tokens.
    path_negative!(fp_reports_monthly,    "/api/reports/monthly?year=2024&month=1");
    path_negative!(fp_report_pdf,         "/files/documents/report.pdf");
    path_negative!(fp_logs_api,           "/api/logs?level=error&limit=100");
    path_negative!(fp_compose_ui_js,      "/static/compose-ui/widget.js");
    path_negative!(fp_database_status,    "/api/database-status");
    path_negative!(fp_parameters_api,     "/api/parameters?env=prod");
    path_negative!(fp_file_manager_list,  "/file-manager/list");

    // ── RC-3 (2026-07-05) — genuinely-missing signature families ───────
    // Raw-form positives + look-alike negatives per family. Score stays
    // at recon::PATH (25) — no single-hit block; corpus re-validation is
    // deferred to Wave B. Raw forms only (detectors see the raw
    // percent-encoded path; never validate via the Python harness).

    // Secrets — private keys, npm/git credential files, generic secrets.*
    path_positive!(rc3_id_rsa_bare,        "/id_rsa");
    path_positive!(rc3_npmrc,              "/.npmrc");
    path_positive!(rc3_git_credentials,    "/.git-credentials");
    path_positive!(rc3_secrets_json,       "/secrets.json");
    path_positive!(rc3_secret_txt,         "/secret.txt");
    path_positive!(rc3_secrets_env,        "/secrets.env");
    path_positive!(rc3_secrets_config,     "/secrets.config");
    // ...look-alikes that must NOT fire (the RC-1 canary negatives + more).
    path_negative!(rc3_fp_id_rsa_guide,    "/id_rsa_setup_guide.html");
    path_negative!(rc3_fp_secrets_guide,   "/secrets-rotation-guide.html");
    path_negative!(rc3_fp_npmrc_example,   "/.npmrc-example");
    path_negative!(rc3_fp_secretary,       "/api/secretary/list");

    // V2 real gaps — word.env (config.env/aws.env), wp-config.txt,
    // .backup suffix, webroot archive dumps.
    path_positive!(rc3_config_env,         "/config.env");
    path_positive!(rc3_aws_env,            "/aws.env");
    path_positive!(rc3_wp_config_txt,      "/wp-config.txt");
    path_positive!(rc3_config_backup,      "/config.backup");
    path_positive!(rc3_www_targz,          "/www.tar.gz");
    path_positive!(rc3_site_zip,           "/site.zip");
    path_positive!(rc3_db_gz,              "/db.gz");
    // ...must NOT match *.environment or legit downloadable archives.
    path_negative!(rc3_fp_app_environment, "/app.environment");
    path_negative!(rc3_fp_settings_environ,"/settings.environment");
    path_negative!(rc3_fp_asset_js_gz,     "/assets/app.js.gz");
    path_negative!(rc3_fp_report_zip,      "/downloads/report.zip");
    path_negative!(rc3_fp_photos_zip,      "/albums/holiday-photos.zip");

    // Exchange / ProxyShell — the .json autodiscover SSRF vector and
    // product login pages. The legit .xml autodiscover (hit by every
    // Outlook client) must NOT fire.
    path_positive!(rc3_autodiscover_json,  "/autodiscover/autodiscover.json?@evil.com/x");
    path_positive!(rc3_owa_logon,          "/owa/auth/logon.aspx");
    path_positive!(rc3_manageengine_login, "/Core/Skin/Login.aspx");
    path_negative!(rc3_fp_autodiscover_xml,"/autodiscover/autodiscover.xml");
    path_negative!(rc3_fp_logon_history,   "/api/logon-history?user=1");

    // WordPress — abused wp-json subpaths, enumeration manifest, xmlrpc.
    // Bare /wp-json/ and legit REST collections must NOT fire.
    path_positive!(rc3_wpjson_gravitysmtp, "/wp-json/gravitysmtp/v1/settings");
    path_positive!(rc3_wpjson_settings,    "/wp-json/wp/v2/settings");
    path_positive!(rc3_wlwmanifest,        "/wlwmanifest.xml");
    path_positive!(rc3_xmlrpc,             "/xmlrpc.php");
    path_negative!(rc3_fp_wpjson_root,     "/wp-json/");
    path_negative!(rc3_fp_wpjson_posts,    "/wp-json/wp/v2/posts?per_page=10");
    path_negative!(rc3_fp_xmlrpc_guide,    "/blog/xmlrpc-guide.html");

    // Misc — Jenkinsfile, Jenkins job config.xml, Terraform working dir.
    path_positive!(rc3_jenkinsfile,        "/Jenkinsfile");
    path_positive!(rc3_jenkins_config,     "/jenkins/config.xml");
    path_positive!(rc3_jenkins_job_config, "/jenkins/job/main/config.xml");
    path_positive!(rc3_terraform_dir,      "/.terraform/terraform.tfstate");
    // ...bare config.xml is too generic to flag; look-alikes must not fire.
    path_negative!(rc3_fp_bare_config_xml, "/config.xml");
    path_negative!(rc3_fp_jenkinsfile_view,"/JenkinsfileViewer");
    path_negative!(rc3_fp_terraform_guide, "/my.terraform-guide");

    // ── L-tester run (2026-06-21) recon-path FP sweep ──────────────────
    // 165 normal requests fired recon-path. Root causes + guards below.

    // (a) Jenkins `/script` + `/manage` token was only `\b`-bounded, so it
    // fired on JS assets, tag-manager routes, and app `/manage` pages.
    // `/script(Text)?` is now anchored to a full path segment (end/query)
    // and bare `/manage` was dropped (too generic). These must NOT fire:
    path_negative!(fp_script_asset_js,     "/cdn/shop/t/37/assets/script.js");
    path_negative!(fp_script_tag_route,    "/api/tag/script/4af34feb-fa17-4bbf-afd4-61e6d2a8819b/null");
    path_negative!(fp_script_min_js,       "/pub/static/version1704626446/frontend/Foxhome/js/script.js");
    path_negative!(fp_script_subpath,      "/merchant/script/welcome");
    path_negative!(fp_script_tag_dash_js,  "/api/script-tag.js");
    path_negative!(fp_manage_account,      "/account/manage");
    path_negative!(fp_manage_user_subpath, "/gateway/api/users/712020:abc/manage/linked-accounts");
    path_negative!(fp_manage_suppliers,    "/manage/c/suppliers");
    // ...including recon tokens carried INSIDE decoded redirect/analytics
    // params (GA4 `dl=`, Wix `ref=`) — the detector sees these decoded:
    path_negative!(fp_ga_collect_manage_dl, "/g/collect?v=2&tid=G-X&dl=https://pro.houzz.com/manage/moodboards/208003397");
    path_negative!(fp_wix_pa_manage_ref,    "/pa?src=76&ref=https://manage.wix.com/&url=https://koalaocbuu.wixsite.com/lk-shop");
    path_negative!(fp_ga_collect_script_dl, "/g/collect?v=2&tid=G-X&dl=https://script.google.com/u/0/home/projects/abc/edit");

    // (b) Tilde editor-backup token `~$` was anchored to the end of the
    // whole path+query, so any URL whose query ends in `~` fired. Analytics
    // pixels (GA `__utm.gif`, SHEIN tracking) must NOT fire:
    path_negative!(fp_ga_utm_gif_tilde,    "/__utm.gif?utmwv=5.7.2&utmn=1239772308&utmu=6AAAAAAAAAAAAAAAAAAAAAAE~");
    path_negative!(fp_shein_tracking_tilde,"/SHEIN-Top-p-2407558-cat-1733.html?scici=WomenHomePage~~ON_Banner~~7_4~~~~");

    // (c) `/debug/` was too generic; narrowed to the Go pprof/vars surface.
    // App debug routes + Chrome Privacy Sandbox debug endpoints must NOT fire:
    path_negative!(fp_api_debug_logs,      "/api/v4/debug/logs");
    path_negative!(fp_private_agg_debug,   "/.well-known/private-aggregation/debug/report-shared-storage");

    // (d) `.env` is now segment-anchored — `.Env.` inside a JSONP callback
    // (YUI.Env.JSONP) must NOT fire:
    path_negative!(fp_yui_env_jsonp,       "/ajax/viewer?p=Wimbledon&callback=YUI.Env.JSONP.yui_3_8_0_1");

    // (e) `web.config` is now segment-anchored — mid-filename `_web.Config…`
    // must NOT fire:
    path_negative!(fp_web_config_midword,  "/slipstream/grp/v1/custom/public/acorn/config_pre_page_landing/config_fare_families_web.ConfigPrePageLanding");

    // (f) WordPress static front-end assets under /wp-admin/ loaded by every
    // anonymous visitor must NOT fire the wp-admin panel probe:
    path_negative!(fp_wp_admin_js_asset,   "/wp-admin/js/password-strength-meter.min.js?ver=6.0");

    // ── Pins: real probes that MUST still fire after the anchoring ──────
    path_positive!(jenkins_script_query,   "/script?a=1");
    path_positive!(go_pprof_heap,          "/debug/pprof/heap");
    path_positive!(env_in_subdir,          "/app/.env");
    path_positive!(wp_admin_panel_probe,   "/wp-admin/");

    // UA-based positive tests.
    macro_rules! ua_positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = ReconDetector;
                let (m, u, h, b) = view_with_ua($input);
                let req = make_view(&m, &u, &h, &b);
                let s = d.inspect(&req);
                assert!(s.iter().any(|s| s.tag == "recon_tool"), "expected recon_tool for UA: {}", $input);
            }
        };
    }

    ua_positive!(ua_sqlmap, "sqlmap/1.5");
    ua_positive!(ua_nikto, "Nikto/2.1.6");
    ua_positive!(ua_nmap, "Nmap Scripting Engine");
    ua_positive!(ua_dirbuster, "DirBuster-1.0");
    ua_positive!(ua_gobuster, "gobuster/3.1");
    ua_positive!(ua_feroxbuster, "feroxbuster/2.7");
    ua_positive!(ua_wfuzz, "Wfuzz/3.1");
    ua_positive!(ua_ffuf, "Fuzz Faster U Fool (ffuf)");
    ua_positive!(ua_nuclei, "Nuclei/2.8");
    ua_positive!(ua_burp, "Burp Suite");
    ua_positive!(ua_zap, "OWASP ZAP");
    ua_positive!(ua_acunetix, "Acunetix");
    ua_positive!(ua_nessus, "Nessus/10");
    ua_positive!(ua_openvas, "OpenVAS");
    ua_positive!(ua_wpscan, "WPScan v3");
    ua_positive!(ua_masscan, "masscan/1.3");

    // Negative tests.
    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = ReconDetector;
                let (m, u, h, b) = view_with_path($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    negative!(clean_root, "/");
    negative!(clean_api, "/api/users");
    negative!(clean_products, "/products/123");
    negative!(clean_static, "/static/main.js");
    negative!(clean_health, "/health");
    negative!(clean_metrics, "/metrics");
    negative!(clean_images, "/images/logo.png");
    negative!(clean_css, "/css/style.css");
    negative!(clean_robots, "/robots.txt");
    negative!(clean_sitemap, "/sitemap.xml");
    negative!(clean_blog, "/blog/post-1");
    negative!(clean_auth, "/auth/login");
    negative!(clean_docs, "/docs/getting-started");
    negative!(clean_page, "/page?id=1");
    negative!(clean_feed, "/feed.xml");
    negative!(clean_manifest, "/manifest.json");
    negative!(clean_sw, "/sw.js");
    negative!(clean_favicon, "/favicon.ico");
    // SEC-L001 — version-shaped paths that aren't Docker REST.
    // The Docker pattern matches /v\d+\.\d+/{namespace} only when
    // namespace is in the allowlist; bare /v1/users etc. don't fire.
    negative!(clean_v1_users,            "/v1/users");
    negative!(clean_semver_v2_1,         "/api/v2.1/products");
    negative!(clean_static_versioned,    "/static/v1.5/app.js");
    negative!(clean_webhook, "/webhooks/github");
    negative!(clean_download, "/download/report.pdf");
    // GAP-001 (Run-5) — operator-hosted endpoints that must NOT FP.
    // /actuator/health and /actuator/info are intentionally public on
    // most Spring Boot deployments — only the dangerous subpaths flag.
    negative!(clean_actuator_health,   "/actuator/health");
    negative!(clean_actuator_info,     "/actuator/info");
    negative!(clean_bare_metrics,      "/metrics");
    negative!(clean_metrics_legit,     "/metrics?accept=text/plain");
    negative!(clean_kibana_substring,  "/api/kibana-feedback");
    negative!(clean_graphql_substr,    "/graphqlproxy");
    // GAP-001b (Run-6) — must NOT FP on these operator-controlled
    // and look-alike paths.
    negative!(clean_actuator_with_subpath, "/actuator/health");        // already covered above; explicit here to pin GAP-001b doesn't break it
    negative!(clean_actuator_info_subpath, "/actuator/info");          // operator-hosted
    negative!(clean_rails_app_path,        "/rails/api/users");        // legitimate Rails app path that happens to start with /rails/
    negative!(clean_index_php,             "/index.php");              // common PHP entry point — too generic to flag
    negative!(clean_app_php,               "/app.php");                // common PHP entry — must not flag
    negative!(clean_phpinfo_substring,     "/api/phpinfocard");        // contains phpinfo as substring but not as filename
    negative!(clean_test_dir,              "/test/results");           // /test/ as directory, not test.php
    // VULN-03 (waf_security_report 2026-06-10) — the widened config /
    // key coverage must NOT FP on legit traffic. Pins the segment +
    // value-boundary anchors and the .crt/.cer exclusion.
    negative!(clean_data_json,             "/api/data.json");          // legit JSON API surface — blanket *.json rule rejected
    negative!(clean_config_guide,          "/docs/config-guide");      // "config" substring, no .yaml file
    negative!(clean_reconfigure,           "/reconfigure-status");     // ends in "figure", not "config.yaml" — segment anchor holds
    negative!(clean_public_key_info,       "/public-key-info");        // "key" substring, no .key extension boundary
    negative!(clean_monkey_html,           "/monkey.html");            // "key" inside word, .html not .key
    negative!(clean_style_css,             "/style.css");              // unrelated extension
    negative!(clean_public_cert,           "/ca.crt");                 // public cert — deliberately NOT flagged
    negative!(clean_public_cert_cer,       "/chain.cer");              // public cert — deliberately NOT flagged
}
