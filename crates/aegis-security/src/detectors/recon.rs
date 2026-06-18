use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// Reconnaissance detector: directory scanning, known tools, probing.
pub struct ReconDetector;

static RECON_PATHS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:\.env(?:\.|$))",
        r"(?i)(?:\.git(?:/|$))",
        r"(?i)(?:\.svn(?:/|$))",
        r"(?i)(?:\.hg(?:/|$))",
        r"(?i)(?:\.DS_Store)",
        r"(?i)(?:\.htaccess)",
        r"(?i)(?:\.htpasswd)",
        r"(?i)(?:wp-config\.php)",
        r"(?i)(?:web\.config)",
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
        r"(?i)(?:/debug/)",
        r"(?i)(?:/console)(?:$|[/?])",
        r"(?i)(?:elmah\.axd)",
        r"(?i)(?:trace\.axd)",
        r"(?i)(?:server-status)",
        r"(?i)(?:server-info)",
        r"(?i)(?:backup\.(?:sql|zip|tar|gz|bak))",
        r"(?i)(?:database\.(?:sql|dump))",
        r"(?i)(?:\.(?:bak|old|orig|save|swp|tmp)$)",
        r"(?i)(?:~$)",
        r"(?i)(?:Dockerfile)",
        r"(?i)(?:docker-compose\.ya?ml)",
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
        r"(?i)/(?:script(?:Text)?|jnlpJars/jenkins-cli\.jar|manage|computer/(?:\(master\)|\(built-in\))/script)\b",
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
        // WordPress front-end AJAX endpoints — hit by every visitor; the
        // `wp-admin` panel-probe pattern otherwise fires.
        || path.ends_with("/admin-ajax.php")
        || path.ends_with("/admin-post.php")
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
