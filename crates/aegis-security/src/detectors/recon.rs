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
        r"(?i)(?:wp-admin)",
        r"(?i)(?:wp-login)",
        r"(?i)(?:administrator)",
        r"(?i)(?:phpmyadmin)",
        r"(?i)(?:adminer)",
        r"(?i)(?:/debug/)",
        r"(?i)(?:/console)",
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
        r"(?i)(?:^|/)v\d+\.\d+/(?:containers|images|networks|volumes|services|tasks|secrets|configs|swarm|nodes|plugins|info|version|events|system|build|auth)\b",
        r"(?i)(?:^|/)_ping\b",
        r"(?i)(?:Makefile$)",
        r"(?i)(?:\.aws/credentials)",
        r"(?i)(?:\.ssh/)",
        // GAP-001 (Run-5, 2026-05-08) — framework recon paths.
        // Spring Boot actuator danger endpoints (/health and /info
        // are intentionally public on most Spring deployments;
        // only the dangerous subpaths flag).
        r"(?i)/actuator/(?:heapdump|threaddump|env|configprops|loggers|trace|httptrace|auditevents|dump|jolokia|liquibase|flyway|gateway|conditions|beans|mappings|metrics/.*|sessions|shutdown)\b",
        // Laravel Ignition — CVE-2021-3129 (RCE).
        r"(?i)/_ignition/(?:execute-solution|health-check|update-config)\b",
        // Swagger / OpenAPI surface enumeration.
        r"(?i)/(?:swagger-ui\.html|swagger\.json|swagger\.yaml|v\d+/api-docs|api-docs|openapi\.json|openapi\.yaml)\b",
        // GraphQL introspection / playground — usually disabled
        // in prod. Operators with intentional public GraphQL can
        // disable this class via `set_profile`.
        r"(?i)/graphql(?:/|\?|$)",
        r"(?i)/graphiql(?:/|\?|$)",
        r"(?i)/playground(?:/|\?|$)",
        // Kubernetes API namespaces / pods / deployments.
        r"(?i)/api/v1/namespaces\b",
        r"(?i)/api/v1/pods\b",
        r"(?i)/apis/apps/v1/deployments\b",
        // Kibana / Elastic internals.
        r"(?i)/(?:app/kibana|\.kibana(?:/|/_search)|_cat/indices|_cluster/health)\b",
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

impl Detector for ReconDetector {
    fn id(&self) -> &'static str {
        "recon"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

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
    path_positive!(graphql_root,          "/graphql");
    path_positive!(graphql_query,         "/graphql?query=__schema");
    path_positive!(graphiql_ide,          "/graphiql/");
    path_positive!(playground_ide,        "/playground");
    path_positive!(k8s_namespaces,        "/api/v1/namespaces");
    path_positive!(k8s_pods,              "/api/v1/pods");
    path_positive!(k8s_deployments,       "/apis/apps/v1/deployments");
    path_positive!(kibana_app,            "/app/kibana");
    path_positive!(kibana_search,         "/.kibana/_search");
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
}
