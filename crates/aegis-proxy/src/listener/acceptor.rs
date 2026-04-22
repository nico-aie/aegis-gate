use std::net::SocketAddr;

use aegis_core::config::WafConfig;

/// A bound data-plane listener ready to accept connections.
pub struct BoundListener {
    pub listener: tokio::net::TcpListener,
    pub addr: SocketAddr,
    pub tls: bool,
}

/// Bind **only** the data-plane sockets defined in `cfg.listeners.data`.
///
/// The admin listener (`cfg.listeners.admin`) is intentionally excluded —
/// that address is owned by `aegis-control`.
pub async fn build_listeners(cfg: &WafConfig) -> aegis_core::Result<Vec<BoundListener>> {
    let mut listeners = Vec::with_capacity(cfg.listeners.data.len());

    for lc in &cfg.listeners.data {
        let tcp = tokio::net::TcpListener::bind(lc.bind).await?;
        let local = tcp.local_addr()?;
        tracing::info!("data-plane bound on {local}");
        listeners.push(BoundListener {
            listener: tcp,
            addr: local,
            tls: lc.tls,
        });
    }

    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_data_ports(ports: &[&str]) -> WafConfig {
        let data_yaml: String = ports
            .iter()
            .map(|p| format!("    - bind: \"{p}\""))
            .collect::<Vec<_>>()
            .join("\n");

        let yaml = format!(
            r#"
listeners:
  data:
{data_yaml}
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[tokio::test]
    async fn build_listeners_returns_data_plane_only() {
        let cfg = cfg_with_data_ports(&["127.0.0.1:0", "127.0.0.1:0"]);
        let admin_bind = cfg.listeners.admin.bind;

        let listeners = build_listeners(&cfg).await.unwrap();

        // Exactly the data-plane count.
        assert_eq!(listeners.len(), 2);

        // None of the bound addresses match the admin address.
        for bl in &listeners {
            assert_ne!(bl.addr, admin_bind);
        }
    }

    #[tokio::test]
    async fn build_listeners_single_port() {
        let cfg = cfg_with_data_ports(&["127.0.0.1:0"]);
        let listeners = build_listeners(&cfg).await.unwrap();
        assert_eq!(listeners.len(), 1);
    }

    #[tokio::test]
    async fn build_listeners_tls_flag_propagated() {
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
      tls: true
    - bind: "127.0.0.1:0"
      tls: false
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let listeners = build_listeners(&cfg).await.unwrap();
        assert_eq!(listeners.len(), 2);
        assert!(listeners[0].tls);
        assert!(!listeners[1].tls);
    }
}
