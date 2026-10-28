use rustls::ClientConfig;
use tokio_postgres_rustls::MakeRustlsConnect;

#[test]
fn test_tls_config_build() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let _connector = MakeRustlsConnect::new(tls_config);
}
