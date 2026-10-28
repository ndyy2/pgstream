use std::sync::Arc;

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test]
async fn test_notls_connect() {
    // Test 1: Try NoTls
    // Set PGSTREAM_TEST_URL=host=... user=... password=... dbname=... to run this test.
    let url = std::env::var("PGSTREAM_TEST_URL").unwrap_or_else(|_| "host=invalid.invalid dbname=skip_test".into());
    match tokio_postgres::connect(url, tokio_postgres::NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(async move { let _ = connection.await; });
            let row = client.query_one("SELECT 1+1 AS result", &[]).await.unwrap();
            let val: i32 = row.get(0);
            println!("NoTls SUCCESS: 1+1 = {}", val);
        }
        Err(e) => {
            println!("NoTls FAILED: {}", e);
        }
    }
}

#[tokio::test]
async fn test_tls_connect_keyvalue() {
    // Test 2: Try TLS with key=value config instead of URL
    let provider = rustls::crypto::ring::default_provider();
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);
    let cfg = format!(
        "{} sslmode=require",
        std::env::var("PGSTREAM_TEST_URL").unwrap_or_else(|_| "host=invalid.invalid dbname=skip_test".into())
    );

    match tokio_postgres::connect(cfg, connector).await {
        Ok((client, connection)) => {
            tokio::spawn(async move { let _ = connection.await; });
            let row = client.query_one("SELECT 1+1 AS result", &[]).await.unwrap();
            let val: i32 = row.get(0);
            println!("TLS key=value SUCCESS: 1+1 = {}", val);
        }
        Err(e) => {
            println!("TLS key=value FAILED: {} (source: {:?})", e, std::error::Error::source(&e));
        }
    }
}
