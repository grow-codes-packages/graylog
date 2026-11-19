//! rustls client configuration from the common [`TlsConfig`] (GELF TCP over TLS).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::core::{Error, Result, TlsConfig};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts every server certificate (`insecure_skip_verify`, tests only); signatures are still
/// checked.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn read(path: &std::path::Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        Error::config(format!("{what} file {} cannot be read", path.display())).with_source(e)
    })
}

fn pem_certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::config(format!("{what} is not valid PEM")))?;
    if certs.is_empty() {
        return Err(Error::config(format!("{what} contains no certificate")));
    }
    Ok(certs)
}

/// Builds a rustls client config: system roots plus the configured CA, an optional client
/// certificate, and `insecure_skip_verify`.
pub(crate) fn client_config(tls: &TlsConfig) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config("TLS setup failed").with_source(e))?;
    let builder = if tls.insecure_skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
    } else {
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let mut extra = Vec::new();
        if let Some(p) = &tls.ca_cert_path {
            extra.extend(read(p, "CA certificate")?);
            extra.push(b'\n');
        }
        if let Some(pem) = &tls.ca_cert_pem {
            extra.extend_from_slice(pem.as_bytes());
        }
        if !extra.is_empty() {
            for cert in pem_certs(&extra, "CA certificate")? {
                roots
                    .add(cert)
                    .map_err(|e| Error::config("CA certificate is not valid").with_source(e))?;
            }
        }
        builder.with_root_certificates(roots)
    };
    let config = match (&tls.client_cert_path, &tls.client_key_path) {
        (Some(cert), Some(key)) => {
            let certs = pem_certs(&read(cert, "client certificate")?, "client certificate")?;
            let key = PrivateKeyDer::from_pem_slice(&read(key, "client key")?)
                .map_err(|_| Error::config("client key is not valid PEM"))?;
            builder.with_client_auth_cert(certs, key).map_err(|e| {
                Error::config("client certificate or key is not valid").with_source(e)
            })?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// The TLS server name for `host` (DNS name or IP address).
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_owned())
        .map_err(|_| Error::config(format!("{host:?} is not a valid TLS server name")))
}
