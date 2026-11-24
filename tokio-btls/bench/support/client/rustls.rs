//! tokio-rustls adapter: rustls with the aws-lc-rs provider.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName, TlsConnector};

use super::ClientAdapter;
use crate::{
    rustls_benchmark,
    support::{case::Tls, BoxError},
};

/// Stateless adapter for the tokio-rustls client stream.
pub(super) struct Adapter;

// ===== impl Adapter =====

impl ClientAdapter for Adapter {
    type Connector = TlsConnector;
    type Stream<S>
        = TlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send;

    const NAME: &'static str = "tokio-rustls";
    const TLS: Tls = Tls::Enabled;

    fn connector() -> Result<Self::Connector, BoxError> {
        Ok(rustls_benchmark::connector()?)
    }

    async fn connect<S>(
        connector: &Self::Connector,
        transport: S,
    ) -> Result<Self::Stream<S>, BoxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let server_name = ServerName::try_from("localhost")?;
        Ok(connector.connect(server_name, transport).await?)
    }
}
