//! Plaintext adapter: the bare transport, a TCP baseline below both TLS stacks.

use tokio::io::{AsyncRead, AsyncWrite};

use super::ClientAdapter;
use crate::support::{case::Tls, BoxError};

/// Stateless adapter that hands the transport back unchanged.
pub(super) struct Adapter;

impl ClientAdapter for Adapter {
    type Connector = ();
    type Stream<S>
        = S
    where
        S: AsyncRead + AsyncWrite + Unpin + Send;

    const NAME: &'static str = "plaintext";
    const TLS: Tls = Tls::Disabled;

    fn connector() -> Result<Self::Connector, BoxError> {
        Ok(())
    }

    fn connect<S>(
        (): &Self::Connector,
        transport: S,
    ) -> impl std::future::Future<Output = Result<Self::Stream<S>, BoxError>> + Send
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        std::future::ready(Ok(transport))
    }
}
