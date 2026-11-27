//! Exercise the actual TLS implementation, not just a build-script invocation.
use btls::ssl::{Ssl, SslContextBuilder, SslMethod};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = SslContextBuilder::new(SslMethod::tls())?.build();
    let ssl = Ssl::new(&context)?;
    std::hint::black_box(ssl);
    Ok(())
}
