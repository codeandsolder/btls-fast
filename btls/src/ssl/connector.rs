use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ex_data::IndexSlot;
use crate::ffi;
use crate::ssl::{
    HandshakeError, NameType, Ssl, SslContext, SslContextBuilder, SslContextRef, SslMethod,
    SslMode, SslRef, SslSession, SslSessionRef, SslStream, SslVerifyMode, SslVersion,
};
use crate::util::catch_native;
use std::net::IpAddr;

use super::MidHandshakeSslStream;
use super::callbacks::raw_new_session;

pub(super) static NEW_SESSION_INDEX: IndexSlot<SslContext, NewSessionCallback> =
    IndexSlot::new(SslContext::new_ex_index);
pub(super) static SESSION_PEER_INDEX: IndexSlot<Ssl, SessionPeer> =
    IndexSlot::new(Ssl::new_ex_index);
static CLIENT_SESSION_OFFER_INDEX: IndexSlot<Ssl, SessionAuthentication> =
    IndexSlot::new(Ssl::new_ex_index);

fn ctx(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
    let mut ctx = SslContextBuilder::new(method)?;

    // BoringSSL already enables SSL_OP_ALL by default. The remaining OpenSSL
    // compatibility flags used here had a literal value of zero, so configure
    // only the two write modes that change the native behavior.
    ctx.set_mode(SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE);

    Ok(ctx)
}

/// A type which wraps client-side streams in a TLS session.
///
/// Configures `BoringSSL` cipher suites, session options, certificate verification,
/// and hostname verification. Certificate verification is enabled by default,
/// including when the caller provides its own trust store.
#[derive(Clone, Debug)]
pub struct SslConnector(SslContext);

impl SslConnector {
    /// Creates a new builder for TLS connections.
    ///
    /// The default configuration is subject to change, and is currently derived from Python.
    ///
    /// # Errors
    ///
    /// Native context creation, CA-path initialization, or cipher configuration fails.
    pub fn builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut builder = Self::bare_builder(method)?;
        builder.set_default_verify_paths()?;
        Ok(builder)
    }

    /// Creates a bare builder for TLS connections without default CA certificates.
    ///
    /// Peer and hostname verification remain enabled. The caller must provide
    /// a custom trust store or explicitly configure another verification policy.
    ///
    /// # Errors
    ///
    /// Native context creation, cipher configuration, or X.509 verification setup fails.
    pub fn bare_builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        // These are supported native selectors. BoringSSL has no anonymous,
        // NULL, MD5, DES, RC4, IDEA, SEED, DSS or SRP cipher suites.
        ctx.set_cipher_list("DEFAULT:!3DES:!aPSK")?;
        ctx.set_verify_mode(SslVerifyMode::PEER)?;

        Ok(SslConnectorBuilder(ctx))
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI and hostname verification.
    ///
    /// # Errors
    ///
    /// The SSL connection cannot be configured or attached to the stream.
    pub fn setup_connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        self.configure()?.setup_connect(domain, stream)
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Errors
    ///
    /// Connection setup or the TLS handshake fails.
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Returns a structure allowing for configuration of a single TLS session before connection.
    ///
    /// # Errors
    ///
    /// A new native SSL connection cannot be allocated.
    pub fn configure(&self) -> Result<ConnectConfiguration, ErrorStack> {
        Ssl::new(&self.0).map(|ssl| ConnectConfiguration {
            ssl,
            sni: true,
            verify_hostname: true,
            session: None,
        })
    }

    /// Consumes the `SslConnector`, returning the inner raw `SslContext`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslConnector`s.
pub struct SslConnectorBuilder(SslContextBuilder);

impl SslConnectorBuilder {
    /// Consumes the builder, returning an `SslConnector`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> SslConnector {
        SslConnector(self.0.build())
    }

    /// Sets the callback which receives sessions for [`ConnectConfiguration::set_client_session`].
    ///
    /// Client session caching is enabled. Only connections created by
    /// [`ConnectConfiguration::into_ssl`] report sessions. This shares BoringSSL's new session
    /// callback with [`SslContextBuilder::set_new_session_callback`]; the last one set wins.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    #[corresponds(SSL_CTX_sess_set_new_cb)]
    pub fn set_client_session_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, ClientSession) + 'static + Sync + Send,
    {
        let callback = ClientSessionCallback {
            issuer: Arc::new(()),
            callback: Box::new(callback),
        };
        self.set_ex_data(
            NEW_SESSION_INDEX.register()?,
            NewSessionCallback::Checked(callback),
        )?;
        // SAFETY: the builder owns a live native context for each session-cache
        // configuration call, and the callback is a static C-ABI function.
        unsafe {
            let mode =
                ffi::SSL_CTX_get_session_cache_mode(self.as_ptr()) | ffi::SSL_SESS_CACHE_CLIENT;
            ffi::SSL_CTX_set_session_cache_mode(self.as_ptr(), mode);
            ffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), Some(raw_new_session));
        }
        Ok(())
    }
}

impl Deref for SslConnectorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslConnectorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

/// A type which allows for configuration of a client-side TLS session before connection.
pub struct ConnectConfiguration {
    ssl: Ssl,
    sni: bool,
    verify_hostname: bool,
    session: Option<ClientSession>,
}

/// A client session and the connection it was issued on.
///
/// Sessions come from [`SslConnectorBuilder::set_client_session_callback`].
/// [`ConnectConfiguration::set_client_session`] offers a session only to the same
/// domain and SNI use, with no stronger hostname or peer verification request,
/// and the same nonempty [session ID context](SslContextBuilder::set_session_id_context)
/// or, without one, the same originating session callback registration, even
/// if the current TLS context was changed. The built-in X.509 authentication
/// policy is revalidated against the current store and parameters immediately
/// before the session is offered, including changes made after `into_ssl`.
/// A rejected session falls back to a full handshake.
///
/// The checked path applies to built-in X.509 authentication without custom
/// verification or OCSP callbacks, PSKs, or client authentication credentials.
/// Applications using those policies must explicitly establish session
/// authentication with [`SslRef::set_session`] instead.
#[derive(Clone)]
pub struct ClientSession {
    session: SslSession,
    authentication: SessionAuthentication,
}

/// The policy metadata is independent of native session ownership. When a
/// session is offered, only this metadata needs to remain in connection ex-data.
#[derive(Clone)]
struct SessionAuthentication {
    peer: SessionPeer,
    verify_peer: bool,
    issuer: Arc<()>,
}

/// Domain, SNI, and hostname verification of a connection created by
/// [`ConnectConfiguration::into_ssl`].
#[derive(Clone)]
pub(super) struct SessionPeer {
    domain: Arc<str>,
    sni: bool,
    verify_hostname: bool,
    builtin_authentication: bool,
}

impl SessionPeer {
    fn matches_sni(&self, ssl: &SslRef) -> bool {
        let actual = ssl.servername_raw(NameType::HOST_NAME);
        if self.sni {
            actual.is_some_and(|name| name.eq_ignore_ascii_case(self.domain.as_bytes()))
        } else {
            actual.is_none()
        }
    }
}

type ClientSessionFn = dyn Fn(&mut SslRef, ClientSession) + Sync + Send;

/// Client session callback, boxed so connections can find it without knowing its type.
///
/// The issuer token identifies the context without keeping it alive.
pub(super) struct ClientSessionCallback {
    issuer: Arc<()>,
    pub(super) callback: Box<ClientSessionFn>,
}

type RawSessionFn = dyn Fn(&mut SslRef, SslSession) + Sync + Send;

// The native new-session callback has exactly one registration. Raw and
// checked notification must replace each other, not retain parallel state.
pub(super) enum NewSessionCallback {
    Raw(Box<RawSessionFn>),
    Checked(ClientSessionCallback),
}

impl NewSessionCallback {
    const fn checked(&self) -> Option<&ClientSessionCallback> {
        match self {
            Self::Raw(_) => None,
            Self::Checked(callback) => Some(callback),
        }
    }
}

impl ClientSessionCallback {
    pub(super) fn issue(
        &self,
        session: SslSession,
        mut peer: SessionPeer,
        ssl: &SslRef,
    ) -> ClientSession {
        peer.builtin_authentication &= builtin_authentication(ssl) && peer.matches_sni(ssl);
        let verify_peer = peer.builtin_authentication && verifies_peer(ssl);
        ClientSession {
            session,
            authentication: SessionAuthentication {
                peer,
                verify_peer,
                issuer: Arc::clone(&self.issuer),
            },
        }
    }
}

impl ClientSession {
    /// Returns the underlying session.
    #[must_use = "Use the returned session reference to inspect the resumption state."]
    pub fn session(&self) -> &SslSessionRef {
        &self.session
    }
}

impl SessionAuthentication {
    /// Reject incompatible identities and policies before native chain validation.
    /// Certificate time, trust and other verification parameters are evaluated
    /// exclusively by the final native verifier.
    fn permits(
        &self,
        session: &SslSessionRef,
        ssl: &SslRef,
        domain: &str,
        sni: bool,
        verify_hostname: bool,
    ) -> bool {
        if !self.peer.builtin_authentication || !builtin_authentication(ssl) {
            return false;
        }
        let scope = session.id_context();
        let verify_peer = verifies_peer(ssl);
        ssl.session_id_context() == Some(scope)
            && (!scope.is_empty()
                || issuer(ssl.session_context())
                    .is_some_and(|issuer| Arc::ptr_eq(&self.issuer, issuer)))
            && self.peer.domain.eq_ignore_ascii_case(domain)
            && self.peer.sni == sni
            && (self.peer.verify_hostname || !verify_hostname)
            && (self.verify_peer || !verify_peer)
    }
}

fn builtin_authentication(ssl: &SslRef) -> bool {
    // SAFETY: the live SSL is borrowed; the native predicate checks its configuration.
    unsafe { ffi::SSL_client_session_uses_builtin_authentication(ssl.as_ptr()) != 0 }
}

unsafe extern "C" fn validate_client_session(
    ssl: *const ffi::SSL,
    session: *const ffi::SSL_SESSION,
) -> libc::c_int {
    catch_native(|| {
        // SAFETY: the native validation callback borrows live SSL and session
        // objects for the duration of this call, before constructing ClientHello.
        let (ssl, session) = unsafe {
            (
                SslRef::from_ptr(ssl.cast_mut()),
                SslSessionRef::from_ptr(session.cast_mut()),
            )
        };
        let Some(peer) = ssl.slot_data(&SESSION_PEER_INDEX) else {
            return 0;
        };
        let Some(authentication) = ssl.slot_data(&CLIENT_SESSION_OFFER_INDEX) else {
            return 0;
        };
        if !peer.matches_sni(ssl)
            || !authentication.permits(session, ssl, &peer.domain, peer.sni, peer.verify_hostname)
        {
            return 0;
        }
        // SAFETY: native verification uses the borrowed immutable session and
        // current SSL configuration, without invoking application callbacks.
        unsafe { ffi::SSL_check_client_session_x509(ssl.as_ptr(), session.as_ptr()) }
    })
    .unwrap_or(0)
}

/// Returns the registration identity of a checked session notification callback.
fn issuer(context: &SslContextRef) -> Option<&Arc<()>> {
    context
        .slot_data(&NEW_SESSION_INDEX)
        .and_then(NewSessionCallback::checked)
        .map(|callback| &callback.issuer)
}

/// Returns whether `ssl` verifies the peer certificate; an unavailable mode counts as not.
fn verifies_peer(ssl: &SslRef) -> bool {
    // SAFETY: `ssl` is a valid connection; BoringSSL returns -1 when its configuration is gone.
    let mode = unsafe { ffi::SSL_get_verify_mode(ssl.as_ptr()) };
    mode >= 0 && SslVerifyMode::from_bits_retain(mode).contains(SslVerifyMode::PEER)
}

impl ConnectConfiguration {
    /// A builder-style version of `set_use_server_name_indication`.
    #[must_use = "Retain the returned configuration; this builder operation consumes the original."]
    pub const fn use_server_name_indication(mut self, use_sni: bool) -> Self {
        self.set_use_server_name_indication(use_sni);
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Defaults to `true`.
    pub const fn set_use_server_name_indication(&mut self, use_sni: bool) {
        self.sni = use_sni;
    }

    /// A builder-style version of `set_verify_hostname`.
    #[must_use = "Retain the returned configuration; this builder operation consumes the original."]
    pub const fn verify_hostname(mut self, verify_hostname: bool) -> Self {
        self.set_verify_hostname(verify_hostname);
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname verification is not
    /// used, *any* valid certificate for *any* site will be trusted for use from any other. This
    /// introduces a significant vulnerability to man-in-the-middle attacks.
    pub const fn set_verify_hostname(&mut self, verify_hostname: bool) {
        self.verify_hostname = verify_hostname;
    }

    /// A builder-style version of `set_client_session`.
    #[must_use = "Retain the returned configuration; this builder operation consumes the original."]
    pub fn client_session(mut self, session: ClientSession) -> Self {
        self.set_client_session(session);
        self
    }

    /// Offers a session for resumption.
    ///
    /// An incompatible session is discarded during setup or at handshake start
    /// as described on [`ClientSession`]; the handshake then proceeds without resumption.
    pub fn set_client_session(&mut self, session: ClientSession) {
        self.session = Some(session);
    }

    /// Returns an [`Ssl`] configured to connect to the provided domain.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// # Errors
    ///
    /// The domain cannot be configured, extra-data allocation fails, or session installation fails.
    pub fn into_ssl(mut self, domain: &str) -> Result<Ssl, ErrorStack> {
        let sni = self.sni && domain.parse::<IpAddr>().is_err();
        if sni {
            self.ssl.set_hostname(domain)?;
        }

        if self.verify_hostname {
            setup_verify_hostname(&mut self.ssl, domain)?;
        }

        let reports_sessions = issuer(self.ssl.session_context()).is_some();
        let session = self.session.take().filter(|session| {
            session.authentication.permits(
                &session.session,
                &self.ssl,
                domain,
                sni,
                self.verify_hostname,
            )
        });
        if reports_sessions || session.is_some() {
            let peer = SessionPeer {
                domain: domain.into(),
                sni,
                verify_hostname: self.verify_hostname,
                builtin_authentication: builtin_authentication(&self.ssl),
            };
            self.ssl.set_ex_data(SESSION_PEER_INDEX.register()?, peer)?;
        }

        if let Some(ClientSession {
            session,
            authentication,
        }) = session
        {
            self.ssl
                .set_ex_data(CLIENT_SESSION_OFFER_INDEX.register()?, authentication)?;
            // SAFETY: the owned SSL has not started its handshake. The native
            // setter retains the session and calls the static validator before
            // offering it; both typed metadata slots are initialized above.
            unsafe {
                cvt(ffi::SSL_set_session_with_validator(
                    self.ssl.as_ptr(),
                    session.as_ptr(),
                    Some(validate_client_session),
                ))?;
            }
        }

        Ok(self.ssl)
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::into_ssl`] and
    /// [`Ssl::setup_connect`].
    ///
    /// # Errors
    ///
    /// Domain verification setup or stream attachment fails.
    pub fn setup_connect<S>(
        self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        self.into_ssl(domain)?.setup_connect(stream)
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Errors
    ///
    /// Connection setup or the TLS handshake fails.
    pub fn connect<S>(self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }
}

impl Deref for ConnectConfiguration {
    type Target = SslRef;

    fn deref(&self) -> &SslRef {
        &self.ssl
    }
}

impl DerefMut for ConnectConfiguration {
    fn deref_mut(&mut self) -> &mut SslRef {
        &mut self.ssl
    }
}

/// A type which wraps server-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, and more.
#[derive(Clone)]
pub struct SslAcceptor(SslContext);

impl SslAcceptor {
    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of version 5 of Mozilla's server side TLS
    /// recommendations, limited to supported server cipher suites. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    ///
    /// # Errors
    ///
    /// Native context creation or cipher configuration fails.
    pub fn mozilla_intermediate_v5(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        ctx.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
             ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Initiates a server-side TLS handshake on a stream.
    ///
    /// See [`Ssl::setup_accept`] for more details.
    ///
    /// # Errors
    ///
    /// The native SSL connection cannot be allocated or attached to the stream.
    pub fn setup_accept<S>(&self, stream: S) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        let ssl = Ssl::new(&self.0)?;

        ssl.setup_accept(stream)
    }

    /// Attempts a server-side TLS handshake on a stream.
    ///
    /// This is a convenience method which combines [`Self::setup_accept`] and
    /// [`MidHandshakeSslStream::handshake`].
    ///
    /// # Errors
    ///
    /// Server-side connection setup or the TLS handshake fails.
    pub fn accept<S>(&self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_accept(stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Consumes the `SslAcceptor`, returning the inner raw `SslContext`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use = "Use the returned reference or negotiated value to inspect the current connection."]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslAcceptor`s.
pub struct SslAcceptorBuilder(SslContextBuilder);

impl SslAcceptorBuilder {
    /// Consumes the builder, returning a `SslAcceptor`.
    #[must_use = "The returned owned value is the result of consuming the original owner."]
    pub fn build(self) -> SslAcceptor {
        SslAcceptor(self.0.build())
    }
}

impl Deref for SslAcceptorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslAcceptorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

fn setup_verify_hostname(ssl: &mut SslRef, domain: &str) -> Result<(), ErrorStack> {
    // BoringSSL always rejects partial wildcards. Do not overwrite the
    // hostname flags inherited from the trust store or set by the caller.
    let param = ssl.verify_param_mut()?;
    match domain.parse() {
        Ok(ip) => param.set_ip(ip),
        Err(_) => param.set_host(domain),
    }
}
