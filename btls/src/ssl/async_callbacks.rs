use super::mut_only::MutOnly;
use super::{
    ClientHello, GetSessionPendingError, PrivateKeyMethod, PrivateKeyMethodError, SelectCertAction,
    SelectCertError, Ssl, SslAlert, SslContextBuilder, SslRef, SslSession, SslSignatureAlgorithm,
    SslVerifyError, SslVerifyMode,
};
use crate::error::ErrorStack;
use crate::ex_data::{Index, IndexSlot};
#[cfg(feature = "credential")]
use crate::ssl::SslCredentialBuilder;
use std::convert::identity;
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll, Waker};

/// The type of futures to pass to [`SslContextBuilder::set_async_select_certificate_callback`].
pub type BoxSelectCertFuture = ExDataFuture<Result<BoxSelectCertFinish, AsyncSelectCertError>>;

/// The type of callbacks returned by [`BoxSelectCertFuture`] methods.
pub type BoxSelectCertFinish = Box<dyn FnOnce(ClientHello<'_>) -> Result<(), AsyncSelectCertError>>;

/// The type of futures to pass to [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
pub type BoxSelectCertActionFuture =
    ExDataFuture<Result<BoxSelectCertActionFinish, AsyncSelectCertError>>;

/// The type of callbacks returned by [`BoxSelectCertActionFuture`] methods.
pub type BoxSelectCertActionFinish =
    Box<dyn FnOnce(ClientHello<'_>) -> Result<SelectCertAction, AsyncSelectCertError>>;

/// The type of futures returned by [`AsyncPrivateKeyMethod`] methods.
pub type BoxPrivateKeyMethodFuture =
    ExDataFuture<Result<BoxPrivateKeyMethodFinish, AsyncPrivateKeyMethodError>>;

/// The type of callbacks returned by [`BoxPrivateKeyMethodFuture`].
pub type BoxPrivateKeyMethodFinish =
    Box<dyn FnOnce(&mut SslRef, &mut [u8]) -> Result<usize, AsyncPrivateKeyMethodError>>;

/// The type of futures to pass to [`SslContextBuilder::set_async_get_session_callback`].
pub type BoxGetSessionFuture = ExDataFuture<Option<BoxGetSessionFinish>>;

/// The type of callbacks returned by [`BoxSelectCertFuture`] methods.
pub type BoxGetSessionFinish = Box<dyn FnOnce(&mut SslRef, &[u8]) -> Option<SslSession>>;

/// The type of futures to pass to [`SslContextBuilder::set_async_custom_verify_callback`].
pub type BoxCustomVerifyFuture = ExDataFuture<Result<BoxCustomVerifyFinish, SslAlert>>;

/// The type of callbacks returned by [`BoxCustomVerifyFuture`] methods.
pub type BoxCustomVerifyFinish = Box<dyn FnOnce(&mut SslRef) -> Result<(), SslAlert>>;

/// Convenience alias for futures stored in [`Ssl`] ex data by [`SslContextBuilder`] methods.
///
/// Public for documentation purposes.
pub type ExDataFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type BoxSelectCertFinishFor<T> =
    Box<dyn FnOnce(ClientHello<'_>) -> Result<T, AsyncSelectCertError>>;
type SelectCertFutureIndex<T> = Index<
    Ssl,
    MutOnly<Option<ExDataFuture<Result<BoxSelectCertFinishFor<T>, AsyncSelectCertError>>>>,
>;

static TASK_WAKER_INDEX: IndexSlot<Ssl, Option<Waker>> = IndexSlot::new(Ssl::new_ex_index);
type SelectCertFutureData<T> =
    MutOnly<Option<ExDataFuture<Result<BoxSelectCertFinishFor<T>, AsyncSelectCertError>>>>;
static SELECT_CERT_FUTURE_INDEX: IndexSlot<Ssl, SelectCertFutureData<()>> =
    IndexSlot::new(Ssl::new_ex_index);
static SELECT_CERT_ACTION_FUTURE_INDEX: IndexSlot<Ssl, SelectCertFutureData<SelectCertAction>> =
    IndexSlot::new(Ssl::new_ex_index);
static SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX: IndexSlot<
    Ssl,
    MutOnly<Option<BoxPrivateKeyMethodFuture>>,
> = IndexSlot::new(Ssl::new_ex_index);
static SELECT_GET_SESSION_FUTURE_INDEX: IndexSlot<Ssl, MutOnly<Option<BoxGetSessionFuture>>> =
    IndexSlot::new(Ssl::new_ex_index);
static SELECT_CUSTOM_VERIFY_FUTURE_INDEX: IndexSlot<Ssl, MutOnly<Option<BoxCustomVerifyFuture>>> =
    IndexSlot::new(Ssl::new_ex_index);

impl SslContextBuilder {
    /// Sets a callback that is called before most [`ClientHello`] processing
    /// and before the decision whether to resume a session is made. The
    /// callback may inspect the [`ClientHello`] and configure the connection.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed [`ClientHello`] to configure
    /// the connection based on the computations done in the future.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`SslContextBuilder::set_select_certificate_callback`] for the sync
    /// setter of this callback.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_select_certificate_callback<F>(
        &mut self,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        let callback = async_select_certificate_callback(
            callback,
            SELECT_CERT_FUTURE_INDEX.register()?,
            |()| SelectCertAction::Success,
        );
        self.set_select_certificate_callback_with_action(callback)
    }

    /// Sets an action-aware asynchronous certificate selection callback.
    ///
    /// This method uses a function that returns a future whose output is itself a closure that
    /// will be passed [`ClientHello`] to configure the connection based on the computations done
    /// in the future.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting `SslContext` with
    /// [`SslRef::set_task_waker`]. Returning [`SelectCertAction::DisableEch`] discards an inner
    /// `ClientHello`, invokes the callback again with the outer `ClientHello`, and continues without
    /// retry configs. It is only valid when ECH has been accepted; returning it otherwise fails
    /// the handshake.
    /// The future-producing callback runs again for the outer `ClientHello`, so per-connection
    /// state must handle both calls.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_select_certificate_callback_with_action<F>(
        &mut self,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertActionFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        let callback = async_select_certificate_callback(
            callback,
            SELECT_CERT_ACTION_FUTURE_INDEX.register()?,
            identity,
        );
        self.set_select_certificate_callback_with_action(callback)
    }

    /// Configures a custom private key method on the context.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`AsyncPrivateKeyMethod`] for more details.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_private_key_method(
        &mut self,
        method: impl AsyncPrivateKeyMethod,
    ) -> Result<(), ErrorStack> {
        SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX.register()?;
        self.set_private_key_method(AsyncPrivateKeyMethodBridge(method))
    }

    /// Sets a callback that is called when a client proposed to resume a session
    /// but it was not found in the internal cache.
    ///
    /// The callback is passed a reference to the session ID provided by the client.
    /// It should return the session corresponding to that ID if available. This is
    /// only used for servers, not clients.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`SslContextBuilder::set_get_session_callback`] for the sync setter
    /// of this callback.
    ///
    /// # Safety
    ///
    /// The returned [`SslSession`] must not be associated with a different [`SslContextBuilder`].
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub unsafe fn set_async_get_session_callback<F>(
        &mut self,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, &[u8]) -> Option<BoxGetSessionFuture> + Send + Sync + 'static,
    {
        let index = SELECT_GET_SESSION_FUTURE_INDEX.register()?;
        let async_callback = move |ssl: &mut SslRef, id: &[u8]| {
            let fut_poll_result = with_ex_data_future(
                &mut *ssl,
                index,
                |ssl| ssl,
                |ssl| callback(ssl, id).ok_or(()),
                |option| option.ok_or(()),
                (),
            );

            match fut_poll_result {
                Poll::Ready(Err(())) => Ok(None),
                Poll::Ready(Ok(finish)) => Ok(finish(ssl, id)),
                Poll::Pending => Err(GetSessionPendingError),
            }
        };

        // SAFETY: the callback is installed on a uniquely borrowed context;
        // its Rust closure is registered with the native extra-data slot and
        // outlives any session lookup performed by BoringSSL.
        unsafe { self.set_get_session_callback(async_callback) }
    }

    /// Configures certificate verification.
    ///
    /// The callback should return `Ok(())` if the certificate is valid.
    /// If the certificate is invalid, the callback should return `SslVerifyError::Invalid(alert)`.
    /// Some useful alerts include [`SslAlert::CERTIFICATE_EXPIRED`], [`SslAlert::CERTIFICATE_REVOKED`],
    /// [`SslAlert::UNKNOWN_CA`], [`SslAlert::BAD_CERTIFICATE`], [`SslAlert::CERTIFICATE_UNKNOWN`],
    /// and [`SslAlert::INTERNAL_ERROR`]. See RFC 5246 section 7.2.2 for their precise meanings.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`SslContextBuilder::set_custom_verify_callback`] for the sync version of this method.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_custom_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
    {
        let index = SELECT_CUSTOM_VERIFY_FUTURE_INDEX.register()?;
        self.set_custom_verify_callback(mode, async_custom_verify_callback(callback, index))
    }
}

#[cfg(feature = "credential")]
impl SslCredentialBuilder {
    /// Configures a custom private key method on the context.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`AsyncPrivateKeyMethod`] for more details.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_private_key_method(
        &mut self,
        method: impl AsyncPrivateKeyMethod,
    ) -> Result<(), ErrorStack> {
        SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX.register()?;
        self.set_private_key_method(AsyncPrivateKeyMethodBridge(method))
    }
}

impl SslRef {
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_async_custom_verify_callback<F>(
        &mut self,
        mode: SslVerifyMode,
        callback: F,
    ) -> Result<(), ErrorStack>
    where
        F: Fn(&mut Self) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
    {
        let index = SELECT_CUSTOM_VERIFY_FUTURE_INDEX.register()?;
        self.set_custom_verify_callback(mode, async_custom_verify_callback(callback, index))
    }

    /// Sets the task waker to be used in async callbacks installed on this `Ssl`.
    ///
    /// # Errors
    ///
    /// Returns an error if the native extra-data index or callback storage cannot be allocated.
    pub fn set_task_waker(&mut self, waker: Option<Waker>) -> Result<(), ErrorStack> {
        self.set_ex_data(TASK_WAKER_INDEX.register()?, waker)
    }
}

fn async_custom_verify_callback<F>(
    callback: F,
    index: Index<Ssl, MutOnly<Option<BoxCustomVerifyFuture>>>,
) -> impl Fn(&mut SslRef) -> Result<(), SslVerifyError>
where
    F: Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
{
    move |ssl| {
        let fut_poll_result = with_ex_data_future(
            &mut *ssl,
            index,
            |ssl| ssl,
            &callback,
            identity,
            SslAlert::INTERNAL_ERROR,
        );

        match fut_poll_result {
            Poll::Ready(Err(alert)) => Err(SslVerifyError::Invalid(alert)),
            Poll::Ready(Ok(finish)) => Ok(finish(ssl).map_err(SslVerifyError::Invalid)?),
            Poll::Pending => Err(SslVerifyError::Retry),
        }
    }
}

/// A fatal error to be returned from async select certificate callbacks.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AsyncSelectCertError;

/// Async private-key operations that delegate signing and decryption to a
/// potentially asynchronous backend. The certificate supplies key metadata
/// such as the algorithm and key size.
///
/// See [`PrivateKeyMethod`] for the sync version of those hooks.
///
/// [`ssl_private_key_method_st`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_private_key_method_st
pub trait AsyncPrivateKeyMethod: Send + Sync + 'static {
    /// Signs the message `input` using the specified signature algorithm.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed `ssl` and `output`
    /// to finish writing the signature.
    ///
    /// See [`PrivateKeyMethod::sign`] for the sync version of this method.
    ///
    /// # Errors
    ///
    /// Creating the asynchronous signing operation fails.
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>;

    /// Decrypts `input`.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed `ssl` and `output`
    /// to finish decrypting the input.
    ///
    /// See [`PrivateKeyMethod::decrypt`] for the sync version of this method.
    ///
    /// # Errors
    ///
    /// Creating the asynchronous decryption operation fails.
    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>;
}

/// A fatal error to be returned from async private key methods.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AsyncPrivateKeyMethodError;

struct AsyncPrivateKeyMethodBridge<M>(M);

impl<M: AsyncPrivateKeyMethod> PrivateKeyMethod for AsyncPrivateKeyMethodBridge<M> {
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |ssl, output| {
            self.0.sign(ssl, input, signature_algorithm, output)
        })
    }

    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |ssl, output| {
            self.0.decrypt(ssl, input, output)
        })
    }

    fn complete(
        &self,
        ssl: &mut SslRef,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |_, _| {
            // This should never be reached, if it does, that's a bug on btls's side,
            // which called `complete` without having been returned to with a pending
            // future from `sign` or `decrypt`.

            Err(AsyncPrivateKeyMethodError)
        })
    }
}

fn async_select_certificate_callback<T, F>(
    callback: F,
    index: SelectCertFutureIndex<T>,
    into_action: fn(T) -> SelectCertAction,
) -> impl Fn(ClientHello<'_>) -> Result<SelectCertAction, SelectCertError> + Send + Sync + 'static
where
    T: 'static,
    F: Fn(
            &mut ClientHello<'_>,
        ) -> Result<
            ExDataFuture<Result<BoxSelectCertFinishFor<T>, AsyncSelectCertError>>,
            AsyncSelectCertError,
        > + Send
        + Sync
        + 'static,
{
    move |mut client_hello| {
        let fut_poll_result = with_ex_data_future(
            &mut client_hello,
            index,
            ClientHello::ssl_mut,
            &callback,
            identity,
            AsyncSelectCertError,
        );

        let fut_result = match fut_poll_result {
            Poll::Ready(fut_result) => fut_result,
            Poll::Pending => return Err(SelectCertError::RETRY),
        };

        let finish = fut_result.or(Err(SelectCertError::ERROR))?;

        finish(client_hello)
            .map(into_action)
            .or(Err(SelectCertError::ERROR))
    }
}

/// Creates and drives a private key method future.
///
/// This is a convenience function used by the three `PrivateKeyMethod`
/// operations implemented by the async private key bridge. It relies on [`with_ex_data_future`] to
/// drive the future and then immediately calls the final [`BoxPrivateKeyMethodFinish`]
/// when the future is ready.
fn with_private_key_method(
    ssl: &mut SslRef,
    output: &mut [u8],
    create_fut: impl FnOnce(
        &mut SslRef,
        &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>,
) -> Result<usize, PrivateKeyMethodError> {
    let fut_poll_result = with_ex_data_future(
        ssl,
        SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX
            .get()
            .ok_or(PrivateKeyMethodError::FAILURE)?,
        |ssl| ssl,
        |ssl| create_fut(ssl, output),
        identity,
        AsyncPrivateKeyMethodError,
    );

    let fut_result = match fut_poll_result {
        Poll::Ready(fut_result) => fut_result,
        Poll::Pending => return Err(PrivateKeyMethodError::RETRY),
    };

    let finish = fut_result.or(Err(PrivateKeyMethodError::FAILURE))?;

    finish(ssl, output).or(Err(PrivateKeyMethodError::FAILURE))
}

/// Creates and drives a future stored in `ssl_handle`'s `Ssl` at ex data index `index`.
///
/// This function won't even bother storing the future in `index` if the future
/// created by `create_fut` returns `Poll::Ready(_)` on the first poll call.
fn with_ex_data_future<H, R: 'static, T, E>(
    ssl_handle: &mut H,
    index: Index<Ssl, MutOnly<Option<ExDataFuture<R>>>>,
    get_ssl_mut: impl Fn(&mut H) -> &mut SslRef,
    create_fut: impl FnOnce(&mut H) -> Result<ExDataFuture<R>, E>,
    into_result: impl Fn(R) -> Result<T, E>,
    failure: E,
) -> Poll<Result<T, E>> {
    let ssl = get_ssl_mut(ssl_handle);
    let Some(waker) = ssl.slot_data(&TASK_WAKER_INDEX).cloned().flatten() else {
        return Poll::Ready(Err(failure));
    };

    let mut ctx = Context::from_waker(&waker);

    if let Some(data) = ssl.ex_data_mut(index).map(MutOnly::get_mut) {
        if let Some(future) = data.as_mut() {
            let result = into_result(ready!(future.as_mut().poll(&mut ctx)));
            *data = None;
            return Poll::Ready(result);
        }
    }
    {
        let mut fut = create_fut(ssl_handle)?;

        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(fut_result) => Poll::Ready(into_result(fut_result)),
            Poll::Pending => {
                match get_ssl_mut(ssl_handle).set_ex_data(index, MutOnly::new(Some(fut))) {
                    Ok(()) => Poll::Pending,
                    Err(_) => Poll::Ready(Err(failure)),
                }
            }
        }
    }
}
