//! The `ChaCha20` stream cipher ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)).
//!
//! ChaCha20-Poly1305 encryption is found in [`aead`](crate::aead). The raw keystream here is for
//! protocols that build on it directly, such as QUIC header protection.

use crate::{error::ErrorStack, ffi};
use openssl_macros::corresponds;

/// XORs `data` in place with the keystream of `key` and `nonce`, starting at block `counter`.
///
/// The caller must not reuse a key, nonce and counter combination.
/// # Errors
///
/// The input would require wrapping the 32-bit block counter.
#[corresponds(CRYPTO_chacha_20)]
pub fn chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    data: &mut [u8],
) -> Result<(), ErrorStack> {
    let available_blocks = u64::from(u32::MAX - counter) + 1;
    if data.len().div_ceil(64) as u64 > available_blocks {
        return Err(ErrorStack::internal_error_str(
            "ChaCha20 block counter would wrap",
        ));
    }
    let data_ptr = data.as_mut_ptr();
    // SAFETY: `CRYPTO_chacha_20` allows the input and output to be the same buffer.
    unsafe {
        ffi::CRYPTO_chacha_20(
            data_ptr,
            data_ptr,
            data.len(),
            key.as_ptr(),
            nonce.as_ptr(),
            counter,
        );
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rejects_counter_wrap_without_modifying_input() {
        let mut data = [0x42; 65];
        assert!(chacha20(&[0; 32], &[0; 12], u32::MAX, &mut data).is_err());
        assert_eq!(data, [0x42; 65]);
        assert!(chacha20(&[0; 32], &[0; 12], u32::MAX, &mut data[..64]).is_ok());
        assert!(chacha20(&[0; 32], &[0; 12], u32::MAX, &mut []).is_ok());
    }

    /// The header protection mask of RFC 9001, Appendix A.5.
    #[test]
    fn quic_header_protection_mask() {
        let key: [u8; 32] =
            hex::decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
                .unwrap()
                .try_into()
                .unwrap();
        let sample = hex::decode("5e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let (counter, nonce) = sample.split_at(4);

        let mut mask = [0; 5];
        chacha20(
            &key,
            nonce.try_into().unwrap(),
            u32::from_le_bytes(counter.try_into().unwrap()),
            &mut mask,
        )
        .unwrap();
        assert_eq!(hex::encode(mask), "aefefe7d03");
    }
}
