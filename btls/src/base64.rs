//! Standard padded Base64 encoding and decoding.
use crate::error::ErrorStack;
use crate::ffi;
use openssl_macros::corresponds;

/// Encodes a slice of bytes as standard padded Base64.
///
/// # Errors
///
/// Returns an error if the encoded size is unrepresentable or allocation fails.
#[corresponds(EVP_EncodeBlock)]
pub fn encode_block(src: &[u8]) -> Result<String, ErrorStack> {
    let mut capacity = 0;
    // SAFETY: the output length is a writable local; native checks size overflow.
    let sized = unsafe { ffi::EVP_EncodedLength(&raw mut capacity, src.len()) };
    if sized != 1 || capacity == 0 {
        return Err(ErrorStack::internal_error_str(
            "unrepresentable Base64 length",
        ));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(ErrorStack::internal_error)?;
    // SAFETY: EVP_EncodedLength includes the native encoder's trailing NUL.
    // The allocation covers that entire length and input stays readable.
    let written = unsafe { ffi::EVP_EncodeBlock(out.as_mut_ptr(), src.as_ptr(), src.len()) };
    if written != capacity - 1 {
        return Err(ErrorStack::internal_error_str(
            "invalid native Base64 length",
        ));
    }
    // SAFETY: native initializes exactly written ASCII characters and the
    // omitted trailing NUL; initialized bytes are valid UTF-8.
    unsafe {
        out.set_len(written);
        Ok(String::from_utf8_unchecked(out))
    }
}

/// Decodes standard padded Base64, ignoring surrounding whitespace.
///
/// # Errors
///
/// Returns an error for malformed input or allocation failure.
#[corresponds(EVP_DecodeBase64)]
pub fn decode_block(src: &str) -> Result<Vec<u8>, ErrorStack> {
    let src = src.trim();
    if src.is_empty() {
        return Ok(Vec::new());
    }
    let mut capacity = 0;
    // SAFETY: the native sizing function writes a local length and validates
    // that input consists of complete encoded quads.
    if unsafe { ffi::EVP_DecodedLength(&raw mut capacity, src.len()) } != 1 {
        return Err(ErrorStack::internal_error_str("invalid Base64 length"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(ErrorStack::internal_error)?;
    let mut written = 0;
    // SAFETY: capacity is the native maximum decoded size and matches the
    // reserved allocation. Native validates input and reports actual bytes.
    let result = unsafe {
        ffi::EVP_DecodeBase64(
            out.as_mut_ptr(),
            &raw mut written,
            capacity,
            src.as_ptr(),
            src.len(),
        )
    };
    if result != 1 || written > capacity {
        return Err(ErrorStack::internal_error_str("invalid Base64 encoding"));
    }
    // SAFETY: native success initializes exactly written bytes within capacity.
    unsafe { out.set_len(written) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_block() {
        assert_eq!(String::new(), encode_block(b"").unwrap());
        assert_eq!("Zg==".to_string(), encode_block(b"f").unwrap());
        assert_eq!("Zm8=".to_string(), encode_block(b"fo").unwrap());
        assert_eq!("Zm9v".to_string(), encode_block(b"foo").unwrap());
        assert_eq!("Zm9vYg==".to_string(), encode_block(b"foob").unwrap());
        assert_eq!("Zm9vYmE=".to_string(), encode_block(b"fooba").unwrap());
        assert_eq!("Zm9vYmFy".to_string(), encode_block(b"foobar").unwrap());
    }

    #[test]
    fn test_decode_block() {
        assert_eq!(b"".to_vec(), decode_block("").unwrap());
        assert_eq!(b"f".to_vec(), decode_block("Zg==").unwrap());
        assert_eq!(b"fo".to_vec(), decode_block("Zm8=").unwrap());
        assert_eq!(b"foo".to_vec(), decode_block("Zm9v").unwrap());
        assert_eq!(b"foob".to_vec(), decode_block("Zm9vYg==").unwrap());
        assert_eq!(b"fooba".to_vec(), decode_block("Zm9vYmE=").unwrap());
        assert_eq!(b"foobar".to_vec(), decode_block("Zm9vYmFy").unwrap());
    }

    #[test]
    fn rejects_invalid_payloads_and_preserves_nuls() {
        for invalid in ["Zg", "Z===", "Zg==Zm9v", "Zg==!", "Zm 9v", "===="] {
            assert!(decode_block(invalid).is_err(), "{invalid}");
        }
        for input in [&[0][..], &[1, 0], &[1, 2, 0], &[0, 0, 0, 0]] {
            let encoded = encode_block(input).unwrap();
            assert_eq!(decode_block(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn test_strip_whitespace() {
        assert_eq!(b"foobar".to_vec(), decode_block(" Zm9vYmFy\n").unwrap());
        assert_eq!(b"foob".to_vec(), decode_block(" Zm9vYg==\n").unwrap());
    }
}
